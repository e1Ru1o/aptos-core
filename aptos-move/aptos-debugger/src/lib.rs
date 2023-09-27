// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{format_err, Result};
use aptos_gas_meter::{StandardGasAlgebra, StandardGasMeter};
use aptos_gas_profiling::{GasProfiler, TransactionGasLog};
use aptos_gas_schedule::{MiscGasParameters, NativeGasParameters, LATEST_GAS_FEATURE_VERSION};
use aptos_memory_usage_tracker::MemoryTrackedGasMeter;
use aptos_resource_viewer::{AnnotatedAccountStateBlob, AptosValueAnnotator};
use aptos_rest_client::Client;
use aptos_state_view::TStateView;
use aptos_types::{
    account_address::AccountAddress,
    chain_id::ChainId,
    on_chain_config::{Features, OnChainConfig, TimedFeatures},
    transaction::{
        SignedTransaction, Transaction, TransactionInfo, TransactionOutput, TransactionPayload,
        Version,
    },
    vm_status::VMStatus,
};
use aptos_framework::{BuildOptions, BuiltPackage, APTOS_COMMONS, STATE_DATA};
use aptos_validator_interface::{
    AptosValidatorInterface, DBDebuggerInterface, DebuggerStateView, RestDebuggerInterface,
};
use aptos_vm::{
    data_cache::AsMoveResolver,
    move_vm_ext::{MoveVmExt, SessionExt, SessionId},
    AptosVM, VMExecutor,
};
use aptos_vm_logging::log_schema::AdapterLogSchema;
use aptos_vm_types::{change_set::VMChangeSet, output::VMOutput, storage::ChangeSetConfigs};

use move_binary_format::errors::VMResult;
use move_core_types::language_storage::{ModuleId, TypeTag};
use move_vm_types::gas::UnmeteredGasMeter;
use move_package::{
    compilation::{compiled_package::CompiledPackage}};
use std::{path::Path, sync::Arc};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::PathBuf;
use std::io::{Read, Write};
use aptos_framework::natives::code::PackageRegistry;
use aptos_types::on_chain_config::TimedFeatureOverride;
use aptos_types::state_store::state_key::StateKey;
use move_binary_format::CompiledModule;
use move_core_types::identifier::IdentStr;
use aptos_language_e2e_tests::{data_store::FakeDataStore, executor::FakeExecutor};
use aptos_state_view::account_with_state_view::AsAccountWithStateView;
use aptos_types::account_view::AccountView;
use move_compiler::compiled_unit::CompiledUnitEnum;
use move_core_types::value::MoveValue;


pub struct AptosDebugger {
    debugger: Arc<dyn AptosValidatorInterface + Send>,
}

impl AptosDebugger {
    pub fn new(debugger: Arc<dyn AptosValidatorInterface + Send>) -> Self {
        Self { debugger }
    }

    pub fn rest_client(rest_client: Client) -> Result<Self> {
        Ok(Self::new(Arc::new(RestDebuggerInterface::new(rest_client))))
    }

    pub fn db<P: AsRef<Path> + Clone>(db_root_path: P) -> Result<Self> {
        Ok(Self::new(Arc::new(DBDebuggerInterface::open(
            db_root_path,
        )?)))
    }

    pub fn execute_transactions_at_version(
        &self,
        version: Version,
        txns: Vec<Transaction>,
    ) -> Result<Vec<TransactionOutput>> {
        let state_view = DebuggerStateView::new(self.debugger.clone(), version);
        AptosVM::execute_block(txns, &state_view, None)
            .map_err(|err| format_err!("Unexpected VM Error: {:?}", err))
    }

    pub fn execute_transaction_at_version_with_gas_profiler(
        &self,
        version: Version,
        txn: SignedTransaction,
    ) -> Result<(VMStatus, VMOutput, TransactionGasLog)> {
        let state_view = DebuggerStateView::new(self.debugger.clone(), version);
        let log_context = AdapterLogSchema::new(state_view.id(), 0);
        let txn = txn
            .check_signature()
            .map_err(|err| format_err!("Unexpected VM Error: {:?}", err))?;

        // TODO(Gas): revisit this.
        let vm = AptosVM::new_from_state_view(&state_view);
        let resolver = state_view.as_move_resolver();

        let (status, output, gas_profiler) = vm.execute_user_transaction_with_custom_gas_meter(
            &resolver,
            &txn,
            &log_context,
            |gas_feature_version, gas_params, storage_gas_params, balance| {
                let gas_meter =
                    MemoryTrackedGasMeter::new(StandardGasMeter::new(StandardGasAlgebra::new(
                        gas_feature_version,
                        gas_params,
                        storage_gas_params,
                        balance,
                    )));
                let gas_profiler = match txn.payload() {
                    TransactionPayload::Script(_) => GasProfiler::new_script(gas_meter),
                    TransactionPayload::EntryFunction(entry_func) => GasProfiler::new_function(
                        gas_meter,
                        entry_func.module().clone(),
                        entry_func.function().to_owned(),
                        entry_func.ty_args().to_vec(),
                    ),
                    TransactionPayload::ModuleBundle(..) => unreachable!("not supported"),
                    TransactionPayload::Multisig(..) => unimplemented!("not supported yet"),
                };
                Ok(gas_profiler)
            },
        )?;

        Ok((status, output, gas_profiler.finish()))
    }

    pub async fn execute_past_transactions(
        &self,
        mut begin: Version,
        mut limit: u64,
    ) -> Result<Vec<TransactionOutput>> {
        let (mut txns, mut txn_infos) = self
            .debugger
            .get_committed_transactions(begin, limit)
            .await?;

        let mut ret = vec![];
        while limit != 0 {
            println!(
                "Starting epoch execution at {:?}, {:?} transactions remaining",
                begin, limit
            );
            let mut epoch_result = self
                .execute_transactions_by_epoch(begin, txns.clone())
                .await?;
            begin += epoch_result.len() as u64;
            limit -= epoch_result.len() as u64;
            txns = txns.split_off(epoch_result.len());
            let epoch_txn_infos = txn_infos.drain(0..epoch_result.len()).collect::<Vec<_>>();
            Self::print_mismatches(&epoch_result, &epoch_txn_infos, begin);

            ret.append(&mut epoch_result);
        }
        Ok(ret)
    }

    pub async fn dump_past_transactions(
        &self,
        begin: Version,
        limit: u64,
        dump_file: &mut File,
    ) -> Version {

        let mut cur_version = begin;
        // if not exists, create the folder aptos-commoms which will store aptos-framework, aptos-stdlib and move-stdlib
        // aptos-framework-upgrade-num
        let mut aptos_commons_path = PathBuf::from(".").join(APTOS_COMMONS);
        if !aptos_commons_path.exists() {
            std::fs::create_dir_all(aptos_commons_path.as_path()).unwrap();
        }

        let mut state_data_path = PathBuf::from(".").join(STATE_DATA);
        if !state_data_path.exists() {
            std::fs::create_dir_all(state_data_path.as_path()).unwrap();
        }

        let mut count = 0;
        let batch_num = 1;
        let mut package_registry_cache: BTreeMap<AccountAddress, PackageRegistry> = BTreeMap::new();
        let mut compiled_package_cache: BTreeMap<(AccountAddress, String, Option<u64>), CompiledPackage> = BTreeMap::new();

        // Compile aptos packages
        BuiltPackage::compile_aptos_packages(&aptos_commons_path, &mut compiled_package_cache);
        while count < limit {
            println!("get txn at version:{}", cur_version);
            let v = self
                .debugger
                .get_committed_transactions_with_available_src(cur_version.clone(), batch_num, &mut package_registry_cache)
                .await.unwrap_or_default();
            if !v.is_empty() {
                //assert_eq!(v.len(), 1);
                count += v.len() as u64;
                println!("count:{}", count);

                // run change_set
                // create a new folder to store the source code
                // unzip_package for the root package
                // during execution
                for (version, txn, (addr, package_name), map) in v {
                    writeln!(dump_file, "{}", version).unwrap();

                    // Obtain the state before execution
                    let state_view = DebuggerStateView::new(self.debugger.clone(), version);
                    // let mut epoch_result = self
                    //     .execute_transactions_by_epoch(version, vec![txn.clone()])
                    //     .await.unwrap();
                    // assert_eq!(epoch_result.len(), 1);

                    // Create a fake executor
                    let executor = FakeExecutor::from_head_genesis();
                    let mut executor = executor.set_not_parallel();
                    *executor.data_store_mut() = FakeDataStore::new(HashMap::new());

                    // // Populate the pre-state in the executor
                    // let state_path = PathBuf::from(".").join(STATE_DATA).join(format!("{}_state", version));
                    // // If the state has not been dumped, get the state and dump it
                    // if !state_path.exists() {
                    //     // Add pre-execution state to the fake executor
                    //     let output = &epoch_result[0];
                    //     println!("output at version {}:{:?}", version, output);
                    //     let state = output.write_set().clone();
                    //     for (state_key, _) in state.into_iter() {
                    //         let state_value_res = state_view.get_state_value(&state_key);
                    //         if let Ok(Some(state_value)) = state_value_res {
                    //             // executor.set(state_key.clone(), state_value);
                    //         }
                    //     }
                    //     let mut file = File::create(state_path).unwrap();
                    //     file.write_all(&bcs::to_bytes(&executor.data_store()).unwrap()).unwrap();
                    // } else { // Retrieve the state
                    //     println!("deser data....");
                    //     let mut file = File::open(state_path).unwrap();
                    //     // read the same file back into a Vec of bytes
                    //     let mut buffer = Vec::<u8>::new();
                    //     file.read_to_end(&mut buffer).unwrap();
                    //     let state = bcs::from_bytes::<FakeDataStore>(&buffer).unwrap();
                    //     *executor.data_store_mut() = state;
                    // }

                    // Dump and compile the source code if necessary
                    if !BuiltPackage::is_aptos_package(&package_name) {
                        let package = map.get(&(addr, package_name.clone())).unwrap();
                        println!("package name:{}", package_name);
                        if !compiled_package_cache.contains_key(&(addr, package_name.clone(), Some(package.upgrade_number))) {
                            BuiltPackage::unzip_and_dump_source_from_package_metadata(package_name.clone(), addr, package.upgrade_number, &map, &mut compiled_package_cache).unwrap();
                        }
                    }
                    let upgrade_number = if BuiltPackage::is_aptos_package(&package_name) {
                        None
                    } else {
                        let package = map.get(&(addr, package_name.clone())).unwrap();
                        Some(package.upgrade_number)
                    };
                    // Execute the txn with compiled module
                    if compiled_package_cache.contains_key(&(addr, package_name.clone(), upgrade_number)) {
                        let compiled_package = compiled_package_cache.get(&(addr, package_name.clone(), upgrade_number)).unwrap();
                        if let Transaction::UserTransaction(signed_trans) = txn {
                            let sender = signed_trans.sender();
                            let signer = MoveValue::Signer(sender).simple_serialize();
                            let payload = signed_trans.payload();
                            if let TransactionPayload::EntryFunction(entry_function) =
                            payload {
                                //let compiled_module = compiled_package.get_module_by_name(&package_name.clone(), &entry_function.module().name().to_string()).unwrap();
                                let root_modules = compiled_package.all_modules();
                                for compiled_module in root_modules {
                                    if let CompiledUnitEnum::Module(module) = &compiled_module.unit {
                                        let module_blob = compiled_module.unit.serialize(None);
                                        executor.add_module(&module.module.self_id(), module_blob);
                                    }
                                }
                                let mut args = entry_function.args().to_vec();
                                args.insert(0, signer.unwrap());
                                let state_view = DebuggerStateView::new_with_fake_data(self.debugger.clone(), version, executor.data_store().clone());
                                let state_view_storage = state_view.as_move_resolver();
                                let features = Features::fetch_config(&state_view_storage).unwrap_or_default();
                                let res = executor.try_exec_with_debugger(entry_function.module().name().as_str(), entry_function.function().as_str(), entry_function.ty_args().to_vec(), args, state_view_storage, features);
                                println!("sender:{}, execution result at {} :{:?}", sender, version, res);
                            }
                        }
                    }
                }

            }
            cur_version += batch_num;
        }
        cur_version
    }

    fn print_mismatches(
        txn_outputs: &[TransactionOutput],
        expected_txn_infos: &[TransactionInfo],
        first_version: Version,
    ) {
        for idx in 0..txn_outputs.len() {
            let txn_output = &txn_outputs[idx];
            let txn_info = &expected_txn_infos[idx];
            let version = first_version + idx as Version;
            txn_output
                .ensure_match_transaction_info(version, txn_info, None, None)
                .unwrap_or_else(|err| println!("{}", err))
        }
    }

    pub async fn execute_transactions_by_epoch(
        &self,
        begin: Version,
        txns: Vec<Transaction>,
    ) -> Result<Vec<TransactionOutput>> {
        let results = self.execute_transactions_at_version(begin, txns)?;
        let mut ret = vec![];
        let mut is_reconfig = false;

        for result in results.into_iter() {
            if is_reconfig {
                continue;
            }
            if is_reconfiguration(&result) {
                is_reconfig = true;
            }
            ret.push(result)
        }
        Ok(ret)
    }

    pub async fn annotate_account_state_at_version(
        &self,
        account: AccountAddress,
        version: Version,
    ) -> Result<Option<AnnotatedAccountStateBlob>> {
        let state_view = DebuggerStateView::new(self.debugger.clone(), version);
        let remote_storage = state_view.as_move_resolver();
        let annotator = AptosValueAnnotator::new(&remote_storage);
        Ok(
            match self
                .debugger
                .get_account_state_by_version(account, version)
                .await?
            {
                Some(account_state) => Some(annotator.view_account_state(&account_state)?),
                None => None,
            },
        )
    }

    pub async fn annotate_key_accounts_at_version(
        &self,
        version: Version,
    ) -> Result<Vec<(AccountAddress, AnnotatedAccountStateBlob)>> {
        let accounts = self.debugger.get_admin_accounts(version).await?;
        let state_view = DebuggerStateView::new(self.debugger.clone(), version);
        let remote_storage = state_view.as_move_resolver();
        let annotator = AptosValueAnnotator::new(&remote_storage);

        let mut result = vec![];
        for (addr, state) in accounts.into_iter() {
            result.push((addr, annotator.view_account_state(&state)?));
        }
        Ok(result)
    }

    pub async fn get_latest_version(&self) -> Result<Version> {
        self.debugger.get_latest_version().await
    }

    pub async fn get_version_by_account_sequence(
        &self,
        account: AccountAddress,
        seq: u64,
    ) -> Result<Option<Version>> {
        self.debugger
            .get_version_by_account_sequence(account, seq)
            .await
    }

    pub fn run_session_at_version<F>(&self, version: Version, f: F) -> Result<VMChangeSet>
    where
        F: FnOnce(&mut SessionExt) -> VMResult<()>,
    {
        let state_view = DebuggerStateView::new(self.debugger.clone(), version);
        let state_view_storage = state_view.as_move_resolver();
        let features = Features::fetch_config(&state_view_storage).unwrap_or_default();
        let move_vm = MoveVmExt::new(
            NativeGasParameters::zeros(),
            MiscGasParameters::zeros(),
            LATEST_GAS_FEATURE_VERSION,
            ChainId::test().id(),
            features,
            TimedFeatures::enable_all(),
            &state_view_storage,
        )
        .unwrap();
        let mut session = move_vm.new_session(&state_view_storage, SessionId::Void);
        f(&mut session).map_err(|err| format_err!("Unexpected VM Error: {:?}", err))?;
        let change_set = session
            .finish(
                &mut (),
                &ChangeSetConfigs::unlimited_at_gas_feature_version(LATEST_GAS_FEATURE_VERSION),
            )
            .map_err(|err| format_err!("Unexpected VM Error: {:?}", err))?;
        Ok(change_set)
    }
}

fn is_reconfiguration(vm_output: &TransactionOutput) -> bool {
    let new_epoch_event_key = aptos_types::on_chain_config::new_epoch_event_key();
    vm_output
        .events()
        .iter()
        .any(|event| event.event_key() == Some(&new_epoch_event_key))
}
