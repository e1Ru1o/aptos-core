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
use aptos_framework::{BuildOptions, BuiltPackage, APTOS_COMMONS, STATE_DATA, TXN_DATA};
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
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::io::{Read, Write};
use aptos_framework::natives::code::PackageRegistry;
use aptos_types::on_chain_config::{FeatureFlag, TimedFeatureOverride};
use aptos_types::state_store::state_key::StateKey;
use move_binary_format::CompiledModule;
use move_core_types::identifier::IdentStr;
use aptos_language_e2e_tests::{data_store::FakeDataStore, executor::FakeExecutor};
use aptos_state_view::account_with_state_view::AsAccountWithStateView;
use aptos_types::account_view::AccountView;
use aptos_types::contract_event::ContractEvent;
use aptos_types::write_set::WriteSet;
use move_binary_format::access::ModuleAccess;
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
        self.execute_transactions_at_version_with_state_view(txns, &state_view)
    }

    pub fn execute_transactions_at_version_with_state_view(
        &self,
        txns: Vec<Transaction>,
        debugger_stateview: &DebuggerStateView
    ) -> Result<Vec<TransactionOutput>> {
        AptosVM::execute_block(txns, debugger_stateview, None)
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

    pub fn set_enable(features: &mut Features, flag: FeatureFlag) {
        let val = flag as u64;
        let byte_index = (val / 8) as usize;
        let bit_mask = 1 << (val % 8);
        if byte_index < features.features.len() {
            (*features).features[byte_index] = features.features[byte_index] | bit_mask;
        }
    }

    pub async fn dump_past_transactions(
        &self,
        begin: Version,
        limit: u64,
        dump_file: &mut File,
    ) -> Version {

        let mut path = PathBuf::from(".").join("error.txt");
        let mut err_file = if !path.exists() {
            File::create(path)
                .expect("Error encountered while creating file!")
        } else {
            OpenOptions::new()
                .write(true)
                .append(true)
                .open(path)
                .unwrap()
        };

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
        let batch_num = 500;
        let mut package_registry_cache: BTreeMap<AccountAddress, PackageRegistry> = BTreeMap::new();
        let mut compiled_package_cache: BTreeMap<(AccountAddress, String, Option<u64>, u32), CompiledPackage> = BTreeMap::new();


        // Compile aptos packages
        BuiltPackage::compile_aptos_packages(&aptos_commons_path, &mut compiled_package_cache);
        while count < limit {
            let v = self
                .debugger
                .get_committed_transactions_with_available_src(cur_version.clone(), batch_num, &mut package_registry_cache)
                .await.unwrap_or_default();
            if !v.is_empty() {
                println!("get txn at version:{}", cur_version);
                //assert_eq!(v.len(), 1);
                println!("count:{}", count);

                // run change_set
                // create a new folder to store the source code
                // unzip_package for the root package
                // during execution
                for (version, txn, (addr, package_name), map) in v {
                    // println!("addr:{}, package name:{}", addr, package_name);
                    // Obtain the state before execution
                    let mut state_view = DebuggerStateView::new_with_data_reads(self.debugger.clone(), version);
                    let state_view_storage = state_view.as_move_resolver();
                    let mut features = Features::fetch_config(&state_view_storage).unwrap_or_default();
                    // println!("before v6 enabled:{}", features.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V6));
                    Self::set_enable(&mut features, FeatureFlag::VM_BINARY_FORMAT_V6);
                    // println!("v6 enabled:{}", features.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V6));
                    let bytecode_version = 6;
                    // let bytecode_version = if features.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V6) {
                    //     6
                    // } else {
                    //     5
                    // };

                    let epoch_result_res = self.execute_transactions_at_version_with_state_view(vec![txn.clone()], &state_view);
;                   if let Err(err) = epoch_result_res {
                        println!("execution error during transaction at version:{} :{}", version, err.to_string());
                        continue;
                    }
                    let mut epoch_result = epoch_result_res.unwrap();
                    assert_eq!(epoch_result.len(), 1);

                    // Create a fake executor
                    let executor = FakeExecutor::no_genesis();
                    let mut executor = executor.set_not_parallel();

                    // Populate the pre-state in the executor
                    let state_path = PathBuf::from(".").join(STATE_DATA).join(format!("{}_state", version));
                    let output = &epoch_result[0];

                    if output.status().is_discarded() || output.status().is_retry() {
                        continue;
                    }

                    let status = output.status().status().unwrap();
                    if !status.is_success() {
                        println!("skip unsucessful txn:{}", version);
                        continue;
                    }
                    // println!("output version {}:{:?}", version, output);
                    // If the state has not been dumped, get the state and dump it
                    if !state_path.exists() {
                        writeln!(dump_file, "{}", version).unwrap();
                        // Add pre-execution state to the fake executor
                        if let Some(reads) = state_view.data_read_stake_keys {
                            for (state_key, state_value) in reads.lock().unwrap().iter() {
                                // println!("set value by key from reads:{:?}", state_key);
                                executor.set(state_key.clone(), state_value.clone());
                            }
                        }
                        // if !output.write_set().is_empty() {
                        //     let new_state_view = DebuggerStateView::new(self.debugger.clone(), version);
                        //     for (state_key, _) in output.write_set() {
                        //         if !executor.data_store().contains_key(state_key) {
                        //             println!("write set set value by key from reads:{:?}", state_key);
                        //             let val_res = new_state_view.get_state_value(state_key);
                        //             if let Ok(Some(val)) = val_res {
                        //                 executor.set(state_key.clone(), val);
                        //             }
                        //         }
                        //     }
                        // }

                        let mut file = File::create(state_path).unwrap();
                        file.write_all(&bcs::to_bytes(&executor.data_store()).unwrap()).unwrap();
                    } else { // Retrieve the state
                        println!("deser data....");
                        let mut file = File::open(state_path).unwrap();
                        // read the same file back into a Vec of bytes
                        let mut buffer = Vec::<u8>::new();
                        file.read_to_end(&mut buffer).unwrap();
                        let state = bcs::from_bytes::<FakeDataStore>(&buffer).unwrap();
                        *executor.data_store_mut() = state;
                    }

                    // Dump and compile the source code if necessary
                    if !BuiltPackage::is_aptos_package(&package_name) {
                        let package = map.get(&(addr, package_name.clone())).unwrap();
                        println!("package name:{}", package_name);
                        if !compiled_package_cache.contains_key(&(addr, package_name.clone(), Some(package.upgrade_number), bytecode_version)) {
                            BuiltPackage::dump_and_compile_from_package_metadata(PathBuf::from("."), package_name.clone(), addr, package.upgrade_number, &map, &mut compiled_package_cache, None, bytecode_version).unwrap();
                        }
                    }
                    let upgrade_number = if BuiltPackage::is_aptos_package(&package_name) {
                        None
                    } else {
                        let package = map.get(&(addr, package_name.clone())).unwrap();
                        Some(package.upgrade_number)
                    };

                    // Execute the txn with compiled module
                    if compiled_package_cache.contains_key(&(addr, package_name.clone(), upgrade_number, bytecode_version)) {
                        let compiled_package = compiled_package_cache.get(&(addr, package_name.clone(), upgrade_number, bytecode_version)).unwrap();
                        if let Transaction::UserTransaction(signed_trans) = &txn {
                            let sender = signed_trans.sender();
                            let signer = MoveValue::Signer(sender).simple_serialize();
                            let payload = signed_trans.payload();
                            if let TransactionPayload::EntryFunction(entry_function) =
                            payload {
                                // println!("entry fun:{:?}", entry_function);
                                let root_modules = compiled_package.all_modules();
                                for compiled_module in root_modules {
                                    if let CompiledUnitEnum::Module(module) = &compiled_module.unit {
                                        let module_blob = compiled_module.unit.serialize(None);
                                        executor.add_module(&module.module.self_id(), module_blob);
                                    }
                                }
                                let mut args = entry_function.args().to_vec();
                                // println!("entry_function.ty_args().len():{}, args.len():{}", entry_function.ty_args().len(), args.len());
                                // args.insert(0, signer.unwrap());
                                // let state_view = DebuggerStateView::new_with_fake_data(self.debugger.clone(), version, executor.data_store().clone());
                                // let state_view_storage = state_view.as_move_resolver();
                                // let features = Features::fetch_config(&state_view_storage).unwrap_or_default();
                                // let res = executor.try_exec_with_debugger(entry_function.module().name().as_str(), entry_function.function().as_str(), entry_function.ty_args().to_vec(), args, state_view_storage, features);
                                // println!("fun:{}, {}", entry_function.module().name().as_str(), entry_function.function().as_str());


                                let res = executor.try_exec_entry_with_features(vec![sender], entry_function, features);
                                // let res = executor.execute_transaction_block(vec![txn]);
                                //println!("{}:{:?}", version, res.unwrap());
                                //println!("whether equal: {}", res.clone().unwrap()[0] == *output);
                                // println!("res:{:?}", res)
                                if res.is_err() {
                                    writeln!(err_file, "res is error,output version {}:{:?}, entry:{:?}", version, output, entry_function).unwrap();
                                    continue;
                                }
                                let res_unwrapped = res.unwrap();
                                let compare_result = Self::compare_correct_trans_output(output, &res_unwrapped);
                                if compare_result.is_err() {
                                    writeln!(err_file, "error in fun:{}::{} at:{} \n {:?}", entry_function.module().name().as_str(), entry_function.function().as_str(), version, compare_result).unwrap();
                                }
                                println!("version:{}: {:?}", version, compare_result);
                                count += 1;
                            }
                        }
                    }
                }

            }
            cur_version += batch_num;
        }
        cur_version
    }

    fn compare_correct_trans_output(output: &TransactionOutput, res: &(WriteSet, Vec<ContractEvent>)) -> Result<()> {
        let output_write_set = output.write_set();
        let output_events = output.events();
        if *res.1 != *output_events {
            return Err(anyhow::Error::msg("event not equal"));
        }
        for (state_key, val) in res.0.iter() {
            let output_val_opt = output_write_set.get(state_key);
            if let Some(output_val) = output_val_opt {
                if output_val != val {
                    println!("value is diff in key:{:?}", state_key);
                    println!("output value:{:?}", output_val);
                    println!("result value:{:?}", val);
                    return Err(anyhow::Error::msg(format!("value at {:?} is different\n output value:{:?}, result value:{:?}", state_key, output_val, val)));
                }
            } else {
                println!("key is different:{:?}", state_key);
                return Err(anyhow::Error::msg(format!("key is different:{:?}", state_key)));
            }
        }
        Ok(())
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
