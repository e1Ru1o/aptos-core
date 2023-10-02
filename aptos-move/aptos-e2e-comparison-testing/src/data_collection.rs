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
use crate::{STATE_DATA, TXN_DATA, INDEX_FILE, check_aptos_packages_availability};
use aptos_framework::{BuildOptions, BuiltPackage, APTOS_COMMONS, APTOS_PACKAGES};
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


pub struct DataCollection {
    debugger: Arc<dyn AptosValidatorInterface + Send>,
    current_dir: PathBuf,
    batch_size: u64,
    _overwrite: bool,
}


impl DataCollection {
    pub fn new(debugger: Arc<dyn AptosValidatorInterface + Send>, current_dir: PathBuf, batch_size: u64, _overwrite: bool) -> Self {
        Self { debugger, current_dir, batch_size, _overwrite }
    }

    pub fn new_with_rest_client(rest_client: Client,  current_dir: PathBuf, batch_size: u64, _overwrite: bool) -> Result<Self> {
        Ok(Self::new(Arc::new(RestDebuggerInterface::new(rest_client)), current_dir, batch_size, _overwrite))
    }

    pub fn execute_transactions_at_version_with_state_view(
        &self,
        txns: Vec<Transaction>,
        debugger_stateview: &DebuggerStateView
    ) -> Result<Vec<TransactionOutput>> {
        AptosVM::execute_block(txns, debugger_stateview, None)
            .map_err(|err| format_err!("Unexpected VM Error: {:?}", err))
    }

    // pub fn check_aptos_packages_availability(path: PathBuf) -> bool {
    //     if !path.exists() {
    //         return false;
    //     }
    //     for package in APTOS_PACKAGES {
    //         if !path.join(package).exists() {
    //             return false;
    //         }
    //     }
    //     true
    // }

    pub async fn dump_data(
        &self,
        begin: Version,
        limit: u64,
    ) -> anyhow::Result<()> {

        let aptos_commons_path = self.current_dir.join(APTOS_COMMONS);
        if !check_aptos_packages_availability(aptos_commons_path.clone()) {
            return Err(anyhow::Error::msg("aptos packages are missing"));;
        }
        let mut compiled_package_cache: BTreeMap<(AccountAddress, String, Option<u64>, u32), CompiledPackage> = BTreeMap::new();
        // Compile aptos packages
        BuiltPackage::compile_aptos_packages(&aptos_commons_path, &mut compiled_package_cache)?;


        let mut index_path = self.current_dir.join(INDEX_FILE);
        let mut index_file = if !index_path.exists() {
            File::create(index_path)
                .expect("Error encountered while creating file!")
        } else {
            OpenOptions::new()
                .write(true)
                .append(true)
                .open(index_path)
                .unwrap()
        };

        let mut state_data_path = self.current_dir.join(STATE_DATA);
        if !state_data_path.exists() {
            std::fs::create_dir_all(state_data_path.as_path()).unwrap();
        }

        let mut txn_data_path = self.current_dir.join(TXN_DATA);
        if !txn_data_path.exists() {
            std::fs::create_dir_all(txn_data_path.as_path()).unwrap();
        }

        let mut cur_version = begin;
        let mut count = 0;
        let mut package_registry_cache: BTreeMap<AccountAddress, PackageRegistry> = BTreeMap::new();


        while count < limit {
            let v = self
                .debugger
                .get_committed_transactions_with_available_src(cur_version.clone(), self.batch_size, &mut package_registry_cache)
                .await.unwrap_or_default();
            if !v.is_empty() {

                for (version, txn, (addr, package_name), map) in v {
                    println!("get txn at version:{}", version);
                    // println!("addr:{}, package name:{}", addr, package_name);
                    // Obtain the state before execution
                    let state_view = DebuggerStateView::new_with_data_reads(self.debugger.clone(), version);
                    let state_view_storage = state_view.as_move_resolver();
                    Features::fetch_config(&state_view_storage).unwrap_or_default();
                    //let features = Features::fetch_config(&state_view_storage).unwrap_or_default();

                    let bytecode_version = 6;

                    let epoch_result_res = self.execute_transactions_at_version_with_state_view(vec![txn.clone()], &state_view);
                    ;                   if let Err(err) = epoch_result_res {
                        println!("execution error during transaction at version:{} :{}", version, err.to_string());
                        continue;
                    }
                    let mut epoch_result = epoch_result_res.unwrap();
                    assert_eq!(epoch_result.len(), 1);

                    let output = &epoch_result[0];
                    if output.status().is_discarded() || output.status().is_retry() {
                        continue;
                    }
                    let status = output.status().status().unwrap();
                    if !status.is_success() {
                        println!("skip unsucessful txn:{}", version);
                        continue;
                    }

                    // Dump and compile the source code if necessary
                    if !BuiltPackage::is_aptos_package(&package_name) {
                        let package = map.get(&(addr, package_name.clone())).unwrap();
                        println!("package name:{}", package_name);
                        if !compiled_package_cache.contains_key(&(addr, package_name.clone(), Some(package.upgrade_number), bytecode_version)) {
                            // Dump source code
                            let res = BuiltPackage::dump_and_compile_from_package_metadata(self.current_dir.clone(), package_name.clone(), addr, package.upgrade_number, &map, &mut compiled_package_cache, None, bytecode_version);
                            if res.is_err() {
                                println!("compile package failed at:{}", version);
                                continue;
                            }
                            // Dump version
                            writeln!(index_file, "{}:{}.{}.{}", version, package_name, addr, package.upgrade_number).unwrap();
                        }
                    } else {
                        writeln!(index_file, "{}:{}.{}", version, package_name, addr).unwrap();
                    }

                    // Dump txn
                    let txn_path = self.current_dir.join(TXN_DATA).join(format!("{}_txn", version));

                    if !txn_path.exists() {
                        let mut txn_file = File::create(txn_path).unwrap();
                        txn_file.write_all(&bcs::to_bytes(&txn).unwrap()).unwrap();
                    } else {
                        // TODO: overwrite the data state
                    }

                    // Dump data state
                    let data_state = state_view.data_read_stake_keys.unwrap();

                    // If the state has not been dumped, get the state and dump it
                    let state_path = self.current_dir.join(STATE_DATA).join(format!("{}_state", version));
                    if !state_path.exists() {
                        let mut data_state_file = File::create(state_path).unwrap();
                        let state_store = FakeDataStore::new_with_state_value(data_state.lock().unwrap().to_owned());
                        data_state_file.write_all(&bcs::to_bytes(&state_store).unwrap()).unwrap();
                    } else {
                        // TODO: overwrite the data state
                    }


                    count += 1;
                }
            }
            cur_version += self.batch_size;
        }
        Ok(())
    }

}
