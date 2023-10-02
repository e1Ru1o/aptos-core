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
use crate::{STATE_DATA, TXN_DATA};
use aptos_framework::{BuildOptions, BuiltPackage, APTOS_COMMONS};
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


pub struct Execution {
    input_path: PathBuf,
    compare: bool,
    all: bool,
}

impl Execution {
    pub fn new(input_path: PathBuf, compare: bool, all: bool) -> Self {
        Self { input_path, compare, all }
    }

    pub fn execute_transactions_at_version_with_state_view(
        txns: Vec<Transaction>,
        debugger_stateview: &DebuggerStateView
    ) -> Result<Vec<TransactionOutput>> {
        AptosVM::execute_block(txns, debugger_stateview, None)
            .map_err(|err| format_err!("Unexpected VM Error: {:?}", err))
    }


    pub fn set_enable(features: &mut Features, flag: FeatureFlag) {
        let val = flag as u64;
        let byte_index = (val / 8) as usize;
        let bit_mask = 1 << (val % 8);
        if byte_index < features.features.len() {
            (*features).features[byte_index] = features.features[byte_index] | bit_mask;
        }
    }

    pub async fn exec(
        &self,
        begin: Version,
        limit: u64,
    ) -> anyhow::Result<()> {

        let aptos_commons_path = self.input_path.join(APTOS_COMMONS);
        if !check_aptos_packages_availability(aptos_commons_path.clone()) {
            return Err(anyhow::Error::msg("aptos packages are missing"));
        }
        let mut compiled_package_cache: BTreeMap<(AccountAddress, String, Option<u64>, u32), CompiledPackage> = BTreeMap::new();
        BuiltPackage::compile_aptos_packages(&aptos_commons_path, &mut compiled_package_cache)?;

        let state_data_path = self.input_path.join(STATE_DATA);
        if !state_data_path.exists() {
            return Err(anyhow::Error::msg("state data is missing"));
        }
        //TODO: load and find the initial line in the index file

        let txn_path = self.input_path.join(TXN_DATA);
        if !txn_path.exists() {
            return Err(anyhow::Error::msg("txn data is missing"));
        }

        let mut cur_version = begin;
        let mut count = 0;

        let mut error_path = self.input_path.join("error.txt");
        let mut err_file = if !error_path.exists() {
            File::create(error_path)
                .expect("Error encountered while creating file!")
        } else {
            OpenOptions::new()
                .write(true)
                .append(true)
                .open(error_path)
                .unwrap()
        };

        // Compile aptos packages
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

                    let epoch_result_res = Self::execute_transactions_at_version_with_state_view(vec![txn.clone()], &state_view);
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

}
