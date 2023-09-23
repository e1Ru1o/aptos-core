// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::AptosValidatorInterface;
use anyhow::{anyhow, Result};
use aptos_api_types::{AptosError, AptosErrorCode};
use aptos_framework::{
    natives::code::{PackageMetadata, PackageRegistry},
    unzip_metadata_str,
    BuiltPackage,
};
use move_core_types::language_storage::ModuleId;
use aptos_rest_client::{
    error::{AptosErrorResponse, RestError},
    Client,
};
use aptos_types::{
    account_address::AccountAddress,
    account_state::AccountState,
    state_store::{state_key::StateKey, state_value::StateValue},
    transaction::{Transaction, TransactionInfo, Version},
};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use async_recursion::async_recursion;

pub struct RestDebuggerInterface(Client);

impl RestDebuggerInterface {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

#[async_trait::async_trait]
impl AptosValidatorInterface for RestDebuggerInterface {
    async fn get_account_state_by_version(
        &self,
        account: AccountAddress,
        version: Version,
    ) -> Result<Option<AccountState>> {
        let resource = self
            .0
            .get_account_resources_at_version_bcs(account, version)
            .await
            .map_err(|err| anyhow!("Failed to get account states: {:?}", err))?
            .into_inner()
            .into_iter()
            .map(|(key, value)| (key.access_vector(), value))
            .collect::<BTreeMap<_, _>>();

        Ok(Some(AccountState::new(account, resource)))
    }

    async fn get_state_value_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<StateValue>> {
        match self.0.get_raw_state_value(state_key, version).await {
            Ok(resp) => Ok(Some(bcs::from_bytes(&resp.into_inner())?)),
            Err(err) => match err {
                RestError::Api(AptosErrorResponse {
                    error:
                        AptosError {
                            error_code: AptosErrorCode::StateValueNotFound,
                            ..
                        },
                    ..
                }) => Ok(None),
                _ => Err(anyhow!(err)),
            },
        }
    }

    async fn get_committed_transactions(
        &self,
        start: Version,
        limit: u64,
    ) -> Result<(Vec<Transaction>, Vec<TransactionInfo>)> {
        let mut txns = Vec::with_capacity(limit as usize);
        let mut txn_infos = Vec::with_capacity(limit as usize);

        while txns.len() < limit as usize {
            self.0
                .get_transactions_bcs(
                    Some(start + txns.len() as u64),
                    Some(limit as u16 - txns.len() as u16),
                )
                .await?
                .into_inner()
                .into_iter()
                .for_each(|txn| {
                    txns.push(txn.transaction);
                    txn_infos.push(txn.info);
                });
            println!("Got {}/{} txns from RestApi.", txns.len(), limit);
        }

        Ok((txns, txn_infos))
    }

    async fn get_committed_transactions_with_available_src(
        &self,
        start: Version,
        limit: u64,
    ) -> Result<Vec<(u64, Transaction, (AccountAddress, String), HashMap<(AccountAddress, String), PackageMetadata>)>> {
        let mut txns = Vec::with_capacity(limit as usize);
        let temp_txns = self
            .0
            .get_transactions_bcs(
                Some(start + txns.len() as u64),
                Some(limit as u16 - txns.len() as u16),
            )
            .await?
            .into_inner();

        let locate_package_with_src = |module: &ModuleId, packages: &[PackageMetadata]|-> Option<PackageMetadata> {
            for package in packages {
                for module_metadata in &package.modules {
                    if module_metadata.name == module.name().as_str() {
                        // If the source is not available or the upgrade policy is not back-compaitible, return None
                        if module_metadata.source.is_empty() || package.upgrade_policy.policy == 0 {
                            return None;
                        } else {
                            return Some(package.clone());
                        }
                    }
                }
            }
            None
        };

        #[async_recursion]
        async fn retrieve_available_src(client: &Client, package: &PackageMetadata, account_address: AccountAddress, data: &mut HashMap<(AccountAddress, String), PackageMetadata>) -> Result<()> {
            if package.modules.is_empty() {
                return Err(anyhow::anyhow!("no modules"));
            }
            if package.modules[0].source.is_empty() {
                return Err(anyhow::anyhow!("no src available"));
            } else {
                let package_name = package.clone().name;
                if !data.contains_key(&(account_address, package_name.clone())) {
                    data.insert((account_address.clone(), package_name.clone()), package.clone());
                    retrieve_dep_packages_with_src(client, package, data).await
                } else {
                    return Ok(());
                }
            }
        };

        #[async_recursion]
        async fn retrieve_dep_packages_with_src(client: &Client, root_package: &PackageMetadata, data: &mut HashMap<(AccountAddress, String), PackageMetadata>)
            -> Result<()> {
            for dep in &root_package.deps {
                let packages = client
                    .get_account_resource_bcs::<PackageRegistry>(
                        dep.account,
                        "0x1::code::PackageRegistry",
                    )
                    .await?
                    .into_inner()
                    .packages;
                for package in &packages {
                    retrieve_available_src(client, package, dep.account, data).await?;
                }
            }
            Ok(())
        };

        for txn in temp_txns {
            if let Transaction::UserTransaction(signed_trans) = txn.transaction.clone() {
                let payload = signed_trans.payload();
                if let aptos_types::transaction::TransactionPayload::EntryFunction(entry_function) =
                    payload
                {
                    if entry_function.function().as_str() == "publish_package_txn" {
                        println!("skip publish txn");
                        continue;
                    }
                    let m = entry_function.module();
                    let addr = m.address();
                    if *addr == AccountAddress::ONE { // if the function is from 0x1, continue
                        txns.push((txn.version, txn.transaction.clone(), (*addr, "AptosFramework".to_string()), HashMap::new()));
                        continue;
                    }
                    let packages = self
                        .0
                        .get_account_resource_bcs::<PackageRegistry>(
                            addr.clone(),
                            "0x1::code::PackageRegistry",
                        )
                        .await?
                        .into_inner()
                        .packages;
                    let target_package_opt = locate_package_with_src(m, &packages);
                    if let Some(target_package) = target_package_opt {
                        // target_package is the root package
                        let mut map = HashMap::new();
                        if let Ok(()) = retrieve_dep_packages_with_src(&self.0, &target_package, &mut map).await {
                            map.insert((addr.clone(), target_package.clone().name), target_package.clone());
                            txns.push((txn.version, txn.transaction, (*addr, target_package.name), map));
                        }
                    }
                }
            }
        }
        return Ok(txns);
    }

    async fn get_latest_version(&self) -> Result<Version> {
        Ok(self.0.get_ledger_information().await?.into_inner().version)
    }

    async fn get_version_by_account_sequence(
        &self,
        account: AccountAddress,
        seq: u64,
    ) -> Result<Option<Version>> {
        Ok(Some(
            self.0
                .get_account_transactions_bcs(account, Some(seq), None)
                .await?
                .into_inner()[0]
                .version,
        ))
    }
}
