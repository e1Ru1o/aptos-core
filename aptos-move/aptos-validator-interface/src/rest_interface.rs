// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::AptosValidatorInterface;
use anyhow::{anyhow, Result};
use aptos_api_types::{AptosError, AptosErrorCode};
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
use aptos_framework::{
    natives::code::{ModuleMetadata, PackageMetadata, PackageRegistry, UpgradePolicy},
    unzip_metadata_str,
};
use std::collections::BTreeMap;

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

    async fn get_committed_transactions_with_available_src(&self,
        start: Version,
        limit: u64,
    ) -> Result<Vec<(Transaction, Vec<PackageMetadata>)>> {
        let mut txns = Vec::with_capacity(limit as usize);
        //while txns.len() < limit as usize {
            let temp_txns = self.0
                .get_transactions_bcs(
                    Some(start + txns.len() as u64),
                    Some(limit as u16 - txns.len() as u16),
                )
                .await?
                .into_inner();
            for txn in temp_txns {
                if let Transaction::UserTransaction(signed_trans) = txn.transaction.clone() {
                    let payload = signed_trans.payload();
                    if let aptos_types::transaction::TransactionPayload::EntryFunction(entry_function) = payload {
                        let m = entry_function.module();
                        let addr = m.address();
                        println!("addr:{}", addr);
                        let packages =
                            self.0.get_account_resource_bcs::<PackageRegistry>
                            (*addr, "0x1::code::PackageRegistry").await?.into_inner().packages;
                        let mut src_available = true;
                        for package in &packages {
                            println!("package name:{}", package.name);
                            for module_metadata in &package.modules {
                                if module_metadata.source.is_empty() {
                                    src_available = false;
                                    break;
                                } else {
                                    println!("module name:{}", module_metadata.name);
                                    let source = unzip_metadata_str(&module_metadata.source)?;
                                    //println!("src:{:?}", source);
                                }
                            }
                        }
                        if src_available {
                            txns.push((txn.transaction, packages.clone()));
                        }
                    }
                }
            }
        //}
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
