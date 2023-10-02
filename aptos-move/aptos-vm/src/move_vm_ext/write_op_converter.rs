// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::move_vm_ext::AptosMoveResolver;
use aptos_aggregator::delta_change_set::serialize;
use aptos_types::{
    on_chain_config::{CurrentTimeMicroseconds, OnChainConfig},
    state_store::{
        state_key::StateKey,
        state_value::{StateValueMetadata, StateValueMetadataKind},
    },
    write_set::WriteOp,
};
use aptos_vm_types::change_set::GroupWrite;
use bytes::Bytes;
use move_core_types::{
    effects::{AccountChangeSet, Op as MoveStorageOp},
    vm_status::{err_msg, StatusCode, VMStatus},
};
use std::collections::HashMap;

pub(crate) struct WriteOpConverter<'r> {
    remote: &'r dyn AptosMoveResolver,
    new_slot_metadata: Option<StateValueMetadata>,
}

macro_rules! convert_impl {
    ($convert_func_name:ident, $get_metadata_callback:ident) => {
        pub(crate) fn $convert_func_name(
            &self,
            state_key: &StateKey,
            move_storage_op: MoveStorageOp<Bytes>,
            legacy_creation_as_modification: bool,
        ) -> Result<WriteOp, VMStatus> {
            self.convert(
                self.remote.$get_metadata_callback(state_key),
                move_storage_op,
                legacy_creation_as_modification,
            )
        }
    };
}

impl<'r> WriteOpConverter<'r> {
    convert_impl!(convert_resource, get_resource_state_value_metadata);

    convert_impl!(convert_module, get_module_state_value_metadata);

    convert_impl!(convert_aggregator, get_aggregator_v1_state_value_metadata);

    pub(crate) fn new(
        remote: &'r dyn AptosMoveResolver,
        is_storage_slot_metadata_enabled: bool,
    ) -> Self {
        let mut new_slot_metadata: Option<StateValueMetadata> = None;
        if is_storage_slot_metadata_enabled {
            if let Some(current_time) = CurrentTimeMicroseconds::fetch_config(remote) {
                // The deposit on the metadata is a placeholder (0), it will be updated later when
                // storage fee is charged.
                new_slot_metadata = Some(StateValueMetadata::new(0, &current_time));
            }
        }

        Self {
            remote,
            new_slot_metadata,
        }
    }

    pub(crate) fn convert_resource_group_v1(
        &self,
        state_key: &StateKey,
        group_changes: AccountChangeSet,
        legacy_creation_as_modification: bool,
    ) -> Result<GroupWrite, VMStatus> {
        // Resource group metadata is stored at the group StateKey, and can be obtained via the
        // same interfaces at for a resource at a given StateKey.
        let state_value_metadata_result = self.remote.get_resource_state_value_metadata(state_key);
        // Currently, due to read-before-write and a gas charge on the first read that is based
        // on the group size, this should simply re-read a cached (speculative) group size.
        let pre_group_size = self.remote.resource_group_size(state_key).map_err(|_| {
            VMStatus::error(
                StatusCode::STORAGE_ERROR,
                err_msg("Error querying resource group size"),
            )
        })?;

        let mut inner_ops = HashMap::new();

        let group_size_arithmetics_error = || {
            VMStatus::error(
                StatusCode::STORAGE_ERROR,
                err_msg("Group size underflow while applying updates"),
            )
        };
        let post_group_size = group_changes.into_resources().into_iter().try_fold(
            pre_group_size,
            |cur_size, (tag, current_op)| {
                let cur_size = if !matches!(current_op, MoveStorageOp::New(_)) {
                    let old_size = self
                        .remote
                        .resource_size_in_group(state_key, &tag)
                        .map_err(|_| {
                            VMStatus::error(
                                StatusCode::STORAGE_ERROR,
                                err_msg("Error querying resource group size"),
                            )
                        })?;
                    cur_size
                        .checked_sub(old_size)
                        .ok_or_else(group_size_arithmetics_error)?
                } else {
                    cur_size
                };

                let (new_size, legacy_op) = match current_op {
                    MoveStorageOp::Delete => (cur_size, WriteOp::Deletion),
                    MoveStorageOp::Modify(new_data) => (
                        cur_size
                            .checked_add(new_data.len() as u64)
                            .ok_or_else(group_size_arithmetics_error)?,
                        WriteOp::Modification(new_data),
                    ),
                    MoveStorageOp::New(data) => (
                        cur_size
                            .checked_add(data.len() as u64)
                            .ok_or_else(group_size_arithmetics_error)?,
                        WriteOp::Creation(data),
                    ),
                };
                inner_ops.insert(tag, legacy_op);
                Ok::<u64, VMStatus>(new_size)
            },
        )?;

        // Create the op that would look like a combined V0 resource group MoveStorageOp,
        // except it encodes the (speculative) size of the group after applying the updates
        // which is used for charging storage fees. Moreover, the metadata computation occurs
        // fully backwards compatibly, and lets obtain final storage op by replacing bytes.
        let metadata_op = if post_group_size == 0 {
            MoveStorageOp::Delete
        } else {
            let encoded_group_size = bcs::to_bytes(&post_group_size)
                .map_err(|_| {
                    VMStatus::error(
                        StatusCode::STORAGE_ERROR,
                        err_msg("Group size underflow while applying updates"),
                    )
                })?
                .into();
            if pre_group_size == 0 {
                MoveStorageOp::New(encoded_group_size)
            } else {
                MoveStorageOp::Modify(encoded_group_size)
            }
        };
        Ok(GroupWrite {
            metadata_op: self.convert(
                state_value_metadata_result,
                metadata_op,
                legacy_creation_as_modification,
            )?,
            inner_ops,
        })
    }

    fn convert(
        &self,
        state_value_metadata_result: anyhow::Result<Option<StateValueMetadataKind>>,
        move_storage_op: MoveStorageOp<Bytes>,
        legacy_creation_as_modification: bool,
    ) -> Result<WriteOp, VMStatus> {
        use MoveStorageOp::*;
        use WriteOp::*;

        let maybe_existing_metadata = state_value_metadata_result.map_err(|_| {
            VMStatus::error(
                StatusCode::STORAGE_ERROR,
                err_msg("Storage read failed when converting change set."),
            )
        })?;

        let write_op = match (maybe_existing_metadata, move_storage_op) {
            (None, Modify(_) | Delete) => {
                return Err(VMStatus::error(
                    // Possible under speculative execution, returning storage error waiting for re-execution
                    StatusCode::STORAGE_ERROR,
                    err_msg("When converting write op: updating non-existent value."),
                ));
            },
            (Some(_), New(_)) => {
                return Err(VMStatus::error(
                    // Possible under speculative execution, returning storage error waiting for re-execution
                    StatusCode::STORAGE_ERROR,
                    err_msg("When converting write op: Recreating existing value."),
                ));
            },
            (None, New(data)) => match &self.new_slot_metadata {
                None => {
                    if legacy_creation_as_modification {
                        Modification(data)
                    } else {
                        Creation(data)
                    }
                },
                Some(metadata) => CreationWithMetadata {
                    data,
                    metadata: metadata.clone(),
                },
            },
            (Some(existing_metadata), Modify(data)) => {
                // Inherit metadata even if the feature flags is turned off, for compatibility.
                match existing_metadata {
                    None => Modification(data),
                    Some(metadata) => ModificationWithMetadata { data, metadata },
                }
            },
            (Some(existing_metadata), Delete) => {
                // Inherit metadata even if the feature flags is turned off, for compatibility.
                match existing_metadata {
                    None => Deletion,
                    Some(metadata) => DeletionWithMetadata { metadata },
                }
            },
        };
        Ok(write_op)
    }

    pub(crate) fn convert_aggregator_modification(
        &self,
        state_key: &StateKey,
        value: u128,
    ) -> Result<WriteOp, VMStatus> {
        let maybe_existing_metadata = self
            .remote
            .get_aggregator_v1_state_value_metadata(state_key)
            .map_err(|_| VMStatus::error(StatusCode::STORAGE_ERROR, None))?;
        let data = serialize(&value).into();

        let op = match maybe_existing_metadata {
            None => {
                match &self.new_slot_metadata {
                    // n.b. Aggregator writes historically did not distinguish Create vs Modify.
                    None => WriteOp::Modification(data),
                    Some(metadata) => WriteOp::CreationWithMetadata {
                        data,
                        metadata: metadata.clone(),
                    },
                }
            },
            Some(existing_metadata) => match existing_metadata {
                None => WriteOp::Modification(data),
                Some(metadata) => WriteOp::ModificationWithMetadata { data, metadata },
            },
        };

        Ok(op)
    }
}
