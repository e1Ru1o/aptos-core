// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use aptos_framework::APTOS_PACKAGES;

mod data_collection;
mod execution;

pub use data_collection::*;
pub use execution::*;

pub(crate) const STATE_DATA: &str = "state_data";
pub(crate) const TXN_DATA: &str = "txn_data";
pub(crate) const FEATURE_DATA: &str = "feature_data";
pub(crate) const INDEX_FILE: &str = "version_index.txt";

pub fn check_aptos_packages_availability(path: PathBuf) -> bool {
    if !path.exists() {
        return false;
    }
    for package in APTOS_PACKAGES {
        if !path.join(package).exists() {
            return false;
        }
    }
    true
}
