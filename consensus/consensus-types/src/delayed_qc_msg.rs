// Copyright © Aptos Foundation
// Parts of the project are originally copyright © Meta Platforms, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{common::Round, vote_data::VoteData};
use aptos_types::ledger_info::LedgerInfo;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// DelayedQCMsg is the struct that is sent by the proposer to self when it receives enough votes
/// for a QC but it still delays the creation of the QC to ensure that slow nodes are given enough
/// time to catch up to the chain and cast their votes.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DelayedQcMsg {
    round: Round,
    /// Vote data for the QC that is being delayed.
    vote: VoteData,
    /// Ledger info associated with the QC that is being delayed.
    ledger_info: LedgerInfo,
}

impl Display for DelayedQcMsg {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "DelayedQcMsg: round [{}] and ledger info [{}]",
            self.round,
            self.ledger_info()
        )
    }
}

impl DelayedQcMsg {
    pub fn new(round: Round, vote: VoteData, ledger_info: LedgerInfo) -> Self {
        Self {
            round,
            vote,
            ledger_info,
        }
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn vote(&self) -> &VoteData {
        &self.vote
    }

    pub fn ledger_info(&self) -> &LedgerInfo {
        &self.ledger_info
    }
}
