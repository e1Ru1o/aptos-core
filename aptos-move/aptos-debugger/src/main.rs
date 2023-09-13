// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use anyhow::Result;
use aptos_debugger::AptosDebugger;
use aptos_rest_client::Client;
use aptos_vm::AptosVM;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use url::Url;

#[derive(Subcommand)]
pub enum Target {
    /// Use full node's rest api as query endpoint.
    Rest { endpoint: String },
    /// Use a local db instance to serve as query endpoint.
    DB { path: PathBuf },
}
#[derive(Parser)]
pub struct Argument {
    #[clap(subcommand)]
    target: Target,

    #[clap(long)]
    begin_version: u64,

    #[clap(long)]
    limit: u64,

    #[clap(long, default_value_t = 1)]
    concurrency_level: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    aptos_logger::Logger::new().init();
    let args = Argument::parse();
    AptosVM::set_concurrency_level_once(args.concurrency_level);

    let debugger = match args.target {
        Target::Rest { endpoint } => {
            AptosDebugger::rest_client(Client::new(Url::parse(&endpoint)?))?
        },
        Target::DB { path } => AptosDebugger::db(path)?,
    };

    let mut path = PathBuf::from(".").join("dumped_txn_versions.txt");
    let mut file = if !path.exists() {
        File::create(path)
            .expect("Error encountered while creating file!")
    } else {
        OpenOptions::new()
            .write(true)
            .append(true)
            .open(path)
            .unwrap()
    };
    debugger
        .dump_past_transactions(args.begin_version, args.limit, &mut file).await;
    // println!(
    //     "{:#?}",
    //     debugger
    //         .execute_past_transactions(args.begin_version, args.limit)
    //         .await?
    // );

    Ok(())
}

#[test]
fn verify_tool() {
    use clap::CommandFactory;
    Argument::command().debug_assert()
}
