// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use anyhow::Result;
use aptos_comparison_testing::DataCollection;
use aptos_comparison_testing::Execution;
use aptos_rest_client::Client;
use aptos_vm::AptosVM;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use url::Url;

#[derive(Subcommand)]
pub enum Cmd {
    /// Collect and dump the data
    Dump {
        endpoint: String,
        output_path: Option<PathBuf>,
        #[clap(long)]
        batch_size: Option<u64>,
        #[clap(long, default_value_t = false)]
        overwrite: bool
    },
    /// Execution
    Execute {
        input_path: Option<PathBuf>,
        #[clap(long, default_value_t = false)]
        compare: bool,
        #[clap(long, default_value_t = false)]
        all: bool,
    },
}

#[derive(Parser)]
pub struct Argument {
    #[clap(subcommand)]
    cmd: Cmd,

    #[clap(long)]
    begin_version: u64,

    #[clap(long)]
    limit: u64,

}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Argument::parse();

    match args.cmd {
        Cmd::Dump { endpoint, output_path, batch_size, overwrite } => {

            let batch_size = if let Some(batch) = batch_size {
                batch
            } else {
                1
            };

            let output = if let Some(path) = output_path {
                path
            } else {
                PathBuf::from(".")
            };

            let data_collector = DataCollection::new_with_rest_client(Client::new(Url::parse(&endpoint)?), output, batch_size, overwrite)?;
            data_collector
                .dump_data(args.begin_version, args.limit).await?;
        },
        Cmd::Execute { input_path, compare, all} => {

            let input = if let Some(path) = input_path {
                path
            } else {
                PathBuf::from(".")
            };

            let executor = Execution::new(input, compare, all);


            return Ok(());
        }
    };
    Ok(())
}
