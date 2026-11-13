extern crate core;

pub mod cache;
pub mod r#const;
pub mod evm;
pub mod executor;
pub mod feedback;
pub mod fuzzer;
pub mod fuzzers;
pub mod generic_vm;
pub mod indexed_corpus;
pub mod input;
pub mod logger;
pub mod minimizer;
pub mod mutation_utils;
pub mod oracle;
pub mod power_sched;
pub mod scheduler;
pub mod state;
pub mod state_input;
pub mod sync_utils;
pub mod tracer;

use clap::{Parser, Subcommand};
use evm::{evm_main, EvmArgs};

#[derive(Parser)]
#[command(author, version=env!("GIT_VERSION_INFO"), about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Commands {
    Evm(EvmArgs),
}

fn main() {
    logger::init();

    let args = Cli::parse();
    match args.command {
        Commands::Evm(args) => {
            evm_main(args);
        }
    }
}
