#![feature(async_closure)]
#![allow(deprecated)]

use crate::{
    full::{full, FullParams},
    groth16::{groth16, Groth16Params},
    keccak::{keccak, KeccakParams},
    srs::{srs, SrsParams},
    universal_batch_verifier::{
        universal_batch_verifier, UniversalBatchVerifierParams,
    },
    universal_outer::{universal_outer, UniversalOuterParams},
};
use clap::{Parser, Subcommand};
use log::debug;

mod default_values;
mod file_utils;
mod full;
mod groth16;
mod keccak;
mod srs;
mod universal_batch_verifier;
mod universal_outer;

#[derive(Parser, Debug)]
#[command(arg_required_else_help(true))]
/// UPA prover tool
struct Cli {
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command()]
    /// SRS operations
    Srs(SrsParams),

    #[command()]
    /// Universal Batch Verifier circuit operations
    UniversalBatchVerifier(UniversalBatchVerifierParams),

    #[command()]
    /// Keccak circuit operations
    Keccak(KeccakParams),

    #[command()]
    /// Universal Outer circuit operations
    UniversalOuter(UniversalOuterParams),

    #[command()]
    /// Groth16 operations
    Groth16(Groth16Params),

    #[command()]
    /// End-to-end aggregated proofs generation and verification
    Full(FullParams),
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    debug!("{cli:?}");

    match cli.command {
        Command::Srs(params) => srs(params),
        Command::UniversalBatchVerifier(params) => {
            universal_batch_verifier(params)
        }
        Command::Keccak(params) => keccak(params),
        Command::UniversalOuter(params) => universal_outer(params),
        Command::Groth16(params) => groth16(params),
        Command::Full(params) => full(params),
    }
}
