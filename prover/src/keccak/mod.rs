use clap::{Parser, Subcommand};

pub use self::{
    keygen::{keygen, KeygenParams},
    prove::{prove, ProveParams},
    verify::{verify, VerifyParams},
};

mod keygen;
mod prove;
mod verify;

#[derive(Parser, Debug)]
pub struct KeccakParams {
    #[command(subcommand)]
    command: KeccakCommand,
}

#[derive(Subcommand, Debug)]
enum KeccakCommand {
    /// Generate VK and PK
    #[command()]
    Keygen(KeygenParams),

    #[command()]
    Prove(ProveParams),

    #[command()]
    Verify(VerifyParams),
}

pub fn keccak(params: KeccakParams) {
    match params.command {
        KeccakCommand::Keygen(params) => keygen(params),
        KeccakCommand::Prove(params) => prove(params),
        KeccakCommand::Verify(params) => verify(params),
    }
}
