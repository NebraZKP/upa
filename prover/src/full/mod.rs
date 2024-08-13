use clap::{Parser, Subcommand};

pub use self::{
    keygen::{keygen, KeygenParams},
    prove::{prove, ProveParams},
};
pub use crate::universal_outer::{verify, VerifyParams};

mod keygen;
mod prove;

#[derive(Parser, Debug)]
pub struct FullParams {
    #[command(subcommand)]
    command: FullCommand,
}

#[derive(Subcommand, Debug)]
enum FullCommand {
    /// Generate VK and PK
    #[command()]
    Keygen(KeygenParams),

    #[command()]
    Prove(ProveParams),

    #[command()]
    Verify(VerifyParams),
}

pub fn full(params: FullParams) {
    match params.command {
        FullCommand::Keygen(params) => keygen(params),
        FullCommand::Prove(params) => prove(params),
        FullCommand::Verify(params) => verify(params),
    }
}
