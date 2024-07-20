use circuits::{
    outer::{
        universal, OuterCircuitInputs, OuterCircuitWrapper, OuterInstanceInputs,
    },
    utils::upa_config::UpaConfig,
};
use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK},
};
use snark_verifier_sdk::SHPLONK;

pub use self::{
    keygen::{keygen, KeygenParams},
    prove::{prove, ProveParams},
    verifier_yul_code::{generate_evm_verifier, GenerateVerifierParams},
    verify::{verify, VerifyParams},
};

mod keygen;
mod prove;
mod verifier_yul_code;
mod verify;

/// Type alias for specifying whether prover uses Shplonk/GWC
pub type UniversalOuterCircuit<'a> = OuterCircuitWrapper<
    'a,
    SHPLONK,
    universal::UniversalOuterCircuit,
    ProverSHPLONK<'a, Bn256>,
    VerifierSHPLONK<'a, Bn256>,
>;
pub type UniversalOuterConfig = UpaConfig;
pub type UniversalOuterCircuitInputs =
    OuterCircuitInputs<universal::UniversalOuterCircuit>;
pub type UniversalOuterInstanceInputs =
    OuterInstanceInputs<universal::UniversalOuterCircuit>;

#[derive(Debug, Parser)]
pub struct UniversalOuterParams {
    #[command(subcommand)]
    command: UniversalOuterCommand,
}

#[derive(Debug, Subcommand)]
enum UniversalOuterCommand {
    /// Generate VK and PK
    #[command()]
    Keygen(KeygenParams),

    /// Generate the on-chain verifier code.
    #[command()]
    GenerateVerifier(GenerateVerifierParams),

    /// Generate a proof (as EVM calldata)
    #[command()]
    Prove(ProveParams),

    /// Read call-data and verify locally
    #[command()]
    Verify(VerifyParams),
}

/// Entry point to the `outer` series of subcommands.  See description in
/// main.rs.
pub fn universal_outer(params: UniversalOuterParams) {
    match params.command {
        UniversalOuterCommand::Keygen(params) => keygen(params),
        UniversalOuterCommand::GenerateVerifier(params) => {
            generate_evm_verifier(params)
        }
        UniversalOuterCommand::Prove(params) => prove(params),
        UniversalOuterCommand::Verify(params) => verify(params),
    }
}
