use clap::{Parser, Subcommand};

pub use self::{
    compute_circuit_id::{compute_circuit_id, ComputeCircuitIDParams},
    compute_proof_id::{compute_proof_id, ComputeProofIDParams},
    keygen::{keygen, KeygenParams},
    prove::{prove, ProveParams},
    verify::{verify, VerifyParams},
};

mod compute_circuit_id;
mod compute_proof_id;
mod keygen;
mod prove;
mod verify;

/// Setting for the Poseidon transcript used by inner proofs.  0 for most
/// specs.  See documentation for `snark_verifier::util::hash::Poseidon::new`.
// TODO: move this to the `circuit` lib.  Should be defined once for all inner
// circuits, with matching value used in the outer circuit.
pub const SECURE_MDS: usize = 0;

#[derive(Debug, Parser)]
pub struct UniversalBatchVerifierParams {
    #[command(subcommand)]
    command: UniversalBatchVerifierCommand,
}

#[derive(Debug, Subcommand)]
enum UniversalBatchVerifierCommand {
    /// Compute the circuit Id of the given VK
    #[command()]
    ComputeCircuitID(ComputeCircuitIDParams),

    /// Compute the proof Id of the given VK, proof and inputs file
    #[command()]
    ComputeProofID(ComputeProofIDParams),

    /// Generate proving, verification key and protocol file
    #[command()]
    Keygen(KeygenParams),

    /// Prove the validity of a UBV batch
    #[command()]
    Prove(ProveParams),

    /// Verify a batch proof
    #[command()]
    Verify(VerifyParams),
}

pub fn universal_batch_verifier(params: UniversalBatchVerifierParams) {
    match params.command {
        UniversalBatchVerifierCommand::ComputeCircuitID(params) => {
            compute_circuit_id(params)
        }
        UniversalBatchVerifierCommand::ComputeProofID(params) => {
            compute_proof_id(params)
        }
        UniversalBatchVerifierCommand::Keygen(params) => keygen(params),
        UniversalBatchVerifierCommand::Prove(params) => prove(params),
        UniversalBatchVerifierCommand::Verify(params) => verify(params),
    }
}
