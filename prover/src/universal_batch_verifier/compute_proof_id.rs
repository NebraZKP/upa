use crate::file_utils::load_app_vk_proof_inputs;
use circuits::{batch_verify::universal::native::compute_circuit_id, keccak};
use clap::Parser;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use hex::ToHex;

#[derive(Parser, Debug)]
pub struct ComputeProofIDParams {
    #[arg(short = 'i', long, value_name = "app-vk-proof-and-inputs")]
    /// JSON file containing an app vk, proof and public inputs.
    app_vk_proof_and_inputs: String,
}

pub fn compute_proof_id(params: ComputeProofIDParams) {
    // Load
    let app_vk_proof_and_inputs =
        load_app_vk_proof_inputs::<Fr>(&params.app_vk_proof_and_inputs);
    let circuit_id = compute_circuit_id(&app_vk_proof_and_inputs.vk);
    let proof_id = keccak::utils::compute_proof_id(
        &circuit_id,
        &app_vk_proof_and_inputs.inputs.0,
    );
    println!("0x{}", proof_id.encode_hex::<String>());
}
