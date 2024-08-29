use circuits::{
    batch_verify::universal::native::{
        compute_circuit_id, json::load_app_vk_proof_and_inputs_batch,
    },
    keccak::utils,
};
use clap::Parser;
use core::iter;

#[derive(Parser, Debug)]
pub struct ComputeSubmissionIdParams {
    /// JSON file containing a batch of app_vk, proof, public input triples
    /// to be verified by the BatchVerifier circuit.
    #[arg(short = 'b', long, value_name = "app-vk-proof-batch-file")]
    pub(crate) app_vk_proof_batch: String,
}

pub fn compute_submission_id(params: ComputeSubmissionIdParams) {
    let ubv_inputs =
        load_app_vk_proof_and_inputs_batch(&params.app_vk_proof_batch);
    let num_proof_ids = ubv_inputs.0.len();
    let submission_size = num_proof_ids.next_power_of_two();
    let mut proof_ids = Vec::with_capacity(submission_size);
    for input in ubv_inputs.0 {
        let circuit_id = compute_circuit_id(&input.vk);
        proof_ids.push(utils::compute_proof_id(&circuit_id, &input.inputs.0));
    }
    proof_ids
        .extend(iter::repeat([0u8; 32]).take(submission_size - num_proof_ids));
    let submission_id =
        utils::compute_submission_id(proof_ids, num_proof_ids as u64);
    println!("0x{}", hex::encode(submission_id));
}
