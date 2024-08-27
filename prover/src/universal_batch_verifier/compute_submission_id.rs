use circuits::{
    batch_verify::universal::native::{
        compute_circuit_id, json::load_app_vk_proof_and_inputs_batch,
    },
    keccak::utils,
};
use clap::Parser;

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
    let mut proof_ids = Vec::new();
    for input in ubv_inputs.0 {
        let circuit_id = compute_circuit_id(&input.vk);
        proof_ids.push(utils::compute_proof_id(&circuit_id, &input.inputs.0));
    }
    let submission_id = utils::compute_submission_id(proof_ids);
    println!("0x{}", hex::encode(submission_id));
}
