use circuits::batch_verify::{common::native::json::load_vk, universal};
use clap::Parser;

#[derive(Parser, Debug)]
pub struct ComputeCircuitIDParams {
    #[arg(long, value_name = "app-vk-file")]
    /// Groth16 verification key of the application.
    app_vk: String,
}

pub fn compute_circuit_id(params: ComputeCircuitIDParams) {
    let vk = load_vk(&params.app_vk);
    let circuit_id = universal::native::compute_circuit_id(&vk);
    println!("0x{}", hex::encode(circuit_id));
}
