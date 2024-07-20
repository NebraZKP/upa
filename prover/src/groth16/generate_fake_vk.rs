use crate::file_utils::save_pretty_json_file;
use circuits::batch_verify::common::native::unsafe_proof_generation::{
    JsonUnsafeVerificationKey, UnsafeVerificationKey,
};
use clap::Parser;
use rand_chacha::rand_core::OsRng;

#[derive(Parser, Debug)]
pub struct GenerateFakeVkParams {
    #[arg(short = 'i', long, value_name = "num-public-inputs")]
    /// Number of public inputs
    num_public_inputs: usize,

    #[arg(short = 'v', long, value_name = "app-vk-file")]
    /// File to write the fake VK to
    app_vk_file: String,

    #[arg(short = 'c', long, value_name = "with-commitment")]
    /// Include a commitment
    with_commitment: bool,
}

pub fn generate_fake_vk(params: GenerateFakeVkParams) {
    let mut rng = OsRng;
    let unsafe_vk = UnsafeVerificationKey::sample(
        params.num_public_inputs,
        params.with_commitment,
        &mut rng,
    );
    let unsafe_vk_json: JsonUnsafeVerificationKey = (&unsafe_vk).into();
    save_pretty_json_file(
        &params.app_vk_file,
        &unsafe_vk_json,
        "unsafe verifying key",
    );
}
