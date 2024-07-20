use crate::file_utils::save_pretty_json_file;
use circuits::{
    batch_verify::{
        common::native::unsafe_proof_generation::{
            JsonUnsafeVerificationKey, UnsafeVerificationKey,
        },
        universal::native::json::JsonUniversalBatchVerifierInput,
    },
    utils::file::load_json,
};
use clap::Parser;
use rand_chacha::rand_core::OsRng;

#[derive(Parser, Debug)]
pub struct GenerateProofsParams {
    /// Number of proofs to generate
    #[arg(short = 'n', long, value_name = "num-proofs")]
    num_proofs: usize,

    /// File(s) holding fake VKs
    #[arg(short = 'v', long, value_name = "app-vk-file")]
    #[clap(required = true)]
    app_vk_file: Vec<String>,

    /// Output file into which the proof batch will be written
    #[arg(short = 'b', long, value_name = "batch-file")]
    batch_file: String,
}

pub fn generate_proofs(params: GenerateProofsParams) {
    let rng = &mut OsRng;

    let unsafe_vks = params.app_vk_file.iter().map(|vk_file| {
        let vk_json: JsonUnsafeVerificationKey = load_json(vk_file);
        (&vk_json).into()
    });

    let batch: Vec<JsonUniversalBatchVerifierInput> = unsafe_vks
        .cycle()
        .take(params.num_proofs)
        .map(|uvk: UnsafeVerificationKey| {
            let (proof, inputs) = uvk.create_proof_and_inputs(rng);
            JsonUniversalBatchVerifierInput {
                vk: uvk.vk().into(),
                proof: (&proof).into(),
                inputs: (&inputs).into(),
            }
        })
        .collect();

    // TODO: can't work out how to make `serde_json::to_writer_pretty` accept an
    // iterator, so we have to realise everything in memory before writing it.

    save_pretty_json_file(&params.batch_file, &batch, "batch file");
}
