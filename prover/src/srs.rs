use crate::file_utils::{create_file_no_overwrite, panic_if_file_exists};
use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use log::debug;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::io::BufWriter;

#[derive(Parser, Debug)]
pub struct SrsParams {
    #[command(subcommand)]
    command: SrsCommand,
}

#[derive(Subcommand, Debug)]
#[command()]
enum SrsCommand {
    #[command()]
    /// Locally generate an SRS and write to a file.
    Generate(GenerateParams),
}

#[derive(Parser, Debug)]
struct GenerateParams {
    #[arg(short, long)]
    degree_bits: u32,

    #[arg(short, long)]
    srs_file: String,
}

pub fn srs(params: SrsParams) {
    debug!("srs: {params:?}");

    match params.command {
        SrsCommand::Generate(params) => generate(params),
    }
}

fn generate(params: GenerateParams) {
    debug!("generate: {params:?}");

    panic_if_file_exists(&params.srs_file);

    let srs = ParamsKZG::<Bn256>::setup(
        params.degree_bits,
        ChaCha20Rng::from_seed(Default::default()),
    );

    let f = create_file_no_overwrite(&params.srs_file);
    srs.write(&mut BufWriter::new(f))
        .expect("failed to write srs");
}
