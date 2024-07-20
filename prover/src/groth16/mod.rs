use clap::{Parser, Subcommand};
use generate_fake_vk::{generate_fake_vk, GenerateFakeVkParams};
use generate_proofs::{generate_proofs, GenerateProofsParams};

mod generate_fake_vk;
mod generate_proofs;

#[derive(Parser, Debug)]
pub struct Groth16Params {
    #[command(subcommand)]
    command: Groth16Command,
}

#[derive(Subcommand, Debug)]
enum Groth16Command {
    #[command()]
    /// Generate a VK with trapdoor.  This can be used for proof generation.
    GenerateFakeVk(GenerateFakeVkParams),

    #[command()]
    /// Generate a VK with trapdoor.  This can be used for proof generation.
    GenerateProofs(GenerateProofsParams),
}

pub fn groth16(params: Groth16Params) {
    match params.command {
        Groth16Command::GenerateFakeVk(params) => generate_fake_vk(params),
        Groth16Command::GenerateProofs(params) => generate_proofs(params),
    }
}
