use crate::{
    default_values::{
        KECCAK_GATE_CONFIG, KECCAK_PK, KECCAK_PROTOCOL, KECCAK_SRS, KECCAK_VK,
        UPA_CONFIG,
    },
    file_utils::{
        break_points_file, load_srs, panic_if_file_exists, save_break_points,
        save_gate_config, save_pk, save_protocol, save_vk,
    },
};
use circuits::{
    keccak::{KeccakCircuit, KeccakConfig},
    SafeCircuit,
};
use clap::Parser;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::G1Affine,
    plonk::{keygen_pk, keygen_vk},
};
use log::info;
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier_sdk::CircuitExt;
use std::time::Instant;

#[derive(Parser, Debug)]
pub struct KeygenParams {
    #[arg(short = 'c', long, value_name = "config-file", default_value = UPA_CONFIG)]
    /// UPA configuration file
    config: String,

    #[arg(short = 's', long, value_name = "srs-file", default_value = KECCAK_SRS)]
    /// SRS file
    srs: String,

    #[arg(short = 'p', long, value_name = "proving-key-file", default_value = KECCAK_PK)]
    /// Output proving key file
    proving_key: String,

    #[arg(short = 'v', long, value_name = "verification-key-file", default_value = KECCAK_VK)]
    /// Output verification key file
    verification_key: String,

    #[arg(short = 'r', long, value_name = "protocol-file", default_value = KECCAK_PROTOCOL)]
    /// Output protocol file
    protocol: String,

    #[arg(long, value_name = "specs-file", default_value = KECCAK_GATE_CONFIG)]
    /// Output circuit specs (KeccakGateConfig) file
    gate_config: String,

    #[arg(short = 'n', long)]
    /// Compute and write the circuit configs and exit.
    dry_run: bool,
}

pub fn keygen(params: KeygenParams) {
    let keccak_config: KeccakConfig =
        KeccakConfig::from_upa_config_file(&params.config);

    // Fail if any of the output paths exist
    let break_points_file = break_points_file(&params.proving_key);
    if !params.dry_run {
        panic_if_file_exists(&params.verification_key);
        panic_if_file_exists(&break_points_file);
        panic_if_file_exists(&params.protocol);
        panic_if_file_exists(&params.proving_key);
        panic_if_file_exists(&params.gate_config);
    }

    let circuit = KeccakCircuit::<_, G1Affine>::keygen(&keccak_config, &());
    let gate_config = circuit.gate_config();

    save_gate_config(&params.gate_config, &gate_config);

    // Early-out if --dry-run was specified
    if params.dry_run {
        info!("dry-run.  not attempting to create proving key");
        return;
    }

    let srs = load_srs(&params.srs);

    info!("Generating Keccak VK ...");
    let now = Instant::now();
    let vk = keygen_vk(&srs, &circuit)
        .unwrap_or_else(|e| panic!("VK generation failed: {e}"));
    info!("Finished generating keccak VK in {:?}", now.elapsed());

    save_vk(&params.verification_key, &vk);

    {
        let break_points = circuit.break_points();
        save_break_points(&break_points_file, &break_points);
    }

    info!("compiling VK to Protocol ...");
    let protocol = compile(
        &srs,
        &vk,
        Config::kzg()
            .with_num_instance(circuit.num_instance())
            .with_accumulator_indices(
                KeccakCircuit::<_, G1Affine>::accumulator_indices(),
            ),
    );

    save_protocol(&params.protocol, &protocol);

    info!("Generating Keccak PK ...");
    let now = Instant::now();
    let pk = keygen_pk(&srs, vk, &circuit)
        .unwrap_or_else(|e| panic!("PK generation failed: {e}"));
    info!("Finished generating keccak PK in {:?}", now.elapsed());
    save_pk(&params.proving_key, &pk);
}
