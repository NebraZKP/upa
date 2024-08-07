use crate::{
    default_values::{
        UBV_GATE_CONFIG, UBV_PK, UBV_PROTOCOL, UBV_SRS, UBV_VK, UPA_CONFIG,
    },
    file_utils::{
        break_points_file, load_srs, panic_if_file_exists, save_break_points,
        save_gate_config, save_pk, save_protocol, save_vk,
    },
};
use circuits::{
    batch_verify::universal::{
        types::UniversalBatchVerifierConfig, UniversalBatchVerifyCircuit,
    },
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

#[derive(Debug, Parser)]
pub struct KeygenParams {
    /// UPA configuration file
    #[arg(short = 'c', long, value_name = "config-file", default_value = UPA_CONFIG)]
    pub(crate) config: String,

    /// SRS file
    #[arg(short = 's', long, value_name = "srs-file", default_value = UBV_SRS)]
    pub(crate) srs: String,

    /// Output proving key file
    #[arg(short = 'p', long, value_name = "proving-key-file", default_value = UBV_PK)]
    pub(crate) proving_key: String,

    /// Output verification key file
    #[arg(short = 'v', long, value_name = "verification-key-file", default_value = UBV_VK)]
    pub(crate) verification_key: String,

    /// Output protocol file
    #[arg(short = 'r', long, value_name = "protocol-file", default_value = UBV_PROTOCOL)]
    pub(crate) protocol: String,

    /// Output circuit specs file
    #[arg(short = 'g', long, value_name = "gate-config-file", default_value = UBV_GATE_CONFIG)]
    pub(crate) gate_config: String,

    /// show circuit stats and exit.  do not write files.
    #[arg(short = 'n', long)]
    pub(crate) dry_run: bool,
}

/// Entry point to the `keygen` subcommand.  Runs the keygen process for the
/// UniversalBatchVerifyCircuit.
pub fn keygen(params: KeygenParams) {
    let ubv_config: UniversalBatchVerifierConfig =
        UniversalBatchVerifierConfig::from_upa_config_file(&params.config);

    // Fail if any of the output paths exist
    let break_points_file = break_points_file(&params.proving_key);
    if !params.dry_run {
        panic_if_file_exists(&params.verification_key);
        panic_if_file_exists(&break_points_file);
        panic_if_file_exists(&params.protocol);
        panic_if_file_exists(&params.proving_key);
        panic_if_file_exists(&params.gate_config);
    }

    let circuit =
        UniversalBatchVerifyCircuit::<_, G1Affine>::keygen(&ubv_config, &());
    let gate_config = circuit.gate_config();

    // Write circuit specs (FlexGateConfigParams)
    save_gate_config(&params.gate_config, &gate_config);

    // Early-out if --dry-run was specified
    if params.dry_run {
        return;
    }

    let srs = load_srs(&params.srs);
    info!("Generating UBV VK ...");
    let now = Instant::now();
    let vk = keygen_vk(&srs, &circuit)
        .unwrap_or_else(|e| panic!("VK generation failed: {e}"));
    info!("Finished generating UBV VK in {:?}", now.elapsed());

    save_vk(&params.verification_key, &vk);

    let break_points = circuit.break_points();
    save_break_points(&break_points_file, &break_points);

    info!("compiling VK to Protocol ...");
    let protocol = compile(
        &srs,
        &vk,
        Config::kzg()
            .with_num_instance(circuit.num_instance())
            .with_accumulator_indices(
                UniversalBatchVerifyCircuit::<_, G1Affine>::accumulator_indices(
                ),
            ),
    );
    save_protocol(&params.protocol, &protocol);

    info!("generating UBV PK ...");
    let now = Instant::now();
    let pk = keygen_pk(&srs, vk, &circuit)
        .unwrap_or_else(|e| panic!("PK generation failed: {e}"));
    info!("Finished generating UBV PK in {:?}", now.elapsed());
    save_pk(&params.proving_key, &pk);
}
