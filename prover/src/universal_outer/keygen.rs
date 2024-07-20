use super::UniversalOuterConfig;
use crate::{
    default_values::{
        BV_SRS, KECCAK_SRS, OUTER_GATE_CONFIG, OUTER_INSTANCE_SIZE, OUTER_PK,
        OUTER_PROTOCOL, OUTER_SRS, OUTER_VK, UPA_CONFIG,
    },
    file_utils::{
        break_points_file, load_srs, panic_if_file_exists, save_break_points,
        save_gate_config, save_json_file, save_pk, save_protocol, save_vk,
    },
};
use circuits::outer::{
    universal,
    utils::{gen_outer_pk, gen_outer_vk},
    OuterGateConfig, OuterKeygenInputs,
};
use clap::Parser;
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, G1Affine},
        plonk::VerifyingKey,
        poly::kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
    },
};
use log::{info, warn};
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier_sdk::{
    halo2::aggregation::AggregationCircuit, CircuitExt, SHPLONK,
};
use std::time::Instant;

#[derive(Debug, Parser)]
pub struct KeygenParams {
    /// UPA configuration file (OuterConfiig)
    #[arg(long, value_name = "config-file", default_value = UPA_CONFIG)]
    config: String,

    /// Outer circuit SRS file
    #[arg(long, value_name = "outer-srs-file", default_value = OUTER_SRS)]
    outer_srs: String,

    /// Batch Verify circuit SRS file
    #[arg(long, value_name = "bv-srs-file", default_value = BV_SRS)]
    bv_srs: String,

    /// Keccak circuit SRS file
    #[arg(long, value_name = "keccak-srs-file", default_value = KECCAK_SRS)]
    keccak_srs: String,

    /// Output proving key file
    #[arg(short = 'p', long, value_name = "proving-key-file", default_value = OUTER_PK)]
    proving_key: String,

    /// Output verification key file
    #[arg(short = 'v', long, value_name = "verification-key-file", default_value = OUTER_VK)]
    verification_key: String,

    /// Output protocol file
    #[arg(short = 'r', long, value_name = "protocol-file", default_value = OUTER_PROTOCOL)]
    protocol: String,

    /// Output gate config file
    #[arg(short = 'g', long, value_name = "gate-config-file", default_value = OUTER_GATE_CONFIG)]
    gate_config: String,

    /// Output num instance file
    #[arg(long, value_name = "num_instance", default_value = OUTER_INSTANCE_SIZE)]
    num_instance: String,

    /// Compute only VK, protocol, and gate config. Skip PK generation.
    #[arg(long, value_name = "vk-only")]
    vk_only: bool,

    /// show circuit stats and exit.  do not write files.
    #[arg(short = 'n', long)]
    dry_run: bool,
}

/// Entry point to the `keygen` subcommand.  Runs the keygen process for the
/// `OuterCircuit`.
pub fn keygen(params: KeygenParams) {
    // Fail if any of the output paths exist
    let break_points_file = break_points_file(&params.proving_key);
    if !params.dry_run {
        panic_if_file_exists(&params.verification_key);
        panic_if_file_exists(&break_points_file);
        panic_if_file_exists(&params.protocol);
        panic_if_file_exists(&params.proving_key);
        panic_if_file_exists(&params.gate_config);
    }

    // TODO: This early-out is only done this early because the circuit
    // currently requires an srs.  Once this is fixed (to use a dummy SRS) move
    // the --dry-run early-out further down.  We should be able to save the
    // gate_config without having to load a real SRS.

    // Early-out if --dry-run was specified.
    if params.dry_run {
        return;
    }

    let config = UniversalOuterConfig::from_file(&params.config);

    let outer_params = load_srs(&params.outer_srs);

    let bv_params = load_srs(&params.bv_srs);

    let keccak_params = load_srs(&params.keccak_srs);
    let keygen_inputs =
        OuterKeygenInputs::new(&bv_params, &keccak_params, &outer_params);

    if params.vk_only {
        warn!("Skipping PK generation!");
        info!("Generating Outer VK ...");
        let now = Instant::now();
        let (vk, gate_config, break_points, num_instance) =
            gen_outer_vk::<
                SHPLONK,
                universal::UniversalOuterCircuit,
                ProverSHPLONK<Bn256>,
                VerifierSHPLONK<Bn256>,
            >(&config, &keygen_inputs)
            .unwrap_or_else(|e| panic!("failed to generate outer VK: {e}"));
        info!("Finished Outer VK gen in {:?}", now.elapsed());
        save_vk_and_auxiliary_files(
            &params,
            &vk,
            &break_points_file,
            &break_points,
            &gate_config,
            num_instance,
            &outer_params,
        );
        return;
    }

    info!("Generating Outer PK ...");
    let now = Instant::now();
    let (pk, gate_config, break_points, num_instance) =
        gen_outer_pk::<
            SHPLONK,
            universal::UniversalOuterCircuit,
            ProverSHPLONK<Bn256>,
            VerifierSHPLONK<Bn256>,
        >(&config, &keygen_inputs)
        .unwrap_or_else(|e| panic!("failed to generate outer PK: {e}"));
    info!("Finished Outer PK gen in {:?}", now.elapsed());
    save_vk_and_auxiliary_files(
        &params,
        pk.get_vk(),
        &break_points_file,
        &break_points,
        &gate_config,
        num_instance,
        &outer_params,
    );
    info!("Writing PK to file...");
    save_pk(&params.proving_key, &pk);
}

/// Save the VK, break points, gate config, protocol, and num instance to files.
fn save_vk_and_auxiliary_files(
    params: &KeygenParams,
    vk: &VerifyingKey<G1Affine>,
    break_points_file: &str,
    break_points: &MultiPhaseThreadBreakPoints,
    gate_config: &OuterGateConfig,
    num_instance: usize,
    outer_params: &ParamsKZG<Bn256>,
) {
    // Write gate config (FlexGateConfigParams)
    save_gate_config(&params.gate_config, gate_config);
    // Write num_instance (needed to generate EVM verifier)
    save_json_file(
        &params.num_instance,
        &num_instance,
        "outer circuit num instances",
    );

    info!("Writing VK to file...");
    save_vk(&params.verification_key, vk);

    save_break_points(break_points_file, break_points);

    info!("compiling VK to Protocol ...");
    let protocol =
        compile(
            outer_params,
            vk,
            Config::kzg()
                .with_num_instance(vec![num_instance])
                .with_accumulator_indices(
                    AggregationCircuit::accumulator_indices(),
                ),
        );
    save_protocol(&params.protocol, &protocol);
}
