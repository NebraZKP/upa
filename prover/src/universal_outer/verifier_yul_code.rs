use super::UniversalOuterCircuit;
use crate::{
    default_values::{
        OUTER_GATE_CONFIG, OUTER_INSTANCE_SIZE, OUTER_SRS, OUTER_VERIFIER_YUL,
        OUTER_VK,
    },
    file_utils::{load_gate_config, load_srs, panic_if_file_exists, save_yul},
};
use circuits::{
    outer::{utils::gen_outer_evm_verifier, OuterGateConfig},
    utils::file::{load_json, open_file_for_read},
    SafeCircuit,
};
use clap::Parser;
use log::info;
use snark_verifier_sdk::SHPLONK;

#[derive(Debug, Parser)]
pub struct GenerateVerifierParams {
    /// Outer circuit SRS file
    #[arg(long, value_name = "outer-srs-file", default_value = OUTER_SRS)]
    outer_srs: String,

    /// Outer circuit gate config file
    #[arg(short = 'g', long, value_name = "gate-config-file", default_value = OUTER_GATE_CONFIG)]
    gate_config: String,

    /// Outer circuit verification key file
    #[arg(short = 'v', long, value_name = "verification-key-file", default_value = OUTER_VK)]
    verification_key: String,

    /// Outer circuit num instance file
    #[arg(long, value_name = "num_instance", default_value = OUTER_INSTANCE_SIZE)]
    num_instance: String,

    /// Output yul code file
    #[arg(short = 'r', long, value_name = "yul-file", default_value = OUTER_VERIFIER_YUL)]
    yul: String,
}

pub fn generate_evm_verifier(params: GenerateVerifierParams) {
    panic_if_file_exists(&params.yul);

    let outer_params = load_srs(&params.outer_srs);

    info!("Loading vk ...");
    let gate_config: OuterGateConfig = load_gate_config(&params.gate_config);
    let vk = {
        let mut buf = open_file_for_read(&params.verification_key);
        UniversalOuterCircuit::read_verifying_key(&gate_config, &mut buf)
            .unwrap_or_else(|e| panic!("error reading vk: {e}"))
    };

    let num_instance: usize = load_json(&params.num_instance);

    let yul_code = gen_outer_evm_verifier::<SHPLONK>(
        &outer_params,
        &vk,
        vec![num_instance],
    );
    save_yul(&params.yul, &yul_code);
}
