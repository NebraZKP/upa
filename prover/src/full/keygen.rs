use crate::{
    default_values::{
        KECCAK_GATE_CONFIG, KECCAK_PK, KECCAK_PROTOCOL, KECCAK_SRS, KECCAK_VK,
        OUTER_GATE_CONFIG, OUTER_INSTANCE_SIZE, OUTER_PK, OUTER_PROTOCOL,
        OUTER_SRS, OUTER_VK, UBV_GATE_CONFIG, UBV_PK, UBV_PROTOCOL, UBV_SRS,
        UBV_VK, UPA_CONFIG,
    },
    keccak, universal_batch_verifier, universal_outer,
};
use clap::Parser;

#[derive(Clone, Debug, Parser)]
pub struct KeygenParams {
    /// UPA configuration file
    #[arg(short = 'c', long, value_name = "config-file", default_value = UPA_CONFIG)]
    config: String,

    /// UBV SRS file
    #[arg(long, value_name = "ubv-srs-file", default_value = UBV_SRS)]
    ubv_srs: String,

    /// Keccak SRS file
    #[arg(short = 's', long, value_name = "keccak-srs-file", default_value = KECCAK_SRS)]
    keccak_srs: String,

    /// Outer SRS file
    #[arg(long, value_name = "outer-srs-file", default_value = OUTER_SRS)]
    outer_srs: String,

    /// Output UBV proving key file
    #[arg(long, value_name = "ubv-proving-key-file", default_value = UBV_PK)]
    ubv_proving_key: String,

    /// Output Keccak proving key file
    #[arg(long, value_name = "keccak-proving-key-file", default_value = KECCAK_PK)]
    keccak_proving_key: String,

    /// Output Outer proving key file
    #[arg(long, value_name = "outer-proving-key-file", default_value = OUTER_PK)]
    outer_proving_key: String,

    /// Output verification key file
    #[arg(long, value_name = "ubv-verification-key-file", default_value = UBV_VK)]
    ubv_verification_key: String,

    /// Output verification key file
    #[arg(long, value_name = "keccak-verification-key-file", default_value = KECCAK_VK)]
    keccak_verification_key: String,

    /// Output verification key file
    #[arg(long, value_name = "outer-verification-key-file", default_value = OUTER_VK)]
    outer_verification_key: String,

    /// Output UBV protocol file
    #[arg(long, value_name = "ubv-protocol-file", default_value = UBV_PROTOCOL)]
    ubv_protocol: String,

    /// Output Keccak protocol file
    #[arg(long, value_name = "keccak-protocol-file", default_value = KECCAK_PROTOCOL)]
    keccak_protocol: String,

    /// Output Outer protocol file
    #[arg(long, value_name = "outer-protocol-file", default_value = OUTER_PROTOCOL)]
    outer_protocol: String,

    /// Output circuit specs (UBVGateConfig) file
    #[arg(long, value_name = "ubv-specs-file", default_value = UBV_GATE_CONFIG)]
    ubv_gate_config: String,

    /// Output circuit specs (KeccakGateConfig) file
    #[arg(long, value_name = "keccak-specs-file", default_value = KECCAK_GATE_CONFIG)]
    keccak_gate_config: String,

    /// Output circuit specs (OuterGateConfig) file
    #[arg(long, value_name = "outer-specs-file", default_value = OUTER_GATE_CONFIG)]
    outer_gate_config: String,

    /// Output num instance file
    #[arg(long, value_name = "num_instance", default_value = OUTER_INSTANCE_SIZE)]
    num_instance: String,

    /// Compute only VK, protocol, and gate config. Skip PK generation for outer circuit.
    #[arg(long, value_name = "vk-only")]
    vk_only: bool,

    /// Compute and write the circuit configs and exit.
    #[arg(short = 'n', long)]
    dry_run: bool,
}

impl From<&KeygenParams> for universal_batch_verifier::KeygenParams {
    fn from(value: &KeygenParams) -> Self {
        let value = value.clone();
        Self {
            config: value.config,
            proving_key: value.ubv_proving_key,
            srs: value.keccak_srs,
            verification_key: value.keccak_verification_key,
            protocol: value.ubv_protocol,
            gate_config: value.ubv_gate_config,
            dry_run: value.dry_run,
        }
    }
}

impl From<&KeygenParams> for keccak::KeygenParams {
    fn from(value: &KeygenParams) -> Self {
        let value = value.clone();
        Self {
            config: value.config,
            proving_key: value.keccak_proving_key,
            srs: value.keccak_srs,
            verification_key: value.keccak_verification_key,
            protocol: value.keccak_protocol,
            gate_config: value.keccak_gate_config,
            dry_run: value.dry_run,
        }
    }
}

impl From<&KeygenParams> for universal_outer::KeygenParams {
    fn from(value: &KeygenParams) -> Self {
        let value = value.clone();
        Self {
            config: value.config,
            outer_srs: value.outer_srs,
            bv_srs: value.ubv_srs,
            keccak_srs: value.keccak_srs,
            proving_key: value.outer_proving_key,
            verification_key: value.outer_verification_key,
            protocol: value.outer_protocol,
            gate_config: value.outer_gate_config,
            num_instance: value.num_instance,
            vk_only: value.vk_only,
            dry_run: value.dry_run,
        }
    }
}

pub fn keygen(params: KeygenParams) {
    universal_batch_verifier::keygen((&params).into());
    keccak::keygen((&params).into());
    universal_outer::keygen((&params).into());
}
