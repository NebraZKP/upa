use crate::{
    default_values::{
        OUTER_GATE_CONFIG, OUTER_INSTANCE_SIZE, OUTER_SRS, OUTER_VERIFIER_YUL,
        OUTER_VK,
    },
    universal_outer::{self, generate_evm_verifier, GenerateVerifierParams},
};
use clap::Parser;

#[derive(Clone, Debug, Parser)]
pub struct VerifyParams {
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

    /// Outer circuit proof file
    #[arg(short = 'p', long, value_name = "outer-proof-file")]
    proof: String,

    /// Outer circuit public inputs file
    #[arg(short = 'i', long, value_name = "outer-instance-file")]
    instance: Option<String>,

    /// Outer circuit calldata file
    #[arg(short = 'c', long, value_name = "outer-calldata-file")]
    calldata: Option<String>,

    /// Output yul code file
    #[arg(short = 'r', long, value_name = "yul-file", default_value = OUTER_VERIFIER_YUL)]
    yul: String,

    /// Load the circuit configs and exit.
    #[arg(short = 'n', long)]
    dry_run: bool,
}

impl From<&VerifyParams> for GenerateVerifierParams {
    fn from(value: &VerifyParams) -> Self {
        let value = value.clone();
        Self {
            outer_srs: value.outer_srs,
            gate_config: value.gate_config,
            verification_key: value.verification_key,
            num_instance: value.num_instance,
            yul: value.yul,
        }
    }
}

impl From<&VerifyParams> for universal_outer::VerifyParams {
    fn from(value: &VerifyParams) -> Self {
        let value = value.clone();
        Self {
            verifier_yul: value.yul,
            proof: value.proof,
            instance: value.instance,
            calldata: value.calldata,
            dry_run: value.dry_run,
        }
    }
}

pub fn verify(params: VerifyParams) {
    generate_evm_verifier((&params).into());
    universal_outer::verify((&params).into());
}
