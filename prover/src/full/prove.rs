use crate::{
    default_values::{
        KECCAK_GATE_CONFIG, KECCAK_PK, KECCAK_PROOF, KECCAK_PROTOCOL,
        KECCAK_SRS, OUTER_GATE_CONFIG, OUTER_PK, OUTER_PROOF, OUTER_SRS,
        UBV_GATE_CONFIG, UBV_PK, UBV_PROOF, UBV_PROTOCOL, UBV_SRS, UPA_CONFIG,
    },
    keccak, universal_batch_verifier, universal_outer,
};
use circuits::utils::upa_config::UpaConfig;
use clap::Parser;
use log::info;

#[derive(Clone, Debug, Parser)]
pub struct ProveParams {
    /// UPA Config file
    #[arg(short = 'c', long, value_name = "config-file", default_value = UPA_CONFIG)]
    config: String,

    /// UBV circuit SRS file
    #[arg(long, value_name = "ubv-srs-file", default_value = UBV_SRS)]
    ubv_srs: String,

    /// Keccak circuit SRS file
    #[arg(long, value_name = "keccak-srs-file", default_value = KECCAK_SRS)]
    keccak_srs: String,

    /// Outer circuit SRS file
    #[arg(long, value_name = "outer-srs-file", default_value = OUTER_SRS)]
    outer_srs: String,

    /// UBV proving key file
    #[arg(long, value_name = "ubv-proving-key-file", default_value = UBV_PK)]
    ubv_proving_key: String,

    /// Keccak proving key file
    #[arg(long, value_name = "keccak-proving-key-file", default_value = KECCAK_PK)]
    keccak_proving_key: String,

    /// Outer proving key file
    #[arg(long, value_name = "outer-proving-key-file", default_value = OUTER_PK)]
    outer_proving_key: String,

    /// Circuit specs file (UBVGateConfig)
    #[arg(long, value_name = "ubv-gate-config-file", default_value = UBV_GATE_CONFIG)]
    ubv_gate_config: String,

    /// Circuit specs file (KeccakGateConfig)
    #[arg(long, value_name = "keccak-gate-config-file", default_value = KECCAK_GATE_CONFIG)]
    keccak_gate_config: String,

    /// Circuit specs file (OuterGateConfig)
    #[arg(long, value_name = "outer-gate-config-file", default_value = OUTER_GATE_CONFIG)]
    outer_gate_config: String,

    /// Universal Batch Verify circuit protocol file
    #[arg(long, value_name = "bv-circuit-protocol-file", default_value = UBV_PROTOCOL)]
    ubv_protocol: String,

    /// Keccak circuit protocol file
    #[arg(long, value_name = "keccak-protocol-file", default_value = KECCAK_PROTOCOL)]
    keccak_protocol: String,

    /// JSON files each containing a batch of app_vk, proof, public input triples
    /// to be verified by the Universal Batch Verifier circuit.
    #[arg(long, value_name = "app-vk-proof-batch-file")]
    app_vk_proof_batch: Vec<String>,

    /// Output UBV proof file
    #[arg(long, value_name = "ubv-proof-file", default_value = UBV_PROOF)]
    ubv_proof: String,

    /// Output keccak proof file
    #[arg(long, value_name = "keccak-proof-file", default_value = KECCAK_PROOF)]
    keccak_proof: String,

    /// Output UBV instance file (defaults to <ubv-proof-file>.instance if not given)
    #[arg(long, value_name = "ubv-instance-file")]
    ubv_instance: Option<String>,

    /// Output keccak instance file (defaults to <keccak-proof-file>.instance if not given)
    #[arg(long, value_name = "keccak-instance-file")]
    keccak_instance: Option<String>,

    /// Output outer proof file
    #[arg(long, value_name = "outer-proof-file", default_value = OUTER_PROOF)]
    proof: String,

    /// Output instance file (defaults to <outer-proof-file>.instance if not given)
    #[arg(long, value_name = "outer-instance-file")]
    instance: Option<String>,

    /// Output calldata file (proofs and public inputs as calldata)
    #[arg(long, value_name = "calldata")]
    calldata: Option<String>,

    /// Do nothing
    #[arg(short = 'n', long)]
    dry_run: bool,
}

fn nth_instance_file(params: &ProveParams, n: u32) -> String {
    params
        .ubv_instance
        .clone()
        .unwrap_or(params.ubv_proof.clone() + ".instance")
        + &n.to_string()
}

fn nth_proof_file(params: &ProveParams, n: u32) -> String {
    params.ubv_proof.clone() + &n.to_string()
}

fn ubv_instances_from_params(params: &ProveParams) -> Vec<String> {
    let upa_config = UpaConfig::from_file(&params.config);
    let outer_batch_size = upa_config.outer_batch_size;
    (0..outer_batch_size)
        .into_iter()
        .map(|i| nth_instance_file(params, i))
        .collect()
}

fn ubv_proofs_from_params(params: &ProveParams) -> Vec<String> {
    let upa_config = UpaConfig::from_file(&params.config);
    let outer_batch_size = upa_config.outer_batch_size;
    (0..outer_batch_size)
        .into_iter()
        .map(|i| nth_proof_file(params, i))
        .collect()
}

impl universal_batch_verifier::ProveParams {
    fn from_full_prove_params_and_batch_number(
        params: &ProveParams,
        batch_number: u32,
    ) -> Self {
        let app_vk_proof_batch =
            params.app_vk_proof_batch[batch_number as usize].clone();
        let proof = nth_proof_file(params, batch_number);
        let instance = nth_instance_file(params, batch_number);
        Self {
            config: params.config.clone(),
            srs: params.ubv_srs.clone(),
            proving_key: params.ubv_proving_key.clone(),
            gate_config: params.ubv_gate_config.clone(),
            app_vk_proof_batch,
            proof,
            instance: Some(instance),
            dry_run: params.dry_run,
        }
    }
}

impl From<&ProveParams> for keccak::ProveParams {
    fn from(value: &ProveParams) -> Self {
        let ubv_instances = ubv_instances_from_params(value);
        let value = value.clone();
        Self {
            config: value.config,
            srs: value.keccak_srs,
            proving_key: value.keccak_proving_key,
            gate_config: value.keccak_gate_config,
            ubv_instances,
            proof: value.keccak_proof,
            instance: value.keccak_instance,
            dry_run: value.dry_run,
        }
    }
}

impl From<&ProveParams> for universal_outer::ProveParams {
    fn from(value: &ProveParams) -> Self {
        let ubv_instances = ubv_instances_from_params(value);
        let ubv_proofs = ubv_proofs_from_params(value);
        let value = value.clone();
        Self {
            config: value.config,
            bv_protocol: value.ubv_protocol,
            srs: value.outer_srs,
            gate_config: value.outer_gate_config,
            proving_key: value.outer_proving_key,
            ubv_proofs,
            ubv_instances: Some(ubv_instances),
            keccak_proof: value.keccak_proof,
            keccak_instance: value.keccak_instance,
            keccak_protocol: value.keccak_protocol,
            proof: value.proof,
            instance: value.instance,
            calldata: value.calldata,
            dry_run: value.dry_run,
        }
    }
}

pub fn prove(params: ProveParams) {
    let upa_config = UpaConfig::from_file(&params.config);
    let outer_batch_size = upa_config.outer_batch_size;
    for i in 0..outer_batch_size {
        info!("Generating UBV proof for batch number {i}");
        let ubv_prove_params = universal_batch_verifier::ProveParams::from_full_prove_params_and_batch_number(&params, i);
        universal_batch_verifier::prove(ubv_prove_params);
    }
    info!("Generating keccak proof");
    keccak::prove((&params).into());
    info!("Generating outer proof");
    universal_outer::prove((&params).into());
}
