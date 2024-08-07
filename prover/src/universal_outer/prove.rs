use super::{
    UniversalOuterCircuit, UniversalOuterCircuitInputs,
    UniversalOuterInstanceInputs,
};
use crate::{
    default_values::{
        KECCAK_PROTOCOL, OUTER_GATE_CONFIG, OUTER_PK, OUTER_SRS, UBV_PROTOCOL,
        UPA_CONFIG,
    },
    file_utils::{
        break_points_file, calldata_file, instance_file, load_break_points,
        load_instance, load_proof, load_protocol, load_srs, open_file_for_read,
        panic_if_file_exists, save_calldata, save_instance, save_proof,
    },
};
use circuits::{
    self,
    outer::{universal, utils::prove_outer, OuterGateConfig},
    utils::{file::load_json, upa_config::UpaConfig},
    SafeCircuit,
};
use clap::Parser;
use core::iter;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK},
};
use log::info;
use snark_verifier_sdk::{evm::encode_calldata, Snark, SHPLONK};
use std::time::Instant;

#[derive(Debug, Parser)]
pub struct ProveParams {
    /// UPA configuration file
    #[arg(long, value_name = "config-file", default_value = UPA_CONFIG)]
    pub(crate) config: String,

    /// Batch Verify circuit protocol file
    #[arg(long, value_name = "bv-circuit-protocol-file", default_value = UBV_PROTOCOL)]
    pub(crate) bv_protocol: String,

    /// Outer circuit SRS file
    #[arg(short = 's', long, value_name = "outer-srs-file", default_value = OUTER_SRS)]
    pub(crate) srs: String,

    /// Outer circuit gate config file
    #[arg(short = 'g', long, value_name = "gate-config-file", default_value = OUTER_GATE_CONFIG)]
    pub(crate) gate_config: String,

    /// Outer circuit proving key file
    #[arg(short = 'p', long, value_name = "proving-key-file", default_value = OUTER_PK)]
    pub(crate) proving_key: String,

    /// Batch Verify proof files
    #[arg(long, value_name = "bv-proof-files")]
    pub(crate) ubv_proofs: Vec<String>,

    /// Batch Verify instances files
    #[arg(long, value_name = "bv-instance-files")]
    pub(crate) ubv_instances: Option<Vec<String>>,

    /// Keccak proof file
    #[arg(long, value_name = "keccak-proof-file")]
    pub(crate) keccak_proof: String,

    /// Keccak input file
    #[arg(long, value_name = "keccak-instance-file")]
    pub(crate) keccak_instance: Option<String>,

    /// Keccak circuit protocol file
    #[arg(long, value_name = "keccak-protocol-file", default_value = KECCAK_PROTOCOL)]
    pub(crate) keccak_protocol: String,

    /// Output proof file
    #[arg(long, value_name = "outer-proof-file")]
    pub(crate) proof: String,

    /// Output public inputs file
    #[arg(long, value_name = "outer-instance-file")]
    pub(crate) instance: Option<String>,

    /// Output calldata file (proofs and public inputs as calldata)
    #[arg(long, value_name = "calldata")]
    pub(crate) calldata: Option<String>,

    /// show circuit stats and exit.  do not write files.
    #[arg(short = 'n', long)]
    pub(crate) dry_run: bool,
}

/// Compute EVM proof. Write proof, inputs, and calldata
/// to separate files. Calldata consists of the proofs and
/// inputs serialized for the verifier contract.
pub fn prove(params: ProveParams) {
    let outer_instance_file = instance_file(params.instance, &params.proof);
    let calldata_file = calldata_file(params.calldata, &params.proof);

    if !params.dry_run {
        panic_if_file_exists(&params.proof);
        panic_if_file_exists(&outer_instance_file);
        panic_if_file_exists(&calldata_file);
    }

    // Parse the (optional) instance files list
    let bv_instance_files: Vec<String> =
        parse_optional_instance_files(params.ubv_instances, &params.ubv_proofs);
    let keccak_instance_file =
        instance_file(params.keccak_instance, &params.keccak_proof);

    // Instances
    let (bv_instances, keccak_instance) =
        load_inner_instances(&bv_instance_files, &keccak_instance_file);

    if params.dry_run {
        prove_dry_run(
            &params.config,
            bv_instances,
            keccak_instance,
            &calldata_file,
        );
        return;
    }

    let config = UpaConfig::from_file(&params.config);
    let outer_params = load_srs(&params.srs);
    let gate_config: OuterGateConfig = load_json(&params.gate_config);
    info!("reading Outer PK ...");
    let now = Instant::now();
    let pk = {
        let mut buf = open_file_for_read(&params.proving_key);
        UniversalOuterCircuit::read_proving_key(&config, &gate_config, &mut buf)
            .unwrap_or_else(|e| panic!("error reading pk: {e}"))
    };
    info!("Finished reading Outer PK in {:?}", now.elapsed());
    let break_points = {
        let break_points_file = break_points_file(&params.proving_key);
        load_break_points(&break_points_file)
    };

    // Outer inputs
    let outer_inputs = {
        let (bv_proofs, keccak_proof) =
            load_inner_proofs(&params.ubv_proofs, &params.keccak_proof);

        let bv_protocol = load_protocol(&params.bv_protocol);
        let bv_snarks: Vec<Snark> = bv_proofs
            .into_iter()
            .zip(bv_instances.into_iter())
            .map(|(p, i)| Snark::new(bv_protocol.clone(), vec![i], p))
            .collect();
        let keccak_protocol = load_protocol(&params.keccak_protocol);
        let keccak_snark =
            Snark::new(keccak_protocol, vec![keccak_instance], keccak_proof);

        UniversalOuterCircuitInputs::new(&config, bv_snarks, keccak_snark)
    };

    info!("Computing Outer proof...");
    let now = Instant::now();
    let (proof, instances) = prove_outer::<
        SHPLONK,
        universal::UniversalOuterCircuit,
        ProverSHPLONK<Bn256>,
        VerifierSHPLONK<Bn256>,
    >(
        &config,
        &gate_config,
        &pk,
        break_points,
        outer_inputs,
        &outer_params,
    );
    info!("Finished computing Outer proof in {:?}", now.elapsed());
    let calldata = encode_calldata(&[instances.clone()], &proof);
    info!("Calldata size: {:?} bytes", calldata.len());

    save_proof(&params.proof, &proof);
    save_instance(&outer_instance_file, &instances);
    save_calldata(&calldata_file, &calldata);
}

/// Assembles `OuterCircuitInputs` from provided files.
pub(crate) fn load_inner_instances(
    bv_instance_files: &[String],
    keccak_instance_file: &str,
) -> (Vec<Vec<Fr>>, Vec<Fr>) {
    let mut bv_instances = Vec::<Vec<Fr>>::new();

    // Read each BV instance from file
    for bv_instance_file in bv_instance_files.iter() {
        bv_instances.push(load_instance(bv_instance_file));
    }
    // Read Keccak instance from file
    let keccak_instances = load_instance(keccak_instance_file);

    (bv_instances, keccak_instances)
}

pub(crate) fn load_inner_proofs(
    bv_proof_files: &Vec<String>,
    keccak_proof_file: &str,
) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut bv_proofs = Vec::<Vec<u8>>::new();

    // Read each BV proof from file
    for bv_proof_file in bv_proof_files {
        bv_proofs.push(load_proof(bv_proof_file));
    }
    // Read Keccak proof from file
    let keccak_proof = load_proof(keccak_proof_file);

    (bv_proofs, keccak_proof)
}

/// Parses the `Option<Vec<String>>` of optionally provided
/// BV instance files.
pub(crate) fn parse_optional_instance_files(
    optional_instance_files: Option<Vec<String>>,
    bv_proof_files: &[String],
) -> Vec<String> {
    match optional_instance_files {
        Some(bv_instances) => {
            assert_eq!(
                bv_instances.len(),
                bv_proof_files.len(),
                "if present, --bv-instances must be given for all proofs"
            );
            bv_instances
        }
        None => bv_proof_files
            .iter()
            .map(|pf_file| instance_file(None, pf_file))
            .collect(),
    }
}

pub(crate) fn do_prove_dry_run(
    config: &UpaConfig,
    inputs: &UniversalOuterInstanceInputs,
) -> (Vec<Fr>, Vec<u8>) {
    let final_digest_field_elements =
        UniversalOuterCircuit::compute_instance(config, inputs);
    assert!(final_digest_field_elements.len() == 2);

    // OuterCircuit::compute_instance returns just the final_digest, without the
    // leading KZG accumulator, hence we must fill this in, in front of the
    // final digest. It consists of 2 arbitrary group points, represented as 12
    // scalar field elements (2 group points x 2 base field elements each x 3
    // limbs each).
    //
    // As long as the elements are non-zero the dummy EVM verifier will accept
    // them.
    let instance: Vec<Fr> = iter::once(Fr::from(1))
        .cycle()
        .take(4 * config.outer_config.num_limbs)
        .chain(final_digest_field_elements)
        .collect();
    let calldata = encode_calldata(&[instance.clone()], &[]);

    (instance, calldata)
}

/// Compute the final digest from the bv_instance files, and create dummy call
/// data with the final digest in the correct place.
fn prove_dry_run(
    config_file: &str,
    bv_instances: Vec<Vec<Fr>>,
    keccak_instance: Vec<Fr>,
    outer_calldata_file: &str,
) {
    info!("dry-run.  generating calldata only");
    let config = UpaConfig::from_file(config_file);
    let instance_inputs = UniversalOuterInstanceInputs::new(
        &config,
        bv_instances,
        keccak_instance,
    );
    let (_instance, calldata) = do_prove_dry_run(&config, &instance_inputs);
    save_calldata(outer_calldata_file, &calldata);
}
