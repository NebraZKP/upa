use crate::{
    default_values::{UBV_GATE_CONFIG, UBV_PK, UBV_SRS, UPA_CONFIG},
    file_utils::{
        break_points_file, instance_file, load_break_points, load_gate_config,
        load_srs, open_file_for_read, panic_if_file_exists, save_instance,
        save_proof,
    },
    universal_batch_verifier::SECURE_MDS,
};
use circuits::{
    batch_verify::universal::{
        native::json::load_app_vk_proof_and_inputs_batch,
        types::UniversalBatchVerifierConfig, UniversalBatchVerifyCircuit,
    },
    SafeCircuit,
};
use clap::Parser;
use halo2_base::{
    gates::builder::FlexGateConfigParams,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::create_proof,
        poly::kzg::{
            commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK,
        },
    },
};
use log::info;
use rand_chacha::rand_core::OsRng;
use snark_verifier::system::halo2::transcript::halo2::ChallengeScalar;
use snark_verifier_sdk::{halo2::PoseidonTranscript, CircuitExt, NativeLoader};
use std::time::Instant;

#[derive(Parser, Debug)]
pub struct ProveParams {
    #[arg(short = 'c', long, value_name = "config-file", default_value = UPA_CONFIG)]
    /// UPA configuration file
    pub(crate) config: String,

    #[arg(short = 's', long, value_name = "srs-file", default_value = UBV_SRS)]
    pub(crate) srs: String,

    #[arg(short = 'p', long, value_name = "proving-key-file", default_value = UBV_PK)]
    pub(crate) proving_key: String,

    #[arg(short = 'g', long, value_name = "gate-config-file", default_value = UBV_GATE_CONFIG)]
    /// Gate configuration file
    pub(crate) gate_config: String,

    #[arg(short = 'b', long, value_name = "app-vk-proof-batch-file")]
    /// JSON file containing a batch of app_vk, proof, public input triples
    /// to be verified by the BatchVerifier circuit.
    pub(crate) app_vk_proof_batch: String,

    #[arg(long, value_name = "proof-file")]
    /// Output proof file
    pub(crate) proof: String,

    #[arg(long, value_name = "instance-file")]
    /// Output instance file (defaults to <proof-file>.instance if not given)
    pub(crate) instance: Option<String>,

    #[arg(short = 'n', long)]
    /// Load the circuit configs and exit.
    pub(crate) dry_run: bool,
}

/// Entry point to the `prove` subcommand. Runs the prove process for the
/// UniversalBatchVerifyCircuit.
pub fn prove(params: ProveParams) {
    let instance_file = instance_file(params.instance, &params.proof);

    if !params.dry_run {
        panic_if_file_exists(&params.proof);
        panic_if_file_exists(&instance_file);
    }

    let bv_config: UniversalBatchVerifierConfig =
        UniversalBatchVerifierConfig::from_upa_config_file(&params.config);

    if params.dry_run {
        prove_dry_run(&bv_config, &params.app_vk_proof_batch, &instance_file);
        return;
    }

    let gate_config: FlexGateConfigParams =
        load_gate_config(&params.gate_config);

    info!("reading BV PK ...");
    let now = Instant::now();
    let pk = {
        let mut buf = open_file_for_read(&params.proving_key);
        UniversalBatchVerifyCircuit::<_, G1Affine>::read_proving_key(
            &bv_config,
            &gate_config,
            &mut buf,
        )
        .unwrap_or_else(|e| panic!("error reading pk: {e}"))
    };
    info!("Finished reading BV PK in {:?}", now.elapsed());

    let break_points = {
        let break_points_file = break_points_file(&params.proving_key);
        load_break_points(&break_points_file)
    };

    // TODO: load this stuff first, and verify the batch?

    info!("Loading app VK, proofs and inputs ...");
    let ubv_inputs =
        load_app_vk_proof_and_inputs_batch(&params.app_vk_proof_batch);

    // TODO: native verification

    let srs = load_srs(&params.srs);
    info!("Computing BV proof...");
    let now = Instant::now();
    let (batch_proof, batch_proof_instance): (Vec<u8>, Vec<Fr>) = {
        let circuit = UniversalBatchVerifyCircuit::<_, G1Affine>::prover(
            &bv_config,
            &gate_config,
            break_points,
            &ubv_inputs,
        );

        // TODO: better interface for instance.  Avoid copy when returning.

        let instances = circuit.instances();

        // TODO: sanity check these instance values against the app_vk and the
        // public inputs.

        // TODO: Better Rng than OsRng?

        let mut transcript =
            PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            ChallengeScalar<G1Affine>,
            _,
            _,
            _,
        >(
            &srs,
            &pk,
            &[circuit],
            &[&[&instances[0]]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();

        (proof, instances[0].clone())
    };
    info!("Finished computing BV proof in {:?}", now.elapsed());

    // TODO: Verify the proof?

    save_proof(&params.proof, &batch_proof);
    save_instance(&instance_file, &batch_proof_instance);
}

/// In dry-run mode, we just compute and write out the instances.
fn prove_dry_run(
    bv_config: &UniversalBatchVerifierConfig,
    app_vk_proof_inputs_file: &str,
    instance_file: &str,
) {
    info!("dry-run.  generating instance only.");

    info!("Loading app VK, proofs and inputs ...");
    let ubv_inputs =
        load_app_vk_proof_and_inputs_batch(app_vk_proof_inputs_file);

    let bv_instance = UniversalBatchVerifyCircuit::<Fr>::compute_instance(
        bv_config,
        &ubv_inputs,
    );
    save_instance(instance_file, &bv_instance);
}
