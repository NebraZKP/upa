use crate::{
    default_values::{
        KECCAK_GATE_CONFIG, KECCAK_PK, KECCAK_PROOF, KECCAK_SRS, UPA_CONFIG,
    },
    file_utils::{
        break_points_file, instance_file, load_break_points, load_gate_config,
        load_instance, load_srs, open_file_for_read, panic_if_file_exists,
        save_instance, save_proof,
    },
    universal_batch_verifier::SECURE_MDS,
};
use circuits::{
    keccak::{
        inputs::KeccakCircuitInputs, utils::keccak_inputs_from_ubv_instances,
        KeccakCircuit, KeccakConfig, KeccakGateConfig,
    },
    SafeCircuit,
};
use clap::Parser;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::create_proof,
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK},
};
use log::info;
use rand_chacha::rand_core::OsRng;
use snark_verifier::system::halo2::transcript::halo2::ChallengeScalar;
use snark_verifier_sdk::{halo2::PoseidonTranscript, CircuitExt, NativeLoader};
use std::time::Instant;

#[derive(Parser, Debug)]
pub struct ProveParams {
    #[arg(short = 'c', long, value_name = "config-file", default_value = UPA_CONFIG)]
    /// Configuration file
    pub(crate) config: String,

    #[arg(short = 's', long, value_name = "srs-file", default_value = KECCAK_SRS)]
    pub(crate) srs: String,

    #[arg(short = 'p', long, value_name = "proving-key-file", default_value = KECCAK_PK)]
    pub(crate) proving_key: String,

    #[arg(short = 'g', long, value_name = "gate-config-file", default_value = KECCAK_GATE_CONFIG)]
    /// Circuit specs file (KeccakGateConfig)
    pub(crate) gate_config: String,

    #[arg(short = 'i', long, value_name = "ubv-inputs-file")]
    /// Public input files for each BV circuit
    pub(crate) ubv_instances: Vec<String>,

    #[arg(long, value_name = "num-proof-ids")]
    /// Number of proof ids.
    ///
    /// # Note
    ///
    /// This number must be provided if and only if the circuit outputs the
    /// submissionId, which is specified in the config.
    pub(crate) num_proof_ids: Option<u64>,

    #[arg(long, value_name = "proof-file", default_value = KECCAK_PROOF)]
    /// Output proof file
    pub(crate) proof: String,

    #[arg(long, value_name = "instance-file")]
    /// Output instance file (defaults to <proof-file>.instance if not given)
    pub(crate) instance: Option<String>,

    #[arg(short = 'n', long)]
    /// Do nothing
    pub(crate) dry_run: bool,
}

pub fn prove(params: ProveParams) {
    let instance_file = instance_file(params.instance, &params.proof);

    if !params.dry_run {
        panic_if_file_exists(&params.proof);
        panic_if_file_exists(&instance_file);
    }

    let keccak_config: KeccakConfig =
        KeccakConfig::from_upa_config_file(&params.config);

    assert!(
        keccak_config.output_submission_id ^ params.num_proof_ids.is_none(),
        "Config incompatible with inputs"
    );

    let keccak_inputs = {
        // Outer Vec indexes BV proof, inner vec is inputs to given BV proof
        let ubv_instances: Vec<Vec<Fr>> = params
            .ubv_instances
            .iter()
            .map(|input_file| load_instance(input_file.as_str()))
            .collect();
        let ubv_instances = ubv_instances.iter().map(|inputs| &inputs[..]);
        keccak_inputs_from_ubv_instances(
            ubv_instances,
            keccak_config.num_app_public_inputs as usize,
            keccak_config.inner_batch_size as usize,
        )
    };

    if params.dry_run {
        info!("dry-run.  computing instance and exiting");
        let instance = KeccakCircuit::<_, G1Affine>::compute_instance(
            &keccak_config,
            &KeccakCircuitInputs {
                inputs: keccak_inputs,
                num_proof_ids: params.num_proof_ids,
            },
        );
        save_instance(&instance_file, &instance);
        return;
    }

    let gate_config: KeccakGateConfig = load_gate_config(&params.gate_config);
    info!("reading PK ...");
    let now = Instant::now();
    let pk = {
        let mut buf = open_file_for_read(&params.proving_key);
        KeccakCircuit::<_, G1Affine>::read_proving_key(
            &keccak_config,
            &gate_config,
            &mut buf,
        )
        .unwrap_or_else(|e| panic!("error reading pk: {e}"))
    };
    info!("Finished reading Keccak PK in {:?}", now.elapsed());

    let break_points = {
        let break_points_file = break_points_file(&params.proving_key);
        load_break_points(&break_points_file)
    };
    let srs = load_srs(&params.srs);

    info!("Computing Keccak proof...");
    let now = Instant::now();
    let (keccak_proof, keccak_instance): (Vec<u8>, Vec<Fr>) = {
        let circuit = KeccakCircuit::<_, G1Affine>::prover(
            &keccak_config,
            &gate_config,
            break_points,
            &KeccakCircuitInputs {
                inputs: keccak_inputs,
                num_proof_ids: params.num_proof_ids,
            },
        );

        // TODO: better interface for instance.  Avoid copy when returning.

        let instances = circuit.instances();

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
    info!("Finished computing Keccak proof in {:?}", now.elapsed());

    // TODO: Verify the proof?

    // Write the proof

    save_proof(&params.proof, &keccak_proof);
    save_instance(&instance_file, &keccak_instance);
}
