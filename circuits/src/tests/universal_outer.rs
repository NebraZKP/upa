//! Universal Outer circuit tests
use crate::{
    batch_verify::universal::{
        native::compute_circuit_id,
        types::{
            UniversalBatchVerifierConfig, UniversalBatchVerifierInput,
            UniversalBatchVerifierInputs,
        },
        utils::gen_ubv_snark,
    },
    keccak::{
        utils::{
            compute_final_digest, compute_proof_id, digest_as_field_elements,
            gen_keccak_snark, keccak_inputs_from_ubv_instances,
        },
        KECCAK_LOOKUP_BITS,
    },
    outer::{
        universal::UniversalOuterCircuit,
        utils::{gen_outer_evm_verifier, gen_outer_pk, prove_outer},
        OuterCircuitInputs, OuterCircuitWrapper, OuterGateConfig,
        OuterKeygenInputs, UniversalOuterConfig,
    },
    CircuitConfig, CircuitWithLimbsConfig, SafeCircuit,
};
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, verify_proof, ProvingKey},
        poly::{
            commitment::{Prover, Verifier},
            kzg::{
                commitment::KZGCommitmentScheme,
                msm::DualMSM,
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::{GuardKZG, SingleStrategy},
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
            TranscriptWriterBuffer,
        },
    },
    utils::fs::gen_srs,
};
use log::info;
use rand::rngs::StdRng;
use rand_core::{OsRng, SeedableRng};
use snark_verifier::loader::evm::compile_yul;
use snark_verifier_sdk::{
    evm::{evm_verify, EvmKzgAccumulationScheme},
    halo2::aggregation::Halo2KzgAccumulationScheme,
    CircuitExt, Snark, SHPLONK,
};

/// Small inner/outer batch sizes, but high enough degrees to be EVM compatible.
const EVM_OUTER_CONFIG: UniversalOuterConfig = UniversalOuterConfig {
    max_num_app_public_inputs: TINY_MAX_NUM_PUBLIC_INPUTS,
    inner_batch_size: TINY_INNER_BATCH_SIZE,
    outer_batch_size: TINY_OUTER_BATCH_SIZE,
    bv_config: TINY_UBV_CONFIG,
    keccak_config: TINY_KECCAK_CONFIG,
    outer_config: CircuitWithLimbsConfig {
        degree_bits: 22,
        lookup_bits: 21,
        num_limbs: 3,
        limb_bits: 88,
    },
};

const TINY_INNER_BATCH_SIZE: u32 = 1;
const TINY_OUTER_BATCH_SIZE: u32 = 1;
const TINY_MAX_NUM_PUBLIC_INPUTS: u32 = 4;

const TINY_UBV_CONFIG: CircuitWithLimbsConfig = CircuitWithLimbsConfig {
    degree_bits: 21,
    lookup_bits: 20,
    limb_bits: 88,
    num_limbs: 3,
};

const TINY_KECCAK_CONFIG: CircuitConfig = CircuitConfig {
    degree_bits: 17,
    lookup_bits: KECCAK_LOOKUP_BITS,
};

const DEFAULT_INNER_BATCH_SIZE: u32 = 2;
const DEFAULT_OUTER_BATCH_SIZE: u32 = 2;
const DEFAULT_MAX_NUM_PUBLIC_INPUTS: u32 = 4;

const DEFAULT_UBV_CONFIG: CircuitWithLimbsConfig = CircuitWithLimbsConfig {
    degree_bits: 17,
    lookup_bits: 16,
    limb_bits: 88,
    num_limbs: 3,
};
const DEFAULT_KECCAK_CONFIG: CircuitConfig = CircuitConfig {
    degree_bits: 17,
    lookup_bits: KECCAK_LOOKUP_BITS,
};

const DEFAULT_OUTER_CONFIG: UniversalOuterConfig = UniversalOuterConfig {
    max_num_app_public_inputs: DEFAULT_MAX_NUM_PUBLIC_INPUTS,
    outer_batch_size: DEFAULT_OUTER_BATCH_SIZE,
    inner_batch_size: DEFAULT_INNER_BATCH_SIZE,
    bv_config: DEFAULT_UBV_CONFIG,
    keccak_config: DEFAULT_KECCAK_CONFIG,
    outer_config: CircuitWithLimbsConfig {
        degree_bits: 21,
        lookup_bits: 20,
        num_limbs: 3,
        limb_bits: 88,
    },
};

fn compute_proof_id_from_ubv_input(
    ubv_input: &UniversalBatchVerifierInput,
) -> [u8; 32] {
    let circuit_id = compute_circuit_id(&ubv_input.vk);
    compute_proof_id(&circuit_id, &ubv_input.inputs.0)
}

/// Common setup for outer circuit mock/prover/evm tests. Returns `UniversalOuterCircuitInputs`
/// and the expected final digest for randomly sampled application proofs/vk's.
fn outer_input_setup<'params, P, V>(
    outer_config: &UniversalOuterConfig,
    keygen_inputs: &'params OuterKeygenInputs,
) -> (OuterCircuitInputs<UniversalOuterCircuit>, [Fr; 2])
where
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    let ubv_config: UniversalBatchVerifierConfig = outer_config.into();

    // Generate UBV snarks
    let (ubv_snarks, proof_ids): (Vec<Snark>, Vec<[u8; 32]>) = {
        let ubv_inputs =
            UniversalBatchVerifierInputs::sample_mixed(&ubv_config, &mut OsRng);
        info!("Generating sample UBV snark for outer circuit test");
        let ubv_snark = gen_ubv_snark::<
            ProverSHPLONK<Bn256>,
            VerifierSHPLONK<Bn256>,
        >(
            &ubv_config, keygen_inputs.bv_params(), &ubv_inputs
        );
        let proof_ids =
            ubv_inputs.0.iter().map(compute_proof_id_from_ubv_input);

        // To speed up test we just repeat the same UBV snark, and the same list
        // of proof_ids.
        let snarks = vec![ubv_snark; outer_config.outer_batch_size as usize];
        let num_proof_ids =
            ubv_inputs.0.len() * outer_config.outer_batch_size as usize;
        let proof_ids: Vec<_> = proof_ids.cycle().take(num_proof_ids).collect();

        (snarks, proof_ids)
    };
    // Get the corresponding keccak snark
    let keccak_snark = {
        let inputs = keccak_inputs_from_ubv_instances(
            ubv_snarks.iter().map(|s| s.instances[0].as_slice()),
            outer_config.max_num_app_public_inputs as usize,
            outer_config.inner_batch_size as usize,
        );
        info!("Generating Keccak snark for outer circuit test");
        gen_keccak_snark::<P, V>(
            keygen_inputs.keccak_params(),
            &outer_config.into(),
            &inputs.into(),
        )
    };

    let expected_final_digest_as_field_pair =
        digest_as_field_elements(&compute_final_digest(proof_ids));

    (
        OuterCircuitInputs::<UniversalOuterCircuit>::new(
            outer_config,
            ubv_snarks,
            keccak_snark,
        ),
        expected_final_digest_as_field_pair,
    )
}

/// Checks that the outer circuit's last two public inputs match
/// the expected final digest (encoded as 2 `Fr` points).
fn check_expected_final_digest(
    instances: &[Fr],
    expected_final_digest: [Fr; 2],
) {
    let computed_final_digest: [Fr; 2] = {
        let num_inputs = instances.len();
        instances[num_inputs - 2..]
            .try_into()
            .expect("has length 2")
    };
    assert_eq!(
        computed_final_digest, expected_final_digest,
        "Public input does not match proof ids."
    );
}

/// Mock prover check of `UniversalOuterCircuit`.
/// Use of Shplonk/GWC19 is specified by the generics `AS`, `P`, `V`.
/// NOTE: `AS`, `P`, `V` are not constrained to be consistent.
fn outer_circuit_mock<'params, AS, P, V>(
    outer_config: &UniversalOuterConfig,
    keygen_inputs: &'params OuterKeygenInputs,
) where
    AS: for<'a> Halo2KzgAccumulationScheme<'a> + 'params,
    P: Prover<'params, KZGCommitmentScheme<Bn256>> + 'params,
    V: Verifier<
            'params,
            KZGCommitmentScheme<Bn256>,
            Guard = GuardKZG<'params, Bn256>,
            MSMAccumulator = DualMSM<'params, Bn256>,
        > + 'params,
{
    let _ = env_logger::builder().is_test(true).try_init();
    let (outer_inputs, expected_final_digest) =
        outer_input_setup::<P, V>(outer_config, keygen_inputs);
    // Generate outer circuit for prover
    let timer = start_timer!(|| "Outer circuit mock prover");
    // Mock Prover
    let circuit = OuterCircuitWrapper::<AS, UniversalOuterCircuit, P, V>::mock(
        outer_config,
        &outer_inputs,
    );
    let instances = circuit.instances();
    MockProver::<Fr>::run(
        outer_config.outer_config.degree_bits,
        &circuit,
        instances.clone(),
    )
    .expect("Mock prover run failure")
    .assert_satisfied();

    // Check correctness of final digest (last 2 public inputs of outer circuit)
    check_expected_final_digest(&instances[0], expected_final_digest);
    end_timer!(timer);
}

/// CMD: `cargo test --release --package upa-circuits --lib -- tests::universal_outer::outer_circuit_mock_shplonk --exact --nocapture --include-ignored`
#[ignore = "takes too long"]
#[test]
fn outer_circuit_mock_shplonk() {
    let outer_config = EVM_OUTER_CONFIG;
    let ubv_config: UniversalBatchVerifierConfig = (&outer_config).into();
    let keccak_config = TINY_KECCAK_CONFIG;

    let outer_params = gen_srs(outer_config.outer_config.degree_bits);
    let bv_params = gen_srs(ubv_config.degree_bits);
    let keccak_params = gen_srs(keccak_config.degree_bits);
    let outer_keygen_inputs =
        OuterKeygenInputs::new(&bv_params, &keccak_params, &outer_params);

    outer_circuit_mock::<SHPLONK, ProverSHPLONK<Bn256>, VerifierSHPLONK<Bn256>>(
        &outer_config,
        &outer_keygen_inputs,
    );
}

/// Computes and natively verifies an outer circuit proof. The
/// proving key is generated from a config using default data,
/// whereas the proof is generated from sample application proofs.
///
/// Use of Shplonk/GWC19 is specified by the generics `AS`, `P`, `V`.
/// NOTE: `AS`, `P`, `V` are not constrained to be consistent.
fn outer_circuit_prover<'params, AS, P, V>(
    outer_config: &UniversalOuterConfig,
    keygen_inputs: &'params OuterKeygenInputs,
) where
    AS: for<'a> Halo2KzgAccumulationScheme<'a> + 'params,
    P: Prover<'params, KZGCommitmentScheme<Bn256>> + 'params,
    V: Verifier<
            'params,
            KZGCommitmentScheme<Bn256>,
            Guard = GuardKZG<'params, Bn256>,
            MSMAccumulator = DualMSM<'params, Bn256>,
        > + 'params,
{
    let timer = start_timer!(|| "Outer PK Gen");
    let (pk, outer_gate_config, break_points, _) =
        gen_outer_pk::<AS, UniversalOuterCircuit, P, V>(
            outer_config,
            keygen_inputs,
        )
        .unwrap();
    end_timer!(timer);

    let (outer_inputs, expected_final_digest) =
        outer_input_setup::<P, V>(outer_config, keygen_inputs);

    // Note: In practice this `set_environment` call is performed by `read_proving_key`.
    outer_gate_config.set_environment();
    let circuit =
        OuterCircuitWrapper::<AS, UniversalOuterCircuit, P, V>::prover(
            outer_config,
            &outer_gate_config,
            break_points,
            &outer_inputs,
        );
    let outer_params = keygen_inputs.outer_params;
    let instances = circuit.instances();
    let proof = {
        let mut transcript =
            Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        let rng = StdRng::from_seed(Default::default());
        create_proof::<KZGCommitmentScheme<Bn256>, P, _, _, _, _>(
            outer_params,
            &pk,
            &[circuit],
            &[&[&instances[0]]],
            rng,
            &mut transcript,
        )
        .expect("proof gen. failure");
        transcript.finalize()
    };

    // Verify
    let timer = start_timer!(|| "Verifying");
    let mut transcript = Blake2bRead::<_, G1Affine, _>::init(&proof[..]);
    verify_proof::<_, V, _, _, _>(
        outer_params,
        pk.get_vk(),
        SingleStrategy::new(outer_params),
        &[&[&instances[0]]],
        &mut transcript,
    )
    .expect("verification failure");
    end_timer!(timer);
    check_expected_final_digest(&instances[0], expected_final_digest);
}

/// CMD: `cargo test --release --package upa-circuits --lib -- tests::universal_outer::outer_circuit_prover_shplonk --exact --nocapture --include-ignored`
#[ignore = "takes too long"]
#[test]
fn outer_circuit_prover_shplonk() {
    let outer_config = DEFAULT_OUTER_CONFIG;
    let ubv_config: UniversalBatchVerifierConfig = (&outer_config).into();
    let keccak_config = DEFAULT_KECCAK_CONFIG;

    let outer_params = gen_srs(outer_config.outer_config.degree_bits);
    let bv_params = gen_srs(ubv_config.degree_bits);
    let keccak_params = gen_srs(keccak_config.degree_bits);
    let outer_keygen_inputs =
        OuterKeygenInputs::new(&bv_params, &keccak_params, &outer_params);

    outer_circuit_prover::<SHPLONK, ProverSHPLONK<Bn256>, VerifierSHPLONK<Bn256>>(
        &outer_config,
        &outer_keygen_inputs,
    );
}

/// Computes an outer circuit proof and checks in EVM. The
/// proving key is generated from a config using default data,
/// whereas the proof is generated from actual sample application
/// proofs.
///
/// Use of Shplonk/GWC19 is specified by the generics `AS`, `P`, `V`.
/// NOTE: `AS`, `P`, `V` are not constrained to be consistent.
///
/// Note: Lifetime errors don't allow `outer_pk` to be computed in the
/// body of this function, hence the need to pass in `outer_pk`,
/// `outer_gate_config`, `break_points` as arguments.
fn outer_circuit_evm_check<'params, AS, P, V>(
    outer_config: &UniversalOuterConfig,
    keygen_inputs: &'params OuterKeygenInputs,
    outer_pk: &'params ProvingKey<G1Affine>,
    outer_gate_config: &OuterGateConfig,
    break_points: MultiPhaseThreadBreakPoints,
) where
    AS: EvmKzgAccumulationScheme
        + for<'a> Halo2KzgAccumulationScheme<'a>
        + 'params,
    P: Prover<'params, KZGCommitmentScheme<Bn256>> + 'params,
    V: Verifier<
            'params,
            KZGCommitmentScheme<Bn256>,
            Guard = GuardKZG<'params, Bn256>,
            MSMAccumulator = DualMSM<'params, Bn256>,
        > + 'params,
{
    let (outer_inputs, expected_final_digest) =
        outer_input_setup::<P, V>(outer_config, keygen_inputs);

    let timer = start_timer!(|| "Outer circuit proof");
    // Note: In practice this `set_environment` call is performed by `read_proving_key`.
    outer_gate_config.set_environment();
    let (proof, instances) = prove_outer::<AS, UniversalOuterCircuit, P, V>(
        outer_config,
        outer_gate_config,
        outer_pk,
        break_points,
        outer_inputs,
        keygen_inputs.outer_params,
    );
    end_timer!(timer);
    check_expected_final_digest(&instances, expected_final_digest);

    // Verify
    let num_instance = vec![instances.len()];
    let verifier_yul = gen_outer_evm_verifier::<AS>(
        keygen_inputs.outer_params,
        outer_pk.get_vk(),
        num_instance,
    );
    let verifier_byte_code = compile_yul(&verifier_yul);
    println!(
        "Verifier contract length: {} bytes",
        verifier_byte_code.len()
    );
    evm_verify(verifier_byte_code, vec![instances], proof);
}

/// CMD: `cargo test --release --package upa-circuits --lib -- tests::universal_outer::outer_circuit_evm_check_shplonk --exact --nocapture --include-ignored`
#[ignore = "takes too long"]
#[test]
fn outer_circuit_evm_check_shplonk() {
    let outer_config = EVM_OUTER_CONFIG;
    let ubv_config = TINY_UBV_CONFIG;
    let keccak_config = TINY_KECCAK_CONFIG;

    let outer_params = gen_srs(outer_config.outer_config.degree_bits);
    let ubv_params = gen_srs(ubv_config.degree_bits);
    let keccak_params = gen_srs(keccak_config.degree_bits);
    let outer_keygen_inputs =
        OuterKeygenInputs::new(&ubv_params, &keccak_params, &outer_params);

    let (pk, outer_gate_config, break_points, _) =
        gen_outer_pk::<
            SHPLONK,
            UniversalOuterCircuit,
            ProverSHPLONK<Bn256>,
            VerifierSHPLONK<Bn256>,
        >(&outer_config, &outer_keygen_inputs)
        .unwrap();

    outer_circuit_evm_check::<
        SHPLONK,
        ProverSHPLONK<Bn256>,
        VerifierSHPLONK<Bn256>,
    >(
        &outer_config,
        &outer_keygen_inputs,
        &pk,
        &outer_gate_config,
        break_points,
    );
}
