//! Universal Batch Verifier Testing Suite

use crate::{
    batch_verify::{
        common::{
            native::unsafe_proof_generation::UnsafeVerificationKey,
            types::PublicInputs,
        },
        universal::{
            types::{
                UniversalBatchVerifierConfig, UniversalBatchVerifierInput,
                UniversalBatchVerifierInputs,
            },
            UniversalBatchVerifyCircuit,
        },
    },
    tests::utils::check_instance,
    SafeCircuit,
};
use ark_std::{end_timer, start_timer};
use halo2_base::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
            TranscriptWriterBuffer,
        },
    },
    utils::fs::gen_srs,
};
use rand::Rng;
use rand_core::{CryptoRng, OsRng, RngCore};
use snark_verifier_sdk::CircuitExt;

pub mod component;
pub mod ecc;
pub mod native;

/// Limb bits for non-native arithmetic
const LIMB_BITS: usize = 88;

/// Number of limbs for non-native arithmetic
const NUM_LIMBS: usize = 3;

/// Maximum batch size for tests
const MAX_BATCH_SIZE: u32 = 2;

/// Maximum number of public inputs for tests
const MAX_NUM_PUBLIC_INPUTS: u32 = 4;

/// Samples a test configuration with `degree_bits`.
fn sample_test_config<R>(
    degree_bits: u32,
    rng: &mut R,
) -> UniversalBatchVerifierConfig
where
    R: CryptoRng + RngCore + ?Sized,
{
    let inner_batch_size = rng.gen_range(1..=MAX_BATCH_SIZE);
    let max_num_public_inputs = rng.gen_range(2..=MAX_NUM_PUBLIC_INPUTS);
    UniversalBatchVerifierConfig {
        degree_bits,
        lookup_bits: (degree_bits - 1) as usize,
        limb_bits: LIMB_BITS,
        num_limbs: NUM_LIMBS,
        inner_batch_size,
        max_num_public_inputs,
    }
}

impl UniversalBatchVerifierInput<Fr> {
    /// Samples a valid [`UniversalBatchVerifierInput`] for `config`, whose inputs
    /// are all zero.
    pub fn sample_all_zero<R>(
        config: &UniversalBatchVerifierConfig,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + ?Sized,
    {
        let num_public_inputs = config.max_num_public_inputs as usize;
        let length = rng.gen_range(1..=num_public_inputs);
        let unsafe_vk = UnsafeVerificationKey::sample(length, false, rng);
        let inputs =
            PublicInputs((0..length).into_iter().map(|_| Fr::zero()).collect());
        let proof = unsafe_vk.create_proof(&inputs.0, rng);

        assert!(length > 0);
        assert!(length + 1 == unsafe_vk.vk().s.len());
        assert!(length == inputs.0.len());

        Self {
            vk: unsafe_vk.into_vk(),
            proof,
            inputs,
        }
    }
}

impl UniversalBatchVerifierInputs<Fr> {
    /// Samples [`UniversalBatchVerifierInputs`] compatible with `config`.
    pub fn sample_all_zero<R>(
        config: &UniversalBatchVerifierConfig,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(
            (0..config.inner_batch_size)
                .into_iter()
                .map(|_| {
                    UniversalBatchVerifierInput::sample_all_zero(config, rng)
                })
                .collect(),
        )
    }
}

/// Instantiates a [`UniversalBatchVerifyCircuit`] with randomly sampled inputs
/// and does a mock run.
///
/// # Command line
///
/// cargo test --release --package upa-circuits --lib -- tests::universal_batch_verifier::universal_batch_verifier_test_mock
/// --exact --nocapture
#[test]
fn universal_batch_verifier_test_mock() {
    let mut rng = OsRng;
    universal_batch_verifier_test_mock_with(
        |config, rng| UniversalBatchVerifierInputs::sample_mixed(config, rng),
        &mut rng,
    )
}

/// Instantiates a [`UniversalBatchVerifyCircuit`] for the edge case where all inputs are zero
/// and does a mock run.
#[test]
fn universal_batch_verifier_test_mock_all_zero() {
    let mut rng = OsRng;
    universal_batch_verifier_test_mock_with(
        |config, rng| {
            UniversalBatchVerifierInputs::sample_all_zero(config, rng)
        },
        &mut rng,
    )
}

/// Randomly samples some inputs with `input_sampler`, instantiates
/// a [`UniversalBatchVerifyCircuit`] with them and does a mock run.
fn universal_batch_verifier_test_mock_with<G, R>(input_sampler: G, rng: &mut R)
where
    G: FnOnce(
        &UniversalBatchVerifierConfig,
        &mut R,
    ) -> UniversalBatchVerifierInputs<Fr>,
    R: CryptoRng + RngCore + ?Sized,
{
    let k: u32 = std::env::var("UBV_DEGREE")
        .unwrap_or_else(|_| "18".to_string())
        .parse()
        .expect("Parsing error");
    let config = sample_test_config(k, rng);
    let inputs = input_sampler(&config, rng);
    let circuit =
        UniversalBatchVerifyCircuit::<Fr, G1Affine>::mock(&config, &inputs);
    let instances = circuit.instances();
    MockProver::<Fr>::run(k, &circuit, instances)
        .expect("Mock prover run failure")
        .assert_satisfied();

    assert!(check_instance(&circuit, &config, &inputs));
}

/// Instantiates a [`UniversalBatchVerifyCircuit`] with randomly sampled inputs
/// and generates/verifies a proof.
///
/// # Command line
///
/// cargo test --release --package upa-circuits --lib -- tests::universal_batch_verifier::universal_batch_verifier_test_prover
/// --exact --nocapture --ignored
#[ignore = "takes too long"]
#[test]
fn universal_batch_verifier_test_prover() {
    let k: u32 = std::env::var("UBV_DEGREE")
        .unwrap_or_else(|_| "18".to_string())
        .parse()
        .expect("Parsing error");
    let mut rng = OsRng;
    let config = sample_test_config(k, &mut rng);
    let inputs = UniversalBatchVerifierInputs::sample_mixed(&config, &mut rng);
    // Keygen
    let timer = start_timer!(|| "Keygen");
    let params = gen_srs(k);
    let (pk, gate_config, break_points) = {
        let circuit =
            UniversalBatchVerifyCircuit::<Fr, G1Affine>::keygen(&config, &());
        println!("Start keygen vk");
        let vk = keygen_vk(&params, &circuit).expect("unable to gen. vk");
        println!("Start keygen pk");
        let pk = keygen_pk(&params, vk, &circuit).expect("unable to gen. pk");
        let break_points = circuit.break_points();
        (pk, circuit.gate_config().clone(), break_points)
    };
    end_timer!(timer);
    // Prove
    let timer = start_timer!(|| "Proving");
    let circuit = UniversalBatchVerifyCircuit::<Fr, G1Affine>::prover(
        &config,
        &gate_config,
        break_points,
        &inputs,
    );
    let instances: &[Fr] = &circuit.instances()[0];
    let proof = {
        let mut transcript =
            Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<Bn256>,
            _,
            _,
            _,
            _,
        >(
            &params,
            &pk,
            &[circuit],
            &[&[instances]],
            rng,
            &mut transcript,
        )
        .expect("proof gen. failure");
        transcript.finalize()
    };
    end_timer!(timer);
    // Verify
    let timer = start_timer!(|| "Verifying");
    let mut transcript = Blake2bRead::<_, G1Affine, _>::init(&proof[..]);
    verify_proof::<_, VerifierSHPLONK<Bn256>, _, _, _>(
        &params,
        pk.get_vk(),
        SingleStrategy::new(&params),
        &[&[instances]],
        &mut transcript,
    )
    .expect("verification failure");
    end_timer!(timer);
}
