//! Keccak circuit tests

use crate::{
    batch_verify::universal::native::compute_circuit_id,
    keccak::{
        self, inputs::KeccakCircuitInputs, utils::compute_submission_id,
        AssignedKeccakInput, AssignedVerifyingKeyLimbs, KeccakConfig,
        KeccakPaddedCircuitInput, PaddedVerifyingKeyLimbs, KECCAK_LOOKUP_BITS,
        LIMB_BITS, NUM_LIMBS,
    },
    tests::utils::check_instance,
    utils::commitment_point::{
        be_bytes_to_field_element, commitment_hash_from_commitment_point_limbs,
    },
    EccPrimeField, SafeCircuit,
};
use ark_std::{end_timer, start_timer};
use ethers_core::utils::keccak256;
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
use itertools::Itertools;
use rand_core::OsRng;
use snark_verifier_sdk::CircuitExt;
use std::env::var;

mod multivar;
mod utils;
mod variable;

/// Number of application public inputs
const NUM_APP_PUBLIC_INPUTS: u32 = 10;

/// Inner batch size
const INNER_BATCH_SIZE: u32 = 2;

/// Outer batch size
const OUTER_BATCH_SIZE: u32 = 2;

/// Keccak circuit type
type KeccakCircuit = keccak::KeccakCircuit<Fr, G1Affine>;

//// Keccak Circuit Inconsistency Error.
///
/// This error can be returned as the result of [`is_well_constructed`](KeccakCircuit::is_well_constructed).
#[derive(Clone, Debug)]
pub enum KeccakCircuitInconsistency<F> {
    /// Keccak Proof Id Mismatch Error.
    ///
    /// The keccak output of a keccak query differs from the
    /// expected value. Returns the number of the query, the output proofId and the
    /// expected proofId.
    KeccakProofId(u32, Vec<u8>, Vec<u8>),

    /// Keccak CircuitId Mismatch Error.
    ///
    /// The keccak output of a keccak query differs from the
    /// expected value. Returns the number of the query, the output circuitId and the
    /// expected circuitId.
    KeccakCircuitId(u32, Vec<u8>, Vec<u8>),

    /// Public Input Number Mismatch Error.
    ///
    /// The number of public inputs of the circuit doesn't correspond to that of
    /// the configuration. Returns those two values in order.
    PublicInputNumber(u32, u32),

    /// Public Output Mismatch Error.
    ///
    /// The field elements given as the public output don't decompose into
    /// the keccak output bytes of the last keccak query. Returns the actual value,
    /// the value computed from the pair of field elements in the instance
    /// and the expected value, in order.
    PublicOutput(Vec<u8>, Vec<u8>, Vec<u8>),

    /// Commitment Query Mismatch Error.
    ///
    /// The field elements given as the commitment hash don't coincide with the
    /// output bytes of the commitment point queries. Returns the number of the
    /// query, the commitment hash computed from the query output bytes,
    /// the commitment hash computed from the limbs and the expected commitment hash.
    CommitmentQuery(u32, F, F, F),
}

/// Keccak circuit test function
impl KeccakCircuit {
    /// Check that for each `input: KeccakInput` of `self.public_inputs`,
    /// 1) The keccak output bytes of `self` match the `commitment_hash` in `input`.
    /// 2) The limbs in `input` represent coordinates that hash to `input.commitment_hash`
    pub fn are_commitment_point_queries_well_constructed(
        &self,
        starting_index_commitment_queries: usize,
    ) -> Result<(), KeccakCircuitInconsistency<Fr>> {
        for (i, input) in self.public_inputs.inputs.iter().enumerate() {
            let expected_commitment_hash = input.commitment_hash.value();
            let commitment_query_index =
                i + 2 * starting_index_commitment_queries;
            let query_commitment_hash_bytes: [u8; 32] = self
                .keccak_output_bytes()[32 * commitment_query_index
                ..32 * (commitment_query_index + 1)]
                .iter()
                .map(|assigned| {
                    assigned
                        .value()
                        .get_lower_32()
                        .try_into()
                        .expect("Not a byte")
                })
                .collect_vec()
                .try_into()
                .expect("Conversion to array is not allowed to fail");
            let commitment_hash = be_bytes_to_field_element::<Fr, 32>(
                &query_commitment_hash_bytes,
            );
            let limbs = input
                .commitment_point_limbs
                .iter()
                .map(|limb| *limb.value())
                .collect_vec();
            let computed_commitment_hash =
                commitment_hash_from_commitment_point_limbs(
                    &limbs[..],
                    LIMB_BITS,
                    NUM_LIMBS,
                );
            ((&commitment_hash == expected_commitment_hash)
                && (&computed_commitment_hash == expected_commitment_hash))
                .then_some(())
                .ok_or({
                    KeccakCircuitInconsistency::CommitmentQuery(
                        commitment_query_index as u32,
                        commitment_hash,
                        computed_commitment_hash,
                        *expected_commitment_hash,
                    )
                })?;
        }
        Ok(())
    }

    /// Checks that `self` is well-formed w.r.t. `config`.
    ///
    /// # Note
    ///
    /// In principle, any circuit generated via [`new`](Self::new) should always be well-formed.
    /// This function is primarly for testing purposes and checking invariants.
    pub fn is_well_constructed(
        &self,
        config: &KeccakConfig,
    ) -> Result<(), KeccakCircuitInconsistency<Fr>> {
        let mut last_index = 0;
        for (i, input) in self.public_inputs.inputs.iter().enumerate() {
            last_index = i as u32;
            let number_of_field_elements = input.num_field_elements();
            let has_commitment = input.has_commitment();
            let num_bytes = 32 * (number_of_field_elements + 1);
            let mut vk = input.app_vk.value().vk();
            vk.s = vk
                .s
                .into_iter()
                .take(number_of_field_elements + 1 + has_commitment as usize)
                .collect();
            if !has_commitment {
                vk.h1 = vec![];
                vk.h2 = vec![];
            }
            let circuit_id = compute_circuit_id(&vk);
            let input_bytes = circuit_id
                .iter()
                .copied()
                .chain(input.public_inputs().into_iter().flat_map(
                    |field_element| {
                        field_element
                            .value()
                            .to_bytes_le()
                            .into_iter()
                            .rev()
                            .collect_vec()
                    },
                ))
                .collect_vec();
            let expected_bytes_proof_id = keccak256(&input_bytes[..num_bytes]);
            let output_bytes_circuit_id = self.keccak_output_bytes()
                [32 * 2 * i..32 * (2 * i + 1)]
                .iter()
                .map(|v| v.value().to_bytes_le()[0])
                .collect_vec();
            let output_bytes_proof_id = self.keccak_output_bytes()
                [32 * (2 * i + 1)..32 * (2 * i + 2)]
                .iter()
                .map(|v| v.value().to_bytes_le()[0])
                .collect_vec();
            (output_bytes_circuit_id == circuit_id)
                .then_some(())
                .ok_or_else(|| {
                    KeccakCircuitInconsistency::KeccakCircuitId(
                        last_index,
                        output_bytes_circuit_id,
                        circuit_id.to_vec(),
                    )
                })?;
            (output_bytes_proof_id == expected_bytes_proof_id)
                .then_some(())
                .ok_or_else(|| {
                    KeccakCircuitInconsistency::KeccakProofId(
                        last_index,
                        output_bytes_proof_id,
                        expected_bytes_proof_id.to_vec(),
                    )
                })?;
        }
        (last_index + 1 == config.inner_batch_size * config.outer_batch_size)
            .then_some(())
            .ok_or({
                KeccakCircuitInconsistency::PublicInputNumber(
                    last_index + 1,
                    config.inner_batch_size * config.outer_batch_size,
                )
            })?;
        let last_input_bytes = self.keccak_output_bytes()
            [0..32 * 2 * (last_index as usize + 1)]
            .iter()
            .chunks(32)
            .into_iter()
            .skip(1)
            .step_by(2)
            .flat_map(|chunk| {
                chunk.into_iter().map(|v| v.value().to_bytes_le()[0])
            })
            .collect_vec();
        // The last bytes will be either the submission Id or the keccak
        // of the proof Ids.
        let last_expected_bytes = match config.output_submission_id {
            true => {
                let proof_ids = last_input_bytes.into_iter().chunks(32).into_iter().map(|chunk| {
                    <[u8; 32]>::try_from(chunk.collect_vec()).expect(
                        "Conversion from vector into array is not allowed to fail",
                    )
                }).collect_vec();
                let num_proof_ids = self
                    .public_inputs
                    .num_proof_ids
                    .expect(
                        "num_proof_ids must exist when the circuit outputs submission id",
                    )
                    .value()
                    .get_lower_32() as u64;
                compute_submission_id(proof_ids, num_proof_ids)
            }
            false => keccak256(last_input_bytes),
        };
        // The last 32 keccak output bytes must match `last_expected_bytes`.
        let num_keccak_output_bytes = self.keccak_output_bytes().len();
        let last_output_bytes = self.keccak_output_bytes()
            [num_keccak_output_bytes - 32..]
            .iter()
            .map(|v| v.value().to_bytes_le()[0])
            .collect_vec();
        let public_output = self.public_output.map(|field_element| {
            field_element
                .value()
                .to_bytes_le()
                .into_iter()
                .take(16)
                .rev()
                .collect_vec()
        });
        let mut output_bytes = public_output[1].clone();
        output_bytes.extend(public_output[0].iter());
        (last_output_bytes == output_bytes
            && last_output_bytes == last_expected_bytes)
            .then_some(())
            .ok_or({
                KeccakCircuitInconsistency::PublicOutput(
                    last_output_bytes,
                    output_bytes,
                    last_expected_bytes.into(),
                )
            })?;
        self.are_commitment_point_queries_well_constructed(
            last_index as usize + 1,
        )?;
        Ok(())
    }
}

/// Instantiates a [`KeccakCircuitBuilder`] with random inputs and does a mock run.
///
/// # Note
///
/// The test fails for KECCAK_DEGREE values below 17.
fn test_keccak_mock(output_submission_id: bool) {
    let _ = env_logger::builder().is_test(true).try_init();
    let k: u32 = var("KECCAK_DEGREE")
        .unwrap_or_else(|_| "18".to_string())
        .parse()
        .expect("Parsing error");
    let config = KeccakConfig {
        degree_bits: k,
        num_app_public_inputs: NUM_APP_PUBLIC_INPUTS,
        inner_batch_size: INNER_BATCH_SIZE,
        outer_batch_size: OUTER_BATCH_SIZE,
        lookup_bits: KECCAK_LOOKUP_BITS,
        output_submission_id,
    };
    let mut rng = OsRng;
    let inputs = KeccakCircuitInputs::<Fr>::sample(&config, &mut rng);
    let circuit = KeccakCircuit::mock(&config, &inputs);
    let instances: Vec<Fr> = circuit.instances()[0].clone();
    circuit
        .is_well_constructed(&config)
        .unwrap_or_else(|err| panic!("Circuit not well constructed: {err:?}"));
    assert!(check_instance(&circuit, &config, &inputs));
    MockProver::<Fr>::run(k, &circuit, vec![instances])
        .expect("Mock prover run failure")
        .assert_satisfied();
}

/// # Command line
///
/// KECCAK_DEGREE=18 RUST_LOG=info cargo test --release -- --nocapture test_keccak_mock_output_sid
#[test]
fn test_keccak_mock_output_sid() {
    test_keccak_mock(true);
}

/// # Command line
///
/// KECCAK_DEGREE=18 RUST_LOG=info cargo test --release -- --nocapture test_keccak_mock_no_sid
#[test]
fn test_keccak_mock_no_sid() {
    test_keccak_mock(false);
}

/// Instantiates a [`KeccakCircuitBuilder`] with random inputs and generates/verifies a proof.
///
/// # Note
///
/// The test fails for KECCAK_DEGREE values below 17.
fn test_keccak_prover(output_submission_id: bool) {
    let _ = env_logger::builder().is_test(true).try_init();
    let k: u32 = var("KECCAK_DEGREE")
        .unwrap_or_else(|_| "18".to_string())
        .parse()
        .expect("Parsing error");
    let config = KeccakConfig {
        degree_bits: k,
        num_app_public_inputs: NUM_APP_PUBLIC_INPUTS,
        inner_batch_size: INNER_BATCH_SIZE,
        outer_batch_size: OUTER_BATCH_SIZE,
        lookup_bits: KECCAK_LOOKUP_BITS,
        output_submission_id,
    };
    let mut rng = OsRng;
    let inputs = KeccakCircuitInputs::sample(&config, &mut rng);
    // Keygen
    let timer = start_timer!(|| "Keygen");
    let params = gen_srs(k);
    let (pk, gate_config, break_points) = {
        let circuit = KeccakCircuit::keygen(&config, &());
        println!("Start keygen vk");
        let vk = keygen_vk(&params, &circuit).expect("unable to gen. vk");
        println!("Start keygen pk");
        let pk = keygen_pk(&params, vk, &circuit).expect("unable to gen. pk");
        let break_points = circuit.break_points();
        (pk, circuit.gate_config().clone(), break_points)
    };
    println!("Break points: {break_points:?}");
    end_timer!(timer);
    // Prove
    let timer = start_timer!(|| "Proving");
    let circuit =
        KeccakCircuit::prover(&config, &gate_config, break_points, &inputs);
    circuit
        .is_well_constructed(&config)
        .unwrap_or_else(|err| panic!("Circuit not well constructed: {err:?}"));
    assert!(check_instance(&circuit, &config, &inputs));
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

/// # Command line
///
/// KECCAK_DEGREE=18 RUST_LOG=info cargo test --release -- --ignored --nocapture test_keccak_prover_output_sid
#[test]
#[ignore = "takes too long"]
fn test_keccak_prover_output_sid() {
    test_keccak_prover(true);
}

/// # Command line
///
/// KECCAK_DEGREE=18 RUST_LOG=info cargo test --release -- --ignored --nocapture test_keccak_prover_no_sid
#[test]
#[ignore = "takes too long"]
fn test_keccak_prover_no_sid() {
    test_keccak_prover(false);
}

/// Unit test checking that [`KeccakPaddedCircuitInputs::to_instance_values`]
/// works correctly in both the fixed and variable length cases.
///
/// # Command line
///
/// RUST_LOG=info cargo test --package upa-circuits --lib -- tests::keccak::test_keccak_padded_circuit_input_to_instance_values --exact --nocapture
#[test]
fn test_keccak_padded_circuit_input_to_instance_values() {
    let mut dummy_app_public_inputs = Vec::new();
    for i in 1..=NUM_APP_PUBLIC_INPUTS {
        dummy_app_public_inputs.push(Fr::from(i as u64));
    }
    let mut dummy_commitment_limbs = Vec::new();
    for i in 1..NUM_LIMBS * 2 {
        dummy_commitment_limbs
            .push(Fr::from(i as u64 + NUM_APP_PUBLIC_INPUTS as u64));
    }
    let dummy_commitment_hash = Fr::from(222);
    let mut dummy_app_vk_limbs = Vec::new();
    for i in 0..(2 * NUM_APP_PUBLIC_INPUTS as usize + 24) * NUM_LIMBS {
        dummy_app_vk_limbs.push(Fr::from(i as u64 + 333));
    }
    let dummy_app_vk = PaddedVerifyingKeyLimbs::from_limbs(
        &dummy_app_vk_limbs,
        NUM_APP_PUBLIC_INPUTS as usize + 1,
    );

    // Test variable length case
    let variable_len = 4;
    let variable_padded_circuit_input = KeccakPaddedCircuitInput {
        len: Fr::from(variable_len),
        app_vk: dummy_app_vk,
        has_commitment: Fr::zero(),
        app_public_inputs: dummy_app_public_inputs[..variable_len as usize]
            .to_vec(),
        commitment_point_limbs: dummy_commitment_limbs,
        commitment_hash: dummy_commitment_hash,
    };

    let mut expected_variable_instance_values =
        vec![variable_padded_circuit_input.len];
    expected_variable_instance_values.extend(dummy_app_vk_limbs);
    expected_variable_instance_values
        .push(variable_padded_circuit_input.has_commitment);
    expected_variable_instance_values
        .push(variable_padded_circuit_input.commitment_hash);
    expected_variable_instance_values
        .extend(&variable_padded_circuit_input.commitment_point_limbs);
    expected_variable_instance_values
        .extend(&variable_padded_circuit_input.app_public_inputs);
    assert_eq!(
        expected_variable_instance_values,
        variable_padded_circuit_input.to_instance_values()
    );
}

impl<F: EccPrimeField> AssignedKeccakInput<F> {
    /// Returns the number of public inputs which will be keccak'd together.
    pub fn num_field_elements(&self) -> usize {
        self.len().value().get_lower_32() as usize
    }

    /// Returns 1 if the input uses the optional commitment, and 0 otherwise.
    pub fn has_commitment(&self) -> bool {
        self.has_commitment.value().get_lower_32() != 0
    }
}

impl<F> AssignedVerifyingKeyLimbs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    /// Returns the unassigned `self` as a [`PaddedVerifyingKeyLimbs`]
    /// instance.
    pub fn value(&self) -> PaddedVerifyingKeyLimbs<F> {
        PaddedVerifyingKeyLimbs {
            alpha: self.alpha.iter().map(|e| *e.value()).collect(),
            beta: self.beta.iter().map(|e| *e.value()).collect(),
            gamma: self.gamma.iter().map(|e| *e.value()).collect(),
            delta: self.delta.iter().map(|e| *e.value()).collect(),
            s: self
                .s
                .iter()
                .map(|s| s.iter().map(|e| *e.value()).collect())
                .collect(),
            h1: self.h1.iter().map(|e| *e.value()).collect(),
            h2: self.h2.iter().map(|e| *e.value()).collect(),
        }
    }
}
