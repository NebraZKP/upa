use crate::{
    batch_verify::{
        common::{
            native::{
                json::{load_proof_and_inputs_batch, load_vk},
                unsafe_proof_generation::sample_proofs_inputs_vk,
            },
            types::PublicInputs,
        },
        universal::{
            native::{
                compute_pi_term_for_entry_without_commitment,
                verify_universal_groth16_batch,
            },
            types::{
                UniversalBatchVerifierConfig, UniversalBatchVerifierInput,
                UniversalBatchVerifierInputs,
            },
        },
    },
    tests::{encode_g1, PROOF_BATCH_1_8_FILE, VK_FILE},
};
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1};
use rand::Rng;
use rand_core::OsRng;

/// Simple test of the universal verifier for multiple proofs with the same VK.
#[test]
fn test_universal_verifier_same_vk() {
    let vk_0 = load_vk(VK_FILE);
    let pf_batch = load_proof_and_inputs_batch(PROOF_BATCH_1_8_FILE);
    const NUM_PUBLIC_INPUTS: usize = 4;
    let batch = pf_batch
        .into_iter()
        .map(|(pf, i)| UniversalBatchVerifierInput::new(vk_0.clone(), pf, i));
    let is_satisfied = verify_universal_groth16_batch(batch, NUM_PUBLIC_INPUTS);
    assert!(is_satisfied, "Verification failed");
}

/// Test the universal verifier for multiple circuits with different numbers
/// of public inputs.
#[test]
fn test_universal_verifier_distinct_vks() {
    // Generate 2 circuits, one with 4 pis and a commitment, the other
    // with 5 and no point.  Generate 2 proofs for the first, and 3 proofs
    // for the second. Verify all 5 proofs in one go.

    let rng = &mut OsRng;
    let (batch_1, vk_1) = sample_proofs_inputs_vk(4, true, 2, rng);
    let (batch_2, vk_2) = sample_proofs_inputs_vk(5, false, 3, rng);
    let batch_1_entries = batch_1
        .into_iter()
        .map(|(p, i)| UniversalBatchVerifierInput::new(vk_1.clone(), p, i));
    let batch_2_entries = batch_2
        .into_iter()
        .map(|(p, i)| UniversalBatchVerifierInput::new(vk_2.clone(), p, i));
    let full_batch = batch_1_entries.chain(batch_2_entries);

    let is_satisfied = verify_universal_groth16_batch(full_batch, 5);
    assert!(is_satisfied, "Verification failed");
}

/// Test the universal verifier in the general case, i.e., with randomly sampled inputs
/// from a [`BatchVerifyConfig`].
#[test]
fn test_universal_verifier_general_case() {
    const MAX_NUM_PUBLIC_INPUTS: u32 = 100;
    const MAX_BATCH_SIZE: u32 = 32;
    let rng = &mut OsRng;
    let fake_config = UniversalBatchVerifierConfig {
        // The first four values don't matter for native checks;
        // only the batch size and the (max) number of public inputs do.
        degree_bits: 16,
        lookup_bits: 15,
        limb_bits: 88,
        num_limbs: 3,
        inner_batch_size: rng.gen_range(1..=MAX_BATCH_SIZE),
        max_num_public_inputs: rng.gen_range(2..=MAX_NUM_PUBLIC_INPUTS),
    };
    let full_batch =
        UniversalBatchVerifierInputs::sample_mixed(&fake_config, rng);
    let max_num_public_inputs = full_batch.max_len();
    let is_satisfied =
        verify_universal_groth16_batch(full_batch.0, max_num_public_inputs);
    assert!(is_satisfied, "Verification failed");
}

/// Test the native computation of the PI term in the universal verifier.
#[test]
fn test_compute_pi_term() {
    // Create fake VK.s group points, keeping knowledge of the "unencoded"
    // scalars that generate them.  We then use these scalars to compute the
    // expected "unencoded" output of `compute_pi_term`, as a scalar field
    // element, and compare this to the actual output group point.

    let vk_s = [encode_g1(7), encode_g1(11), encode_g1(13), encode_g1(17)];
    let inputs = [Fr::from(3), Fr::from(5), Fr::from(7)];

    // First 2 inputs should yield:
    //   7 + 3*11 + 5*13 = 7 + 33 + 65 = 105
    assert_eq!(
        G1::from(encode_g1(105)),
        compute_pi_term_for_entry_without_commitment(
            &vk_s[0..3],
            &PublicInputs(Vec::from(&inputs[0..2])),
        ),
    );

    // First 2 inputs should yield:
    //   7 + 3*11 + 5*13 + 7*17 = 7 + 33 + 65 + 119 = 224
    assert_eq!(
        G1::from(encode_g1(224)),
        compute_pi_term_for_entry_without_commitment(
            &vk_s,
            &PublicInputs(Vec::from(&inputs[..])),
        ),
    );
}
