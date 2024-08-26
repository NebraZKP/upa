use crate::{
    keccak::{
        chip::get_assigned_bytes_values,
        utils::{byte_decomposition_list, bytes_to_keccak_padded_words},
        variable::{
            bytes_from_words, constant_1_zeroes, constant_zeroes_1,
            input_to_keccak_padded_words, remove_padded_bytes,
        },
        AssignedKeccakInput, KeccakConfig, KeccakPaddedCircuitInput,
        PaddedVerifyingKeyLimbs, KECCAK_LOOKUP_BITS,
    },
    utils::bitmask::{first_i_bits_bitmask, ith_bit_bitmask},
};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateChip, RangeChip},
    halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr},
};
use itertools::Itertools;
use rand::Rng;
use rand_core::OsRng;
use zkevm_keccak::util::NUM_WORDS_TO_ABSORB;

/// Max vector length for tests to prevent overflow.
const MAX_VEC_LEN: u64 = 10000;

/// Checks the [`first_i_bits_bitmask`] and the [`ith_bit_bitmask`] are computed correctly.
#[test]
fn check_bitmasks() {
    let mut builder = GateThreadBuilder::default();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let mut rng = OsRng;
    let n = rng.gen_range(0..MAX_VEC_LEN);
    let len = rng.gen_range(0..n);
    let expected_bitmask = (0..len)
        .into_iter()
        .map(|_| 1)
        .chain((0..n - len).into_iter().map(|_| 0))
        .collect_vec();
    let mut expected_equality_bitmask =
        (0..n).into_iter().map(|_| 0).collect_vec();
    expected_equality_bitmask[len as usize] = 1;
    let assigned_len = ctx.load_witness(Fr::from(len));
    let bitmask = first_i_bits_bitmask(ctx, &chip, assigned_len, n);
    let equality_bitmask = ith_bit_bitmask(ctx, &chip, assigned_len, n);
    assert_eq!(
        get_assigned_bytes_values(&bitmask),
        expected_bitmask,
        "Bitmask mismatch"
    );
    assert_eq!(
        get_assigned_bytes_values(&equality_bitmask),
        expected_equality_bitmask,
        "Equality bitmask mismatch"
    )
}

/// Checks the words computed with [`input_to_keccak_padded_words`] are correct, i.e., that they match
/// those coming from [`bytes_to_keccak_padded_words`] in their common chunks and that they have the
/// right padding after that.
#[test]
fn check_words() {
    let mut builder = GateThreadBuilder::default();
    let ctx = builder.main(0);
    let chip = RangeChip::<Fr>::default(8);
    let mut rng = OsRng;
    let len = rng.gen_range(0..MAX_VEC_LEN / 2);
    let len_fr = Fr::from(len);
    let mut field_elements: Vec<Fr> =
        (0..len).map(|_| Fr::random(&mut rng)).collect();
    let og_field_elements = field_elements.clone();
    let filler_len = rng.gen_range(0..MAX_VEC_LEN / 2);
    let filler_field_elements: Vec<Fr> =
        (0..filler_len).map(|_| Fr::zero()).collect();
    field_elements.extend(filler_field_elements);
    let config = KeccakConfig {
        degree_bits: 1,
        num_app_public_inputs: (len + filler_len) as u32,
        inner_batch_size: 1,
        outer_batch_size: 1,
        lookup_bits: KECCAK_LOOKUP_BITS,
        output_submission_id: false, // Irrelevant for this test
    };
    // This input has `app_public_inputs` of length `len` + `filler_len`.
    let keccak_input = KeccakPaddedCircuitInput {
        len: len_fr,
        app_vk: PaddedVerifyingKeyLimbs::dummy(&config),
        has_commitment: Fr::zero(),
        app_public_inputs: field_elements,
        commitment_hash: Default::default(),
        commitment_point_limbs: Default::default(),
    };
    // Assign keccak input
    let assigned_keccak_input =
        AssignedKeccakInput::from_keccak_padded_input(ctx, &chip, keccak_input);
    // Map input to words
    let words = input_to_keccak_padded_words(ctx, &chip, assigned_keccak_input);
    // Create and assign the original (without padding) keccak input
    let og_input = og_field_elements;
    let assigned_og_input = ctx.assign_witnesses(og_input);
    // Map original input to words
    let og_bytes = byte_decomposition_list(ctx, &chip, &assigned_og_input);
    let og_words = bytes_to_keccak_padded_words(ctx, &chip, &og_bytes);
    // Check words and og words coincide (up to the length of og_words)
    let og_words_len = og_words.len();
    let words_len = words.len();
    assert_eq!(
        og_words_len % NUM_WORDS_TO_ABSORB,
        0,
        "Number of words must be a multiple of {NUM_WORDS_TO_ABSORB}"
    );
    assert_eq!(
        words_len % NUM_WORDS_TO_ABSORB,
        0,
        "Number of words must be a multiple of {NUM_WORDS_TO_ABSORB}"
    );
    assert!(
        og_words_len <= words_len,
        "There must be more padded words than original words"
    );
    for (word, og_word) in words.iter().zip(og_words.iter()) {
        assert_eq!(word.value(), og_word.value(), "Words mismatch");
    }
    // Check extra chunks
    for chunk in &words
        .iter()
        .skip(og_words_len)
        .map(|word| word.value())
        .chunks(NUM_WORDS_TO_ABSORB)
    {
        for (idx, word) in chunk.enumerate() {
            if idx == 0 {
                assert_eq!(
                    word,
                    &constant_1_zeroes::<Fr>(),
                    "Word at the start of the chunk must be 10...00"
                );
            } else if idx == NUM_WORDS_TO_ABSORB - 1 {
                assert_eq!(
                    word,
                    &constant_zeroes_1::<Fr>(),
                    "Word at the end of the chunk must be 00...01"
                );
            } else {
                assert_eq!(
                    word,
                    &Fr::zero(),
                    "Words in the middle of the chunk must be zero"
                );
            }
        }
    }
}

/// Checks the function [`remove_padded_bytes`] performs the unpadding correctly.
#[test]
fn check_unpacking() {
    let mut builder = GateThreadBuilder::default();
    let ctx = builder.main(0);
    let chip = RangeChip::<Fr>::default(8);
    let mut rng = OsRng;
    let byte_len = rng.gen_range(1..MAX_VEC_LEN);
    let bytes = (0..byte_len)
        .into_iter()
        .map(|_| rng.gen::<u8>())
        .collect_vec();
    let assigned_bytes = bytes
        .iter()
        .map(|byte| ctx.load_constant(Fr::from(*byte as u64)))
        .collect_vec();
    let words = bytes_to_keccak_padded_words(ctx, &chip, &assigned_bytes);
    let padded_bytes = bytes_from_words(&words);
    let unpadded_bytes = remove_padded_bytes(&padded_bytes);
    assert_eq!(
        bytes, unpadded_bytes,
        "Unpadded bytes must equal original bytes"
    );
}
