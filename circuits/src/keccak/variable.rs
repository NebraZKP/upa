//! Variable base keccak utility functions

use super::utils::bytes_to_keccak_padded_words;
#[cfg(test)]
use super::{utils::byte_decomposition_list, AssignedKeccakInput};
use crate::utils::bitmask::{first_i_bits_bitmask, ith_bit_bitmask};
use ark_std::log2;
use halo2_base::{
    gates::RangeInstructions,
    safe_types::{GateInstructions, RangeChip},
    AssignedValue, Context,
};
use zkevm_keccak::util::{
    eth_types::Field, pack, unpack, NUM_BYTES_PER_WORD, NUM_WORDS_TO_ABSORB,
    RATE,
};

/// Number of bytes per field element. Because we are working with fields which
/// implement [`Field`], we can take this to be 32.
pub const NUM_BYTES_PER_FIELD_ELEMENT: u64 = 32;

/// Number of 64-bit words per field element
pub const NUM_WORDS: u64 = 4;

/// Log2 of the maximum number of input words.
pub const MAX_INPUT_LEN_WORDS_LOG2: u32 = 16;

/// Converts `input` to 64-bit words, padded as in keccak
#[cfg(test)]
pub(crate) fn input_to_keccak_padded_words<F: Field>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    input: AssignedKeccakInput<F>,
) -> Vec<AssignedValue<F>> {
    let num_bytes = ctx.load_constant(F::from(NUM_BYTES_PER_FIELD_ELEMENT));
    let word_len = chip.gate.mul(ctx, input.len, num_bytes);
    let public_input_bytes =
        byte_decomposition_list(ctx, chip, &input.public_inputs());
    var_bytes_to_keccak_padded_words(ctx, chip, public_input_bytes, word_len)
}

/// Computes the length of an input in words from the length of an input in
/// field elements
pub fn upa_input_len_to_word_len<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    len: AssignedValue<F>,
) -> AssignedValue<F> {
    let num_words = ctx.load_constant(F::from(NUM_WORDS));
    // The +1 below accounts for the vk_hash, always present in
    // UPA inputs
    range.gate.mul_add(ctx, num_words, len, num_words)
}

/// Computes the length of an input in bytes from the length of an input in
/// field elements
///
/// # Specification
///
/// This function performs **Step 2: Compute query byte length** of **Proof ID
/// Computation** in the variable length keccak spec.
pub fn upa_input_len_to_byte_len<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    len: AssignedValue<F>,
) -> AssignedValue<F> {
    let num_bytes = ctx.load_constant(F::from(NUM_BYTES_PER_FIELD_ELEMENT));
    // The +1 below accounts for the vk_hash, always present in UPA inputs
    //   result = (len+1) * num_bytes
    //          = len * num_bytes + num_bytes
    range.gate.mul_add(ctx, len, num_bytes, num_bytes)
}

/// Computes the length of an input measured in 64-bit words from the length of an input
/// in bytes.
///
/// # Note
///
/// The constraints here will only be satisfied when `byte_len` is
/// a multiple of [`NUM_BYTES_PER_WORD`]. The constraints may not be
/// satisfied for an otherwise valid circuit if
/// `byte_len` > 2^([`MAX_INPUT_LEN_WORDS_LOG2`]+3)
pub fn byte_len_to_word_len<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    byte_len: AssignedValue<F>,
) -> AssignedValue<F> {
    let num_bytes_per_word =
        ctx.load_constant(F::from(NUM_BYTES_PER_WORD as u64));
    // We can use div_unsafe because `num_bytes_per_word` is nonzero.
    let word_len = range.gate.div_unsafe(ctx, byte_len, num_bytes_per_word);
    // To avoid wrap-around, we need check that `word_len` < 2^MAX_INPUT_LEN_WORDS_LOG2.
    // Technically the condition is `word_len` < F::MODULUS/NUM_BYTES_PER_WORD
    // but this range check is cheaper and covers all reasonable use cases.
    assert!(
        word_len.value().get_lower_32() < 1 << MAX_INPUT_LEN_WORDS_LOG2,
        "Word length out of range"
    );
    range.range_check(ctx, word_len, MAX_INPUT_LEN_WORDS_LOG2 as usize);
    word_len
}

/// Computes the last chunk index of an input measured in 17-word chunks from the
/// length of an input in bytes.
///
/// # Note
///
/// - In the keccak variable circuit, `byte_len` will never be 0.
/// - The last chunk index is defined as the chunk index of the last chunk after
/// padding. For example, if `byte_len` bytes fill exactly `n` chunks, the index
/// will be `n` because the bytes fill chunks from `0` to `n-1`, the `n`-th chunk
/// being the padding one.
pub fn byte_len_to_last_chunk_index<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    byte_len: AssignedValue<F>,
    max_len: usize,
) -> AssignedValue<F> {
    let num_bits = log2(max_len);
    let (quotient, _) = range.div_mod(ctx, byte_len, RATE, num_bits as usize);
    quotient
}

/// Converts `public_input_bytes` to 64-bit words. Input vector `public_input_bytes` is the byte decomposition
/// of the public input vector of field elements, which has been padded to the maximum length allowed
/// for this circuit configuration. This function converts these bytes into a vector of 64-bit words
/// and returns these as output. The first word_len output words are derived from the public input vector,
/// while the rest are padded according to the keccak algorithm
///
/// # Specification
///
/// This function corresponds to the component **Var bytes to Keccak Padded Words**
/// in the variable length keccak spec.
pub fn var_bytes_to_keccak_padded_words<F: Field>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    input_bytes: Vec<AssignedValue<F>>,
    byte_len: AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    // Compute word length
    let word_len = byte_len_to_word_len(ctx, chip, byte_len);
    // Convert public inputs to words. This adds padding to the final chunk, but not
    // to the previous ones.
    let public_input_words =
        bytes_to_keccak_padded_words(ctx, chip, &input_bytes);
    // Sanity check: the number of words is a multiple of the block size
    let number_of_words = public_input_words.len();
    assert_eq!(number_of_words % NUM_WORDS_TO_ABSORB, 0);
    // Compute the word bitmasks
    let number_of_chunks = number_of_words / NUM_WORDS_TO_ABSORB;
    // This bitmask has ones in the first `word_len` elements and zeroes everywhere else
    let input_word_bitmask = first_i_bits_bitmask(
        ctx,
        chip.gate(),
        word_len,
        number_of_words as u64,
    );
    // This bitmask has a single one on the `word_len`-th position (counting from 0)
    // and zeroes everywhere else
    let first_padding_word_bitmask =
        ith_bit_bitmask(ctx, &chip.gate, word_len, number_of_words as u64);
    // Initialize the word vector
    let mut result = Vec::with_capacity(number_of_words);
    // Iterate over words and select the right one
    for chunk_idx in 0..number_of_chunks {
        for word_idx in 0..NUM_WORDS_TO_ABSORB {
            let is_last = word_idx == NUM_WORDS_TO_ABSORB - 1;
            let is_first = word_idx == 0;
            let selector =
                input_word_bitmask[chunk_idx * NUM_WORDS_TO_ABSORB + word_idx];
            let filler_selector = first_padding_word_bitmask
                [chunk_idx * NUM_WORDS_TO_ABSORB + word_idx];
            // Compute the filler word.
            let filler_word = if is_last {
                // If it is the last word of a block, it can be:
                // a) 00...01, if it isn't the `word_len`-th word
                // b) 10...01, if it is
                let zeroes_one = ctx.load_constant(constant_zeroes_1());
                let one_zeroes_one = ctx.load_constant(constant_1_zeroes_1());
                chip.gate.select(
                    ctx,
                    one_zeroes_one,
                    zeroes_one,
                    filler_selector,
                )
            } else if is_first {
                // If it is the first word of a block, it is 100...0
                ctx.load_constant(constant_1_zeroes())
            } else {
                // If it's neither the first nor the last word of a block, it can be:
                // a) 00...00, if it isn't the `word_len`-th word
                // b) 10...00, if it is
                let zero = ctx.load_constant(F::zero());
                let one_zeroes = ctx.load_constant(constant_1_zeroes());
                chip.gate.select(ctx, one_zeroes, zero, filler_selector)
            };
            // The resulting word will be:
            // a) the original word coming from the bytes for the first `word_len` words
            // b) the filler word for the rest
            result.push(chip.gate.select(
                ctx,
                public_input_words[chunk_idx * NUM_WORDS_TO_ABSORB + word_idx],
                filler_word,
                selector,
            ));
        }
    }
    result
}

/// Converts `bits` to a byte.
fn bits_to_byte(bits: &[u8]) -> u8 {
    bits.iter().fold(0, |result, &bit| (result << 1) | bit)
}

/// Converts `words` to a byte vector.
///
/// # Specification
///
/// This function performs **Step 3 of Variable-Length Query**
/// in the variable length keccak spec.
pub fn bytes_from_words<F: Field>(words: &[AssignedValue<F>]) -> Vec<u8> {
    let mut result = Vec::new();
    for word in words {
        let mut bits = unpack(*word.value());
        for bit_chunk in bits.chunks_mut(8) {
            bit_chunk.reverse();
            let byte = bits_to_byte(bit_chunk);
            result.push(byte);
        }
    }
    result
}

/// Computes the word corresponding to 10...00.
pub fn constant_1_zeroes<F: Field>() -> F {
    let mut bit_vec = [0u8; 64];
    bit_vec[0] = 1;
    pack(&bit_vec)
}

/// Computes the word corresponding to 10...01.
fn constant_1_zeroes_1<F: Field>() -> F {
    let mut bit_vec = [0u8; 64];
    bit_vec[0] = 1;
    bit_vec[63] = 1;
    pack(&bit_vec)
}

/// Computes the word corresponding to 00...01.
pub fn constant_zeroes_1<F: Field>() -> F {
    let mut bit_vec = [0u8; 64];
    bit_vec[63] = 1;
    pack(&bit_vec)
}

/// Given `bytes`, detects whether it has keccak padding and removes it in that case.
///
/// # Specification
///
/// This function performs **Step 7 of Variable-Length Query**
/// in the variable length keccak spec.
pub(crate) fn remove_padded_bytes(bytes: &[u8]) -> &[u8] {
    let mut counter = 1;
    let number_of_bytes = bytes.len();
    let last_byte = bytes.last().expect("Empty byte vector");
    if *last_byte != 128 {
        panic!("Wrong last byte: {last_byte:?}");
    }
    for byte in bytes.iter().rev().skip(1) {
        match byte {
            0 => counter += 1,
            1 => break,
            b => {
                panic!(
                    "Wrong byte {b:?} at position {:?}",
                    number_of_bytes - counter - 1
                );
            }
        }
    }
    &bytes[..number_of_bytes - 1 - counter]
}
