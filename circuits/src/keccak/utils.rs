//! Some `KeccakCircuit`-related utility functions.

use super::{
    KeccakCircuitInputs, KeccakVarLenInput, LIMB_BITS, NUM_BYTES_FQ, NUM_LIMBS,
};
use crate::{
    keccak::{
        KeccakCircuit, KeccakConfig, KeccakGateConfig, PaddedVerifyingKeyLimbs,
    },
    utils::{
        commitment_point::limbs_into_g1affine, keccak_hasher::KeccakHasher,
    },
    EccPrimeField, SafeCircuit,
};
use core::{borrow::Borrow, iter};
use halo2_base::{
    gates::{
        builder::MultiPhaseThreadBreakPoints, GateInstructions, RangeChip,
        RangeInstructions,
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::ProvingKey,
        poly::{
            commitment::{Prover, Verifier},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                msm::DualMSM,
                strategy::GuardKZG,
            },
        },
    },
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;
use log::info;
use snark_verifier_sdk::{gen_pk, halo2::gen_snark, Snark};
use tiny_keccak::{Hasher, Keccak};
use zkevm_keccak::util::{NUM_WORDS_TO_ABSORB, RATE_IN_BITS};

/// Byte size in bits
const BYTE_SIZE_IN_BITS: usize = 8;

/// Number of parts to perform the in-field assertion
/// for byte decompositions.
const NUM_PARTS: usize = 2;

/// Number of FQ elements per G1Affine point
const NUM_FQ_PER_G1AFFINE: usize = 2;

/// Number of FQ elements per G2Affine point
const NUM_FQ_PER_G2AFFINE: usize = 4;

/// Number of bytes per field element.
///
/// # Note
///
/// Most of the functions in this module are generic over this, but for
/// some particular ones we have to assume the field elements are representable
/// as 32 bytes.
const NUM_BYTES_PER_FIELD_ELEMENT: usize = 32;

/// Returns the number of bytes required to represent a field element.
pub fn num_bytes<F: EccPrimeField>() -> usize {
    let num_bytes: usize =
        (F::NUM_BITS as usize + BYTE_SIZE_IN_BITS - 1) / BYTE_SIZE_IN_BITS;
    assert!(num_bytes > 0);
    num_bytes
}

/// Returns a vector with the powers of 2^8.
pub(crate) fn byte_decomposition_powers<F: EccPrimeField>() -> Vec<F> {
    let num_bytes = num_bytes::<F>();
    let mut powers = Vec::<F>::with_capacity(num_bytes);
    let two_to_byte_size_in_bits = F::from(1 << BYTE_SIZE_IN_BITS);

    powers.push(F::one());
    for i in 1..num_bytes {
        powers.push(powers[i - 1] * two_to_byte_size_in_bits);
    }

    powers
}

/// Returns the little-endian byte decomposition of F::MODULUS - 1,
/// in other words, the byte decomposition of the max element
/// in the field F.
fn field_max_element_byte_decomposition<F: EccPrimeField>() -> Vec<F> {
    let modulus_minus_one = F::zero() - F::one();
    modulus_minus_one
        .to_bytes_le()
        .into_iter()
        .map(|byte| F::from(byte as u64))
        .collect_vec()
}

/// Splits the element `F::MODULUS - 1` into `NUM_PARTS` parts, each representable
/// with `num_bytes`/`NUM_PARTS` bytes. The parts are returned from least to most
/// significant.
pub(crate) fn field_max_element_into_parts<F, const NUM_PARTS: usize>(
) -> [F; NUM_PARTS]
where
    F: EccPrimeField,
{
    let num_bytes = num_bytes::<F>();
    assert_eq!(num_bytes % NUM_PARTS, 0);
    let num_bytes_in_part = num_bytes / NUM_PARTS;
    let powers = &byte_decomposition_powers::<F>()[0..num_bytes_in_part];
    field_max_element_byte_decomposition::<F>()
        .into_iter()
        .chunks(num_bytes_in_part)
        .into_iter()
        .map(|chunk| {
            chunk
                .into_iter()
                .zip_eq(powers.iter())
                .fold(F::zero(), |acc, (byte, power)| acc + byte * power)
        })
        .collect_vec()
        .try_into()
        .expect("Conversion from vector into array is not allowed to fail")
}

/// Splits the field element represented by `bytes` into `NUM_PARTS` parts.
fn assigned_field_element_bytes_into_parts<'a, F, const NUM_PARTS: usize>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    bytes: impl ExactSizeIterator<Item = &'a AssignedValue<F>>,
) -> [AssignedValue<F>; NUM_PARTS]
where
    F: EccPrimeField,
{
    let num_bytes = num_bytes::<F>();
    assert_eq!(num_bytes, bytes.len(), "Wrong number of bytes");
    assert_eq!(num_bytes % NUM_PARTS, 0);
    let num_bytes_in_part = num_bytes / NUM_PARTS;
    let powers = byte_decomposition_powers()
        .into_iter()
        .take(num_bytes_in_part)
        .map(|power| QuantumCell::from(ctx.load_constant(power)))
        .collect_vec();
    bytes
        .into_iter()
        .chunks(num_bytes_in_part)
        .into_iter()
        .map(|chunk| {
            chip.gate.inner_product(
                ctx,
                chunk.into_iter().cloned().map(QuantumCell::from),
                powers.clone(),
            )
        })
        .collect_vec()
        .try_into()
        .expect("Conversion from vector into array is not allowed to fail")
}

/// Checks `bytes` corresponds to the byte decomposition of a field element.
/// It does so by splitting both the field element represented by `bytes` into
/// `NUM_PARTS` parts and comparing them to the parts of `F::MODULUS - 1`.
///
/// # Implementation Note
///
/// This function assumes that `bytes` have been range-checked to be `< 2^8`.
pub(crate) fn assert_byte_decomposition_is_in_field<
    'a,
    F,
    const NUM_PARTS: usize,
>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    bytes: impl ExactSizeIterator<Item = &'a AssignedValue<F>>,
) -> bool
where
    F: EccPrimeField,
{
    let num_bytes = num_bytes::<F>();
    assert_eq!(num_bytes % NUM_PARTS, 0);
    let num_bytes_in_part = num_bytes / NUM_PARTS;
    let num_bits_in_part = num_bytes_in_part * BYTE_SIZE_IN_BITS;
    let parts = assigned_field_element_bytes_into_parts::<F, NUM_PARTS>(
        ctx, chip, bytes,
    );
    let maximal_parts = field_max_element_into_parts::<F, NUM_PARTS>()
        .map(|part| QuantumCell::from(ctx.load_constant(part)));
    let is_in_field = parts.into_iter().zip_eq(maximal_parts.into_iter()).fold(
        ctx.load_constant(F::one()),
        |lower_parts_satisfied, (part, maximal_part)| {
            // It can satisfy all inequalities for the lower parts
            // AND be equal to the current part OR it can be strictly
            // smaller than the current part.
            let is_equal = chip.gate.is_equal(ctx, part, maximal_part);
            let is_equal_and_lower_parts =
                chip.gate.and(ctx, lower_parts_satisfied, is_equal);
            let is_less =
                chip.is_less_than(ctx, part, maximal_part, num_bits_in_part);
            chip.gate.or(ctx, is_equal_and_lower_parts, is_less)
        },
    );
    chip.gate.assert_is_const(ctx, &is_in_field, &F::one());

    // Return true if the byte decomposition is in the field, false otherwise
    is_in_field.value().get_lower_32() != 0
}

/// Decomposes `field_element` into bytes. Returns its big-endian byte decomposition,
/// already assigned in the `ctx`.
///
/// # Specification:
///
/// This function corresponds to the component "Byte Decomposition" of the
/// var-len Keccak spec.
pub fn byte_decomposition<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    field_element: &AssignedValue<F>,
) -> Vec<AssignedValue<F>>
where
    F: EccPrimeField,
{
    let mut byte_decomposition_powers = byte_decomposition_powers()
        .into_iter()
        .map(|power| QuantumCell::from(ctx.load_constant(power)))
        .collect_vec();
    byte_decomposition_powers.reverse();
    let byte_repr = field_element
        .value()
        .to_bytes_le()
        .into_iter()
        .rev()
        .map(|byte| F::from(byte as u64))
        .collect_vec();
    let assigned_repr = ctx.assign_witnesses(byte_repr);
    assert_byte_decomposition_is_in_field::<F, NUM_PARTS>(
        ctx,
        chip,
        assigned_repr.iter().rev(),
    );
    for byte in assigned_repr.iter() {
        chip.range_check(ctx, *byte, BYTE_SIZE_IN_BITS);
    }
    let result = chip.gate.inner_product(
        ctx,
        assigned_repr.clone().into_iter().map(QuantumCell::from),
        byte_decomposition_powers,
    );
    ctx.constrain_equal(field_element, &result);
    assigned_repr
}

/// Decomposes `field_elements` into bytes. Returns the concatenation
/// of their respective byte decompositions, in order.
pub fn byte_decomposition_list<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    field_elements: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>>
where
    F: EccPrimeField,
{
    field_elements
        .iter()
        .flat_map(|field_element| byte_decomposition(ctx, chip, field_element))
        .collect()
}

/// Converts [`NUM_LIMBS`] coordinate limbs to bytes, interpreted as the
/// big-endian byte representation of an `Fq` point. Each element of the
/// output is constrained to be a byte. Currently this function assumes
/// `LIMB_BITS = 88`, `NUM_LIMBS = 3`.
#[allow(clippy::assertions_on_constants)]
fn coordinate_limbs_to_bytes<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    coordinate_limbs: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>>
where
    F: EccPrimeField,
{
    assert!(
        LIMB_BITS == 88 && NUM_LIMBS == 3,
        "Unsupported limb decomposition"
    );
    assert_eq!(coordinate_limbs.len(), NUM_LIMBS, "Wrong number of limbs");
    // Note: All byte decompositions are big-endian, however the arrangement
    // of limbs is least-to-most significant.
    // For `NUM_LIMBS = 3, LIMB_BITS = 88`:
    // The big-endian bytes [b_0, ... , b_31] of a field element
    // are arranged in the limbs as
    // [0, ..., 0, b_21,  ... b_31]
    // [0, ..., 0, b_10,  ... b_20]
    // [0, ..., 0, 0, b_0 ... b_9]
    // (assuming `num_limbs = 3`, `limb_bits = 88`)
    // In the first two limbs, we take the last 11 bytes from each limb.
    // In the third limb, we take only the last 10 bytes.

    // num_zeroes takes the .rev() into account
    let num_zeroes = [22, 21, 21];
    let limbwise_bytes = coordinate_limbs
        .iter()
        .rev()
        .zip_eq(num_zeroes)
        .flat_map(|(limb, num_zeroes)| {
            let limb_byte_decomposition = byte_decomposition(ctx, chip, limb);
            limb_byte_decomposition.into_iter().skip(num_zeroes)
        })
        .collect_vec();

    assert_eq!(
        limbwise_bytes.len(),
        NUM_BYTES_FQ,
        "These bytes don't represent an Fq element"
    );
    limbwise_bytes
}

/// Converts `g1_point_limbs` to bytes, where `g1_point_limbs`
/// is the limb representation of a G1 affine point. Each element of the output
/// is constrained to be a byte.
pub fn g1_point_limbs_to_bytes<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    g1_point_limbs: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>>
where
    F: EccPrimeField,
{
    assert_eq!(g1_point_limbs.len(), NUM_LIMBS * 2, "Wrong number of limbs");
    multi_coordinates_to_bytes(ctx, chip, g1_point_limbs)
}

/// Converts `g2_point_limbs` to bytes, where `g2_point_limbs`
/// is the limb representation of a G1 affine point. Each element of the output
/// is constrained to be a byte.
pub fn g2_point_limbs_to_bytes<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    g2_point_limbs: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>>
where
    F: EccPrimeField,
{
    assert_eq!(g2_point_limbs.len(), NUM_LIMBS * 4, "Wrong number of limbs");
    multi_coordinates_to_bytes(ctx, chip, g2_point_limbs)
}

/// Converts `limbs` to bytes, where each chunk of [`NUM_LIMBS`] limbs is
/// understood as an `FQ` element.
pub(crate) fn multi_coordinates_to_bytes<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    limbs: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>>
where
    F: EccPrimeField,
{
    assert_eq!(limbs.len() % NUM_LIMBS, 0);
    limbs
        .iter()
        .chunks(NUM_LIMBS)
        .into_iter()
        .flat_map(|chunk| {
            coordinate_limbs_to_bytes(ctx, chip, &chunk.copied().collect_vec())
        })
        .collect()
}

/// Compute the proofId of an application proof.  Must match the method
/// `computeProofId` in the UPA contract.
pub fn compute_proof_id<'a, F: EccPrimeField>(
    circuit_id: &[u8; 32],
    app_public_inputs: impl IntoIterator<Item = &'a F>,
) -> [u8; 32] {
    let mut hasher = KeccakHasher::new();
    hasher.absorb_bytes(circuit_id);
    for pi in app_public_inputs {
        hasher.absorb_f(pi);
    }
    hasher.finalize()
}

/// Concatenate all bytes of `digests` and return Keccak digest.
/// Intended usage is for `digests` to be the proof IDs of all application
/// circuits contained in a given `OuterCircuit`.
pub fn compute_final_digest(
    proof_ids: impl IntoIterator<Item = impl Borrow<[u8; 32]>>,
) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();

    for pf_id in proof_ids {
        hasher.update(pf_id.borrow());
    }

    hasher.finalize(&mut output);
    output
}

/// Computes the Merkle leaf corresponding to `proof_id`.
fn compute_leaf(proof_id: impl Borrow<[u8; 32]>) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(proof_id.borrow());
    hasher.finalize(&mut leaf);
    leaf
}

/// Computes the keccak hash of `left` and `right`.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();

    hasher.update(left);
    hasher.update(right);

    hasher.finalize(&mut output);
    output
}

/// Hashes the elements of `row` by pairs.
fn hash_row(row: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut next_row = Vec::new();
    let row_len = row.len();
    for i in (0..row_len).step_by(2) {
        next_row.push(hash_pair(&row[i], &row[i + 1]));
    }
    next_row
}

/// Computes the submission id corresponding to `proof_ids`.
pub fn compute_submission_id(
    proof_ids: impl IntoIterator<Item = impl Borrow<[u8; 32]>>,
    num_proof_ids: u64,
) -> [u8; 32] {
    let num_proof_ids = num_proof_ids as usize;
    let next_power_of_two = num_proof_ids.next_power_of_two();
    let proof_ids = proof_ids
        .into_iter()
        .map(|proof_id| *proof_id.borrow())
        .collect_vec();
    let num_leaves = proof_ids.len();
    let proof_ids = proof_ids
        .into_iter()
        .take(num_proof_ids)
        .chain(iter::repeat([0u8; 32]).take(next_power_of_two - num_proof_ids))
        .collect_vec();
    let mut current_row = proof_ids.into_iter().map(compute_leaf).collect_vec();
    assert!(num_leaves >= next_power_of_two, "not enough leaves");
    assert_eq!(
        (num_leaves & (num_leaves - 1)),
        0,
        "The number of leaves must be a power of two in submission id mode"
    );

    while current_row.len() > 1 {
        current_row = hash_row(current_row);
    }

    current_row[0]
}

/// Compute the representation of a 32-byte Keccak digest as a pair of field
/// elements.  The elements are the low and high order 128-bit halves
/// (respectivaly) of the digest when interpretted as a 256-bit word.  Namely,
/// they are the (big-endian) integers encoded in the trailing and leading
/// (respectively) 16 bytes of the digest in memory.
/// See ``digestAsFieldElements` in `UpaLib.sol`.
///
/// NOTE: This is currently tied to bn256::Fr since `from_bytes`, `from_raw` etc
/// are just part of the impl, not part of any trait.
pub fn digest_as_field_elements(digest: &[u8; 32]) -> [Fr; 2] {
    let mut digest = *digest;
    digest.reverse();

    let l_bytes_0 = u64::from_le_bytes(digest[0..8].try_into().unwrap());
    let l_bytes_1 = u64::from_le_bytes(digest[8..16].try_into().unwrap());
    let h_bytes_0 = u64::from_le_bytes(digest[16..24].try_into().unwrap());
    let h_bytes_1 = u64::from_le_bytes(digest[24..32].try_into().unwrap());

    [
        Fr::from_raw([l_bytes_0, l_bytes_1, 0, 0]),
        Fr::from_raw([h_bytes_0, h_bytes_1, 0, 0]),
    ]
}

/// Composes `bytes` into a field element
pub fn compose_into_field_element<F: EccPrimeField>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    bytes: &[AssignedValue<F>; 32],
) -> AssignedValue<F> {
    let byte_decomposition_powers = byte_decomposition_powers()
        .into_iter()
        .rev()
        .map(|power| QuantumCell::from(ctx.load_constant(power)))
        .collect_vec();
    chip.gate.inner_product(
        ctx,
        bytes.iter().cloned().map(QuantumCell::from),
        byte_decomposition_powers,
    )
}

/// Encodes `bytes` as two 16-byte field elements. Each field element in `bytes`
/// is assumed to have been previously range checked.
///
/// # Specification
///
/// This function performs the encoding in **Final Digest Computation**
/// in the variable length keccak spec.
pub fn encode_digest_as_field_elements<F: EccPrimeField>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    bytes: &[AssignedValue<F>; NUM_BYTES_PER_FIELD_ELEMENT],
) -> [AssignedValue<F>; 2] {
    let byte_decomposition_powers = byte_decomposition_powers()
        .into_iter()
        .map(|power| QuantumCell::from(ctx.load_constant(power)))
        .collect_vec();
    let result = bytes
        .iter()
        .rev()
        .chunks(NUM_BYTES_PER_FIELD_ELEMENT / 2)
        .into_iter()
        .map(|chunk| {
            // Overflow is not possible here because:
            // 2^{8*15} (highest byte decomposition power)
            // * 2^8 (byte value upper bound)
            // * 2 (the rest of the terms together, at most, will equal the highest one)
            // = 2^129, which is strictly less than the modulus of F (approx. 2^254).
            chip.gate.inner_product(
                ctx,
                chunk.into_iter().cloned().map(QuantumCell::from),
                byte_decomposition_powers.clone(),
            )
        })
        .collect::<Vec<_>>();
    result
        .try_into()
        .expect("Conversion from vec into array is not allowed to fail")
}

/// Converts bytes into bits.
fn into_bits<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>>
where
    F: EccPrimeField,
{
    let mut assigned_bits: Vec<AssignedValue<F>> =
        Vec::with_capacity(bytes.len() * BYTE_SIZE_IN_BITS);
    for byte in bytes {
        assigned_bits.extend(chip.gate.num_to_bits(
            ctx,
            *byte,
            BYTE_SIZE_IN_BITS,
        ));
    }
    assigned_bits
}

/// Pads `bits` so its length becomes a multiple of `rate_in_bits`.
fn padding<F>(
    ctx: &mut Context<F>,
    bits: &mut Vec<AssignedValue<F>>,
    rate_in_bits: usize,
) where
    F: EccPrimeField,
{
    bits.push(ctx.load_constant(F::one()));
    while (bits.len() + 1) % rate_in_bits != 0 {
        bits.push(ctx.load_constant(F::zero()));
    }
    bits.push(ctx.load_constant(F::one()));
}

/// Packs a vector of padded `bits` into a word.
fn pack<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> AssignedValue<F>
where
    F: EccPrimeField,
{
    assert_eq!(bits.len(), 64, "Wrong number of bits");
    let base = ctx.load_constant(F::from(8u64));
    let initial_value = ctx.load_constant(F::zero());
    bits.iter().rev().fold(initial_value, |acc, bit| {
        chip.gate.mul_add(ctx, acc, base, *bit)
    })
}

/// Converts `bytes` to bits, pads them and packs them into 64-bit words.
///
/// # Specification
///
/// This function corresponds to the component **Bytes to keccak padded words**
/// in the variable length keccak spec.
pub fn bytes_to_keccak_padded_words<F>(
    ctx: &mut Context<F>,
    chip: &RangeChip<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>>
where
    F: EccPrimeField,
{
    let mut bits = into_bits(ctx, chip, bytes);
    padding(ctx, &mut bits, RATE_IN_BITS);
    let chunks = bits.chunks(RATE_IN_BITS);
    let mut result = Vec::new();
    for chunk in chunks {
        for idx in 0..NUM_WORDS_TO_ABSORB {
            result.push(pack(ctx, chip, &chunk[idx * 64..(idx + 1) * 64]));
        }
    }
    result
}

/// Returns the little endian bit decomposition of the next power of two
/// of `n` with `n_max_num_bits`.
pub fn compute_next_power_of_two_bit_decomposition<F: EccPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    n: AssignedValue<F>,
    n_max_num_bits: usize,
) -> Vec<AssignedValue<F>> {
    // First: compute and assign the witness
    let next_power_of_two_witness =
        n.value().get_lower_32().next_power_of_two();
    let next_power_of_two =
        ctx.load_witness(F::from(next_power_of_two_witness as u64));

    // Constrain the witness so `num_proof_ids <= next_power_of_two`
    range.range_check(ctx, n, n_max_num_bits);
    range.range_check(ctx, next_power_of_two, n_max_num_bits);
    let one = ctx.load_constant(F::one());
    let next_power_of_two_plus_one =
        range.gate.add(ctx, next_power_of_two, one);
    range.range_check(ctx, next_power_of_two_plus_one, n_max_num_bits + 1);
    range.check_less_than(
        ctx,
        n,
        next_power_of_two_plus_one,
        n_max_num_bits + 1,
    );

    // Constrain the witness so `previous_power_of_two < num_proof_ids`.
    // When `next_power_of_two = 1`, we take `previous_power_of_two = 0`
    let two = ctx.load_constant(F::from(2));
    let half_next_power_of_two =
        range.gate.div_unsafe(ctx, next_power_of_two, two);
    let is_one = range.gate.is_equal(ctx, next_power_of_two, one);
    let zero = ctx.load_constant(F::zero());
    let previous_power_of_two =
        range.gate.select(ctx, zero, half_next_power_of_two, is_one);
    range.check_less_than(ctx, previous_power_of_two, n, n_max_num_bits);

    // We decompose `next_power_of_two` into little-endian bits
    let bit_decomposition =
        range
            .gate
            .num_to_bits(ctx, next_power_of_two, n_max_num_bits);
    // We make sure it is a power of two, i.e., that exactly one of the entries
    // is 1 and the rest are zero.
    let sum = bit_decomposition
        .iter()
        .copied()
        .reduce(|a, b| range.gate.add(ctx, a, b))
        .expect("bit decomposition must have at least one element");
    ctx.constrain_equal(&sum, &one);
    bit_decomposition
}

/// The number of public inputs each application proof
/// contributes to the keccak circuit.
pub(crate) fn inputs_per_application_proof(num_pub_ins: usize) -> usize {
    // Keccak inputs contain for each application proof:
    // len_i, vk_limbs_i, has_commitment_i, commitment_hash_i, commitment_limbs_i, padded_inputs_i
    num_pub_ins
        + 3 // len + has_commitment + commitment_hash
        + NUM_LIMBS
            * (NUM_FQ_PER_G1AFFINE * 3 // alpha + s[0] + commitment_point
                + NUM_FQ_PER_G2AFFINE * 5 // beta + gamma + delta + h1 + h2
                + NUM_FQ_PER_G1AFFINE * num_pub_ins // s[1..]
                )
}

/// Given slice of `UniversalBatchVerifyCircuit` instances,
/// compute the appropriate keccak inputs.
pub fn keccak_inputs_from_ubv_instances<'a>(
    ubv_instances: impl ExactSizeIterator<Item = &'a [Fr]>,
    max_num_public_inputs: usize,
    inner_batch_size: usize,
) -> Vec<KeccakVarLenInput<Fr>> {
    let inputs_per_proof = inputs_per_application_proof(max_num_public_inputs);

    let mut keccak_inputs =
        Vec::with_capacity(ubv_instances.len() * inputs_per_proof);
    for instance in ubv_instances {
        assert_eq!(
            instance.len(),
            inputs_per_proof * inner_batch_size,
            "UBV instance length inconsistent with configuration"
        );
        for mut app_inputs in &instance.iter().chunks(inputs_per_proof) {
            let len = app_inputs
                .next()
                .expect("Missing input length")
                .get_lower_32() as usize;
            let app_vk_vec = app_inputs
                .by_ref()
                .take(NUM_LIMBS * (24 + 2 * max_num_public_inputs))
                .copied()
                .collect_vec();
            let has_commitment =
                *app_inputs.next().expect("Missing has commitment flag");
            let _ = *app_inputs.next().expect("Missing commitment hash");
            let commitment_point_limbs = app_inputs
                .by_ref()
                .take(NUM_LIMBS * 2)
                .copied()
                .collect_vec();
            let app_public_inputs =
                app_inputs.by_ref().take(len).copied().collect_vec();
            assert_eq!(
                commitment_point_limbs.len(),
                NUM_LIMBS * 2,
                "Missing commitment point limbs"
            );
            assert_eq!(app_public_inputs.len(), len, "Missing public inputs");

            // If the lth public input coincides with the commitment
            // hash, then this input has a commitment.
            const ZERO: Fr = Fr::zero();
            const ONE: Fr = Fr::one();
            let commitment_point_coordinates = {
                match has_commitment {
                    ZERO => vec![],
                    ONE => {
                        let commitment_point = limbs_into_g1affine(
                            &commitment_point_limbs,
                            LIMB_BITS,
                            NUM_LIMBS,
                        );
                        vec![[commitment_point.x, commitment_point.y]]
                    }
                    _ => panic!("has commitment can only be 0 or 1"),
                }
            };
            let has_commitment_bool = match has_commitment {
                ZERO => 0,
                _ => 1,
            };
            let len_s = len + 1 + has_commitment_bool;
            let mut app_vk = PaddedVerifyingKeyLimbs::from_limbs(
                &app_vk_vec,
                max_num_public_inputs + 1,
            )
            .vk();
            app_vk.s.drain(len_s..);
            if has_commitment_bool == 0 {
                app_vk.h1 = Vec::new();
                app_vk.h2 = Vec::new();
            }

            keccak_inputs.push(KeccakVarLenInput {
                app_vk,
                app_public_inputs,
                commitment_point_coordinates,
            })
        }
    }

    keccak_inputs
}

/// Produces a SNARK of the `KeccakCircuit`.
/// Use of `Shplonk` or `GWC` is specified by the types `P, V`.
///
/// Note: `P`, `V` are not constrained to be
/// consistent with each other.
pub fn gen_keccak_snark<'params, P, V>(
    params: &'params ParamsKZG<Bn256>,
    config: &KeccakConfig,
    inputs: &KeccakCircuitInputs<Fr>,
) -> Snark
where
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    let now = std::time::Instant::now();
    let (pk, break_points, gate_config) = gen_keccak_pk(params, config);
    info!("Generated Keccak PK in {:?}", now.elapsed());
    let now = std::time::Instant::now();
    let snark = gen_keccak_snark_with::<P, V>(
        params,
        config,
        &gate_config,
        inputs,
        &pk,
        break_points,
    );
    info!("Computed dummy Keccak snark in {:?}", now.elapsed());
    snark
}

/// Produces a SNARK of the `KeccakCircuit`.
/// Use of `Shplonk` or `GWC` is specified by the types `P, V`.
///
/// Note: `P`, `V` are not constrained to be
/// consistent with each other.
fn gen_keccak_snark_with<'params, P, V>(
    params: &'params ParamsKZG<Bn256>,
    config: &KeccakConfig,
    gate_config: &KeccakGateConfig,
    inputs: &KeccakCircuitInputs<Fr>,
    pk: &ProvingKey<G1Affine>,
    break_points: MultiPhaseThreadBreakPoints,
) -> Snark
where
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    let circuit = KeccakCircuit::<Fr, G1Affine>::prover(
        config,
        gate_config,
        break_points,
        inputs,
    );
    gen_snark::<_, P, V>(params, pk, circuit, None::<&str>)
}

/// Produces a SNARK of the `KeccakCircuit`.
/// Use of `Shplonk` or `GWC` is specified by the types `P, V`.
///
/// Note: `P`, `V` are not constrained to be
/// consistent with each other.
pub fn gen_keccak_pk(
    params: &ParamsKZG<Bn256>,
    config: &KeccakConfig,
) -> (
    ProvingKey<G1Affine>,
    MultiPhaseThreadBreakPoints,
    KeccakGateConfig,
) {
    let circuit = KeccakCircuit::<Fr, G1Affine>::keygen(config, &());
    let pk = gen_pk(params, &circuit, None);
    let break_points = circuit.break_points();
    (pk, break_points, circuit.gate_config().clone())
}
