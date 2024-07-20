//! Pedersen commitment point utilities

use crate::{
    batch_verify::common::ecc::{G1InputPoint, G2InputPoint},
    utils::hashing::FieldElementRepresentation,
    EccPrimeField,
};
use ethers_core::utils::keccak256;
use halo2_base::{
    halo2_proofs::{
        arithmetic::CurveAffine,
        halo2curves::bn256::{Fq, Fq2, G1Affine, G2Affine},
    },
    utils::{decompose_biguint, fe_to_biguint, CurveAffineExt},
    AssignedValue,
};
use itertools::Itertools;

/// Number of bytes in an Fq element
const NUM_BYTES_FQ: usize = 32;

/// Constructs a field element from a big endian array of 32 `bytes`.
/// The resulting field element equals `\sum_i 2^[31-i] * bytes[i] % F::MODULUS`.
pub fn be_bytes_to_field_element<F, const NUM_BYTES: usize>(
    bytes: &[u8; NUM_BYTES],
) -> F
where
    F: EccPrimeField,
{
    let num_bytes: usize = ((F::NUM_BITS + 7) / 8) as usize;
    assert!(num_bytes == NUM_BYTES);
    let mut le_bytes = *bytes;
    le_bytes.reverse();
    let mut new_input_bytes = [0u8; 64];
    new_input_bytes[..32].copy_from_slice(&le_bytes);
    F::from_bytes_wide(&new_input_bytes)
}

/// Computes the commitment hash bytes from `m`.
pub fn commitment_hash_bytes_from_g1_point(m: &G1Affine) -> [u8; 32] {
    let (m_x, m_y) = m.into_coordinates();
    let m_bytes = m_x
        .to_bytes()
        .into_iter()
        .rev()
        .chain(m_y.to_bytes().into_iter().rev())
        .collect_vec();
    keccak256(m_bytes)
}

/// Decomposes `m` into `num_limbs` limbs.
pub fn get_g1_point_limbs<F: EccPrimeField>(
    m: &G1InputPoint<F>,
    num_limbs: usize,
) -> Vec<AssignedValue<F>> {
    let result = m.representation();
    assert_eq!(
        result.len(),
        2 * num_limbs,
        "Number of limbs incompatible with the config"
    );
    result
}

/// Decomposes `m` into `num_limbs` limbs.
pub fn get_g2_point_limbs<F: EccPrimeField>(
    m: &G2InputPoint<F>,
    num_limbs: usize,
) -> Vec<AssignedValue<F>> {
    let result = m.representation();
    assert_eq!(
        result.len(),
        4 * num_limbs,
        "Number of limbs incompatible with the config"
    );
    result
}

/// Decomposes `m` into `num_limbs` limbs of size `limb_bits`.
pub fn g1affine_into_limbs<F: EccPrimeField>(
    m: &G1Affine,
    limb_bits: usize,
    num_limbs: usize,
) -> Vec<F> {
    let mut x_coordinate =
        decompose_biguint(&fe_to_biguint(&m.x), num_limbs, limb_bits);
    let mut y_coordinate =
        decompose_biguint(&fe_to_biguint(&m.y), num_limbs, limb_bits);
    x_coordinate.append(&mut y_coordinate);
    x_coordinate
}

/// Decomposes `m` into `num_limbs` limbs of size `limb_bits`.
pub fn g2affine_into_limbs<F: EccPrimeField>(
    m: &G2Affine,
    limb_bits: usize,
    num_limbs: usize,
) -> Vec<F> {
    let mut x_0_coordinate =
        decompose_biguint(&fe_to_biguint(&m.x.c0), num_limbs, limb_bits);
    let mut x_1_coordinate =
        decompose_biguint(&fe_to_biguint(&m.x.c1), num_limbs, limb_bits);
    let mut y_0_coordinate =
        decompose_biguint(&fe_to_biguint(&m.y.c0), num_limbs, limb_bits);
    let mut y_1_coordinate =
        decompose_biguint(&fe_to_biguint(&m.y.c1), num_limbs, limb_bits);
    x_0_coordinate.append(&mut x_1_coordinate);
    x_0_coordinate.append(&mut y_0_coordinate);
    x_0_coordinate.append(&mut y_1_coordinate);
    x_0_coordinate
}

/// Converts `limbs` into the [`G1Affine`] point they represent.
pub fn limbs_into_g1affine<F: EccPrimeField>(
    limbs: &[F],
    limb_bits: usize,
    num_limbs: usize,
) -> G1Affine {
    let mut x_coordinate_bytes =
        coordinate_limbs_to_bytes(&limbs[..num_limbs], limb_bits, num_limbs);
    x_coordinate_bytes.reverse();
    let x = Fq::from_bytes_le(&x_coordinate_bytes);
    let mut y_coordinate_bytes =
        coordinate_limbs_to_bytes(&limbs[num_limbs..], limb_bits, num_limbs);
    y_coordinate_bytes.reverse();
    let y = Fq::from_bytes_le(&y_coordinate_bytes);

    let result = G1Affine { x, y };
    assert!(
        bool::from(result.is_on_curve()),
        "Limbs do not represent a G1 affine point"
    );
    result
}

/// Converts `limbs` into the [`G2Affine`] point they represent.
pub fn limbs_into_g2affine<F: EccPrimeField>(
    limbs: &[F],
    limb_bits: usize,
    num_limbs: usize,
) -> G2Affine {
    let mut x_0_coordinate_bytes =
        coordinate_limbs_to_bytes(&limbs[..num_limbs], limb_bits, num_limbs);
    x_0_coordinate_bytes.reverse();
    let x_0 = Fq::from_bytes_le(&x_0_coordinate_bytes);
    let mut x_1_coordinate_bytes = coordinate_limbs_to_bytes(
        &limbs[num_limbs..2 * num_limbs],
        limb_bits,
        num_limbs,
    );
    x_1_coordinate_bytes.reverse();
    let x_1 = Fq::from_bytes_le(&x_1_coordinate_bytes);
    let mut y_0_coordinate_bytes = coordinate_limbs_to_bytes(
        &limbs[2 * num_limbs..3 * num_limbs],
        limb_bits,
        num_limbs,
    );
    y_0_coordinate_bytes.reverse();
    let y_0 = Fq::from_bytes_le(&y_0_coordinate_bytes);
    let mut y_1_coordinate_bytes = coordinate_limbs_to_bytes(
        &limbs[3 * num_limbs..],
        limb_bits,
        num_limbs,
    );
    y_1_coordinate_bytes.reverse();
    let y_1 = Fq::from_bytes_le(&y_1_coordinate_bytes);

    let result = G2Affine {
        x: Fq2 { c0: x_0, c1: x_1 },
        y: Fq2 { c0: y_0, c1: y_1 },
    };
    assert!(
        bool::from(result.is_on_curve()),
        "Limbs do not represent a G1 affine point"
    );
    result
}

/// Converts `limbs` into [`NUM_BYTES_FQ`] bytes, asserting the extra bytes
/// in the limbs are zero.
fn coordinate_limbs_to_bytes<F: EccPrimeField>(
    limbs: &[F],
    limb_bits: usize,
    num_limbs: usize,
) -> Vec<u8> {
    assert_eq!(
        limbs.len(),
        num_limbs,
        "Limbs do not represent an Fq element"
    );
    assert_eq!(limb_bits % 8, 0, "limb bits must be a multiple of 8");
    let limb_bytes = limb_bits / 8;
    let num_zeroes_per_limb = NUM_BYTES_FQ - limb_bytes;
    let remainder = limb_bytes * num_limbs % NUM_BYTES_FQ;

    let mut num_zeroes = vec![num_zeroes_per_limb; num_limbs];
    num_zeroes[0] += remainder;

    let result = limbs
        .iter()
        .rev()
        .zip_eq(num_zeroes)
        .flat_map(|(limb, num_zeroes)| {
            let mut limb_be_bytes = limb.to_bytes_le().into_iter().rev();
            assert!(
                limb_be_bytes
                    .by_ref()
                    .take(num_zeroes)
                    .all(|byte| byte == 0),
                "Extra bytes in limbs must be zero"
            );
            limb_be_bytes
        })
        .collect_vec();
    assert_eq!(result.len(), NUM_BYTES_FQ, "Wrong number of bytes");
    result
}

/// Converts `limbs` to bytes, where `limbs` represent an elliptic curve point.
pub fn commitment_point_limbs_to_bytes<F: EccPrimeField>(
    limbs: &[F],
    limb_bits: usize,
    num_limbs: usize,
) -> Vec<u8> {
    assert_eq!(
        limbs.len(),
        num_limbs * 2,
        "Limbs do not represent an elliptic curve point"
    );
    let mut coordinate_x =
        coordinate_limbs_to_bytes(&limbs[..num_limbs], limb_bits, num_limbs);
    let mut coordinate_y =
        coordinate_limbs_to_bytes(&limbs[num_limbs..], limb_bits, num_limbs);
    coordinate_x.append(&mut coordinate_y);

    coordinate_x
}

/// Computes the commitment hash from `limbs`, which represent an elliptic curve
/// point.
pub fn commitment_hash_from_commitment_point_limbs<F: EccPrimeField>(
    limbs: &[F],
    limb_bits: usize,
    num_limbs: usize,
) -> F {
    let input_bytes =
        commitment_point_limbs_to_bytes(limbs, limb_bits, num_limbs);
    let commitment_hash_bytes = keccak256(input_bytes);
    be_bytes_to_field_element(&commitment_hash_bytes)
}
