use super::{LIMB_BITS, NUM_LIMBS};
use crate::{
    batch_verify::common::native::json::{
        field_element_from_str, g1_from_json,
    },
    utils::commitment_point::{
        be_bytes_to_field_element, commitment_hash_bytes_from_g1_point,
        commitment_hash_from_commitment_point_limbs, g1affine_into_limbs,
        limbs_into_g1affine,
    },
};
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Fr, G1Affine},
};
use rand_core::OsRng;

/// A [`G1Affine`] point.
pub const COMMITMENT_POINT: [&str; 2] =
["7856551849401418337206312780272143792992617682304676811898920167160475106147",
"7394615866234640375895482715703310589640913697951205795251091544235468188934"
];

/// These output bytes have been generated with the following solidity code:
/// `keccak256(abi.encodePacked(m[0], m[1]))`, where `m` is the G1Affine point
/// whose coordinates are [COMMITMENT_POINT].
pub const OUTPUT_BYTES: [u8; 32] = [
    0x1f, 0x9c, 0x1e, 0xcc, 0x84, 0x0b, 0x2e, 0x7a, 0x4e, 0x7c, 0xfc, 0xb9,
    0xb3, 0xa3, 0x2b, 0xf6, 0x0c, 0xf4, 0x21, 0x6d, 0x33, 0xce, 0xf6, 0x86,
    0x8d, 0x31, 0x7a, 0x67, 0xdd, 0x92, 0xfa, 0x11,
];

/// Field element representation of [`OUTPUT_BYTES`].
pub const FIELD_ELEMENT_HEX: &str =
    "0x1f9c1ecc840b2e7a4e7cfcb9b3a32bf60cf4216d33cef6868d317a67dd92fa11";

/// Interprets `COMMITMENT_POINT` as coordinates of a `G1` point.
pub fn parse_commitment_point() -> G1Affine {
    g1_from_json(&[
        COMMITMENT_POINT[0].to_string(),
        COMMITMENT_POINT[1].to_string(),
    ])
}

/// Tests that [`commitment_hash_bytes_from_g1_point`] and [`be_bytes_to_field_element`]
/// return the right value for a known input-output pair.
#[test]
fn test_input_bytes_from_commitment_point() {
    // Load the G1Affine point from the file
    let commitment_point = parse_commitment_point();

    // Compute the output bytes and compare
    let output_bytes = commitment_hash_bytes_from_g1_point(&commitment_point);
    assert_eq!(output_bytes, OUTPUT_BYTES, "Output bytes mismatch");

    // Compute the field element and compare
    let expected_field_element =
        field_element_from_str::<Fr>(FIELD_ELEMENT_HEX);
    let field_element = be_bytes_to_field_element(&OUTPUT_BYTES);
    assert_eq!(
        expected_field_element, field_element,
        "Field element mismatch"
    );
}

/// Tests [`commitment_hash_from_commitment_point_limbs`] returns the
/// expected value.
#[test]
fn test_commitment_hash_from_limbs() {
    let commitment_point = parse_commitment_point();
    let commitment_point_limbs =
        g1affine_into_limbs::<Fr>(&commitment_point, LIMB_BITS, NUM_LIMBS);
    let output_element = commitment_hash_from_commitment_point_limbs(
        &commitment_point_limbs,
        LIMB_BITS,
        NUM_LIMBS,
    );
    let expected_field_element =
        field_element_from_str::<Fr>(FIELD_ELEMENT_HEX);
    assert_eq!(
        output_element, expected_field_element,
        "Field element mismatch"
    );
}

/// Checks [`g1affine_into_limbs`] and [`limbs_into_g1affine`] are each other's inverse.
#[test]
fn test_conversion_to_and_from_limbs() {
    let g1_generator = G1Affine::generator();
    let scalar = Fr::random(OsRng);
    let g1_point = G1Affine::from(g1_generator * scalar);
    let limbs = g1affine_into_limbs::<Fr>(&g1_point, LIMB_BITS, NUM_LIMBS);
    let reconstructed_g1_point =
        limbs_into_g1affine(&limbs, LIMB_BITS, NUM_LIMBS);
    assert_eq!(g1_point, reconstructed_g1_point, "g1 point mismatch");
}
