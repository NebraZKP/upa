use crate::{
    batch_verify::{
        common::native::json::field_element_from_str,
        universal::native::compute_circuit_id,
    },
    keccak::{
        inputs::KeccakCircuitInputs,
        utils::{
            assert_byte_decomposition_is_in_field, byte_decomposition,
            byte_decomposition_powers, compose_into_field_element,
            compute_final_digest, compute_proof_id, digest_as_field_elements,
            encode_digest_as_field_elements, field_max_element_into_parts,
            g1_point_limbs_to_bytes,
        },
        KeccakCircuit, KeccakConfig, KeccakPaddedCircuitInputs,
        KECCAK_LOOKUP_BITS, LIMB_BITS, NUM_LIMBS,
    },
    tests::{
        commitment_point::{
            parse_commitment_point, FIELD_ELEMENT_HEX, OUTPUT_BYTES,
        },
        load_proof_and_inputs, load_vk,
    },
    utils::commitment_point::{self, g1affine_into_limbs},
    EccPrimeField, SafeCircuit,
};
use halo2_base::{
    gates::builder::GateThreadBuilder,
    halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine},
    safe_types::RangeChip,
};
use hex::ToHex;
use itertools::Itertools;
use rand::Rng;
use rand_core::OsRng;

/// Max vector length for tests to prevent overflow.
const MAX_VEC_LEN: u64 = 200;

/// Ensures that the native proofId calculation matches the test vectors from
/// the UPA contract.  See`/upa/test/upa*` files for details of
/// the test vector.
#[test]
pub fn test_compute_proof_id_vectors() {
    let circuit_id: [u8; 32] = hex::decode(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap()
    .try_into()
    .unwrap();

    // 0 PIs
    {
        let app_pi: Vec<Fr> = vec![];
        let expect_proof_id: [u8; 32] = [
            0xb1, 0x0e, 0x2d, 0x52, 0x76, 0x12, 0x07, 0x3b, //
            0x26, 0xee, 0xcd, 0xfd, 0x71, 0x7e, 0x6a, 0x32, //
            0x0c, 0xf4, 0x4b, 0x4a, 0xfa, 0xc2, 0xb0, 0x73, //
            0x2d, 0x9f, 0xcb, 0xe2, 0xb7, 0xfa, 0x0c, 0xf6,
        ];
        let proof_id = compute_proof_id(&circuit_id, &app_pi);
        assert_eq!(expect_proof_id, proof_id.as_slice(), "0 pis");
    }

    // 1 PIs
    {
        let app_pi = [Fr::from(2)];
        let expect_proof_id: [u8; 32] = [
            0xe9, 0x0b, 0x7b, 0xce, 0xb6, 0xe7, 0xdf, 0x54, //
            0x18, 0xfb, 0x78, 0xd8, 0xee, 0x54, 0x6e, 0x97, //
            0xc8, 0x3a, 0x08, 0xbb, 0xcc, 0xc0, 0x1a, 0x06, //
            0x44, 0xd5, 0x99, 0xcc, 0xd2, 0xa7, 0xc2, 0xe0,
        ];
        let proof_id = compute_proof_id(&circuit_id, &app_pi);
        assert_eq!(expect_proof_id, proof_id.as_slice());
        assert_eq!(expect_proof_id, proof_id.as_slice(), "1 pis");
    }

    // 2 PIs
    {
        let app_pi = [Fr::from(2), Fr::from(3)];
        let expect_proof_id: [u8; 32] = [
            0x6e, 0x0c, 0x62, 0x79, 0x00, 0xb2, 0x4b, 0xd4, //
            0x32, 0xfe, 0x7b, 0x1f, 0x71, 0x3f, 0x1b, 0x07, //
            0x44, 0x09, 0x1a, 0x64, 0x6a, 0x9f, 0xe4, 0xa6, //
            0x5a, 0x18, 0xdf, 0xed, 0x21, 0xf2, 0x94, 0x9c,
        ];
        let proof_id = compute_proof_id(&circuit_id, &app_pi);
        assert_eq!(expect_proof_id, proof_id.as_slice());
        assert_eq!(expect_proof_id, proof_id.as_slice(), "2 pis");
    }

    // 3 PIs
    {
        let app_pi =
            [Fr::from(2), Fr::from(3), Fr::from(2).pow(&[128, 0, 0, 0])];
        let expect_proof_id: [u8; 32] = [
            0x39, 0x23, 0x5a, 0xb0, 0xd4, 0x13, 0xc4, 0x0e, //
            0x06, 0x3c, 0xde, 0xbb, 0x9c, 0x8c, 0x3f, 0x14, //
            0x07, 0xbf, 0x56, 0x22, 0x59, 0x78, 0x31, 0x33, //
            0x3a, 0xcb, 0x1f, 0x64, 0xf0, 0x52, 0x21, 0x6b,
        ];
        let proof_id = compute_proof_id(&circuit_id, &app_pi);
        assert_eq!(expect_proof_id, proof_id.as_slice(), "3 pis");
    }

    // 4 PIs
    {
        let app_pi = [
            Fr::from(2),
            Fr::from(3),
            Fr::from(2).pow(&[128, 0, 0, 0]),
            Fr::from(2).pow(&[253, 0, 0, 0]),
        ];
        // 0x227ba65a7f156e2a72f88325abe99b31b0c5bd09eec1499eb48617aaa2d33fb7
        let expect_proof_id: [u8; 32] = [
            0x22, 0x7b, 0xa6, 0x5a, 0x7f, 0x15, 0x6e, 0x2a, //
            0x72, 0xf8, 0x83, 0x25, 0xab, 0xe9, 0x9b, 0x31, //
            0xb0, 0xc5, 0xbd, 0x09, 0xee, 0xc1, 0x49, 0x9e, //
            0xb4, 0x86, 0x17, 0xaa, 0xa2, 0xd3, 0x3f, 0xb7,
        ];
        let proof_id = compute_proof_id(&circuit_id, &app_pi);
        assert_eq!(expect_proof_id, proof_id.as_slice(), "4 pis");
    }
}

/// Ensures that the native digest decomposition matches the test vectors from
/// the UPA contract.  See`/contracts/test/upa*` files for details of
/// the test vector.
#[test]
pub fn test_compute_digest_decomposition() {
    // The final digest from the proofId calculation should decompose into field elements:
    //
    //   l = 0xb0c5bd09eec1499eb48617aaa2d33fb7;
    //   h = 0x227ba65a7f156e2a72f88325abe99b31;
    //
    // Note that these have to be reversed to form the LE representation.

    let digest: [u8; 32] = [
        0x22, 0x7b, 0xa6, 0x5a, 0x7f, 0x15, 0x6e, 0x2a, //
        0x72, 0xf8, 0x83, 0x25, 0xab, 0xe9, 0x9b, 0x31, //
        0xb0, 0xc5, 0xbd, 0x09, 0xee, 0xc1, 0x49, 0x9e, //
        0xb4, 0x86, 0x17, 0xaa, 0xa2, 0xd3, 0x3f, 0xb7,
    ];
    let expect_l = Fr::from_raw([0xb48617aaa2d33fb7, 0xb0c5bd09eec1499e, 0, 0]);
    let expect_h = Fr::from_raw([0x72f88325abe99b31, 0x227ba65a7f156e2a, 0, 0]);

    let [l, h] = digest_as_field_elements(&digest);
    assert_eq!(expect_l, l);
    assert_eq!(expect_h, h);
}

/// Checks [`digest_as_field_elements`] and [`compose_into_field_elements`] return the same result.
#[test]
fn composition_test() {
    let mut builder = GateThreadBuilder::<Fr>::mock();
    let ctx = builder.main(0);
    let range_chip = RangeChip::default(8);
    let mut rng = OsRng;
    let sampled_bytes: [u8; 32] = rng.gen();
    let sampled_field_elements = sampled_bytes
        .into_iter()
        .map(|byte| Fr::from_u128(byte as u128))
        .collect::<Vec<_>>();
    let assigned_field_elements = ctx
        .assign_witnesses(sampled_field_elements)
        .try_into()
        .unwrap();
    let digest_result = digest_as_field_elements(&sampled_bytes);
    let compose_result = encode_digest_as_field_elements(
        ctx,
        &range_chip,
        &assigned_field_elements,
    )
    .map(|assigned| *assigned.value());
    assert_eq!(digest_result, compose_result, "Composition mismatch");
}

/// Computes and outputs the proof_id of the proofs in the test data.  Primary
/// purpose is to produce text vectors for implementations in other languages.
#[test]
#[ignore = "does nothing"]
pub fn test_compute_proof_id_test_vector() {
    // Compute the proof id for proof1, proof2 and proof3 in the test data
    let vk = load_vk("src/tests/data/vk.json");
    let vk_hash = compute_circuit_id(&vk);

    let proofs = vec![
        "src/tests/data/proof1.json",
        "src/tests/data/proof2.json",
        "src/tests/data/proof3.json",
    ];
    for pf_file in proofs {
        let p_i = load_proof_and_inputs(pf_file);
        let pid = compute_proof_id(&vk_hash, &p_i.1 .0);
        println!("{pf_file}: {}", pid.encode_hex::<String>());
    }
}

/// Using the proofIds from test_compute_proof_id_test_vector, compute a test
/// vector for final digest.  This is chosen to match the test data for a batch
/// of 2 proofs (tests/data/proof_batch_2.json).
#[test]
#[ignore = "does nothing"]
pub fn test_compute_final_digest_test_vector() {
    // From test_compute_proof_id_test_data_proof:
    //   proof1.json id: 096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f
    //   proof3.json id: 4908a0d394b509bb1543ee49ceb56d5385b583bcabc8bb4c2d726396ac135a9b
    //
    // proof2 is not used in the particular proof batch considered here.

    let pid1: [u8; 32] = [
        0x09, 0x6b, 0x71, 0x95, 0x8a, 0x31, 0xf9, 0x19, 0x87, 0x21, 0xfd, 0xba,
        0xe1, 0xb6, 0x97, 0xa4, 0x84, 0x5e, 0xa3, 0x9d, 0x31, 0xcf, 0x34, 0xea,
        0x53, 0x24, 0xe7, 0x16, 0xb4, 0x8e, 0x76, 0x5f,
    ];
    let pid3: [u8; 32] = [
        0x49, 0x08, 0xa0, 0xd3, 0x94, 0xb5, 0x09, 0xbb, 0x15, 0x43, 0xee, 0x49,
        0xce, 0xb5, 0x6d, 0x53, 0x85, 0xb5, 0x83, 0xbc, 0xab, 0xc8, 0xbb, 0x4c,
        0x2d, 0x72, 0x63, 0x96, 0xac, 0x13, 0x5a, 0x9b,
    ];

    // Print the digests for batches:
    //   [[1,1],[1,1]], and
    //   [[1,3],[1,3]]
    let digest1 = compute_final_digest([pid1, pid1, pid1, pid1]);
    println!(
        "final digest ([[p1, p1], [p1, p1]]): {}",
        digest1.encode_hex::<String>()
    );
    let digest2 = compute_final_digest([pid1, pid3, pid1, pid3]);
    println!(
        "final digest ([[p1, p3], [p1, p3]]): {}",
        digest2.encode_hex::<String>()
    );
}

#[test]
fn keccak_var_len_input_serialization() {
    const DEFAULT_DEGREE_BITS: u32 = 20;
    let mut rng = OsRng;
    let num_app_public_inputs = 20u32;
    let config = KeccakConfig {
        degree_bits: DEFAULT_DEGREE_BITS,
        inner_batch_size: 1,
        outer_batch_size: 1,
        num_app_public_inputs,
        lookup_bits: KECCAK_LOOKUP_BITS,
        output_submission_id: false, // Irrelevant for this test
    };
    let mut inputs = KeccakCircuitInputs::<Fr>::sample(&config, &mut rng);
    inputs.inputs[0]
        .commitment_point_coordinates
        .push([Fq::random(rng), Fq::random(rng)]);

    let inputs_serialized = serde_json::to_string_pretty(&inputs).expect("");
    let inputs_deserialized: KeccakCircuitInputs<Fr> =
        serde_json::from_str(&inputs_serialized).unwrap();
    assert_eq!(inputs, inputs_deserialized)
}

/// Checks the [`KeccakCircuit`] computes circuitIds and proofIds correctly by
/// comparing them to the output of [`compute_circuit_id`] and [`compute_proof_id`],
/// respectively.
#[test]
fn circuit_id_and_proof_id_test() {
    const DEFAULT_DEGREE_BITS: u32 = 20;
    let mut rng = OsRng;
    let num_app_public_inputs = rng.gen_range(1..MAX_VEC_LEN) as u32;
    // We use a circuit with only one application circuit as input
    let config = KeccakConfig {
        degree_bits: DEFAULT_DEGREE_BITS,
        inner_batch_size: 1,
        outer_batch_size: 1,
        num_app_public_inputs,
        lookup_bits: KECCAK_LOOKUP_BITS,
        output_submission_id: false, // Irrelevant for this test
    };
    let keccak_inputs = KeccakCircuitInputs::sample(&config, &mut rng);
    let circuit_inputs = KeccakPaddedCircuitInputs::from_keccak_circuit_inputs(
        &keccak_inputs,
        num_app_public_inputs as usize,
    );

    let number_of_field_elements = circuit_inputs.0[0].num_field_elements();
    let circuit_id = compute_circuit_id(&keccak_inputs.inputs[0].app_vk);
    let proof_id = compute_proof_id(
        &circuit_id,
        &circuit_inputs.0[0].app_public_inputs[..number_of_field_elements],
    )
    .to_vec();
    // Creating the circuit computes automatically the byte decomposition of
    // `public_inputs` as well as their keccak. We don't intend to run this
    // circuit.
    let circuit = KeccakCircuit::<Fr, G1Affine>::mock(&config, &keccak_inputs);
    // This is the location of the keccak of the first chunk of public inputs
    // (in our case the only one).
    let circuit_output_circuit_id = circuit.keccak_output_bytes()[0..32]
        .iter()
        .map(|assigned_value| assigned_value.value().to_bytes()[0])
        .collect::<Vec<_>>();
    assert_eq!(
        circuit_id.to_vec(),
        circuit_output_circuit_id,
        "Circuit id mismatch"
    );
    let circuit_output_proof_id = circuit.keccak_output_bytes()[32..64]
        .iter()
        .map(|assigned_value| assigned_value.value().to_bytes()[0])
        .collect::<Vec<_>>();
    assert_eq!(proof_id, circuit_output_proof_id, "Proof id mismatch");
}

/// Tests [`field_max_element_into_parts`] returns the right decomposition.
#[test]
fn test_field_modulus_parts() {
    let field_modulus_two_halves = field_max_element_into_parts::<Fr, 2>();
    let powers = byte_decomposition_powers::<Fr>();
    let fr_minus_one = Fr::zero() - Fr::one();
    assert_eq!(
        fr_minus_one,
        field_modulus_two_halves[0] + field_modulus_two_halves[1] * powers[16]
    );
}

/// Tests [`assert_byte_decomposition_is_in_field`] on some select values, namely:
/// - `0`, `1`, `r-1`: should succeed
/// - `r`, `r+1`, `0xffff...` : should fail
fn test_assert_is_in_field_for_num_parts<const NUM_PARTS: usize>() {
    let mut builder = GateThreadBuilder::<Fr>::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::<Fr>::default(8);

    let zero = ctx.load_constant(Fr::zero());
    let zero_bytes = byte_decomposition(ctx, &chip, &zero);
    assert!(assert_byte_decomposition_is_in_field::<Fr, NUM_PARTS>(
        ctx,
        &chip,
        zero_bytes.iter().rev(),
    ));

    let one = ctx.load_constant(Fr::one());
    let one_bytes = byte_decomposition(ctx, &chip, &one);
    assert!(assert_byte_decomposition_is_in_field::<Fr, NUM_PARTS>(
        ctx,
        &chip,
        one_bytes.iter().rev(),
    ));

    let r_minus_one = ctx.load_constant(Fr::zero() - Fr::one());
    let r_minus_one_bytes = byte_decomposition(ctx, &chip, &r_minus_one);
    assert!(assert_byte_decomposition_is_in_field::<Fr, NUM_PARTS>(
        ctx,
        &chip,
        r_minus_one_bytes.iter().rev(),
    ));

    let mut r_bytes = r_minus_one_bytes;
    assert_ne!(
        r_bytes[31].value().get_lower_32(),
        u8::MAX as u32,
        "The least significant byte of r-1 isn't 255"
    );
    r_bytes[31] = ctx.load_constant(r_bytes[31].value() + Fr::one());
    assert!(!assert_byte_decomposition_is_in_field::<Fr, NUM_PARTS>(
        ctx,
        &chip,
        r_bytes.iter().rev(),
    ));

    let mut r_plus_one_bytes = r_bytes;
    assert_ne!(
        r_plus_one_bytes[31].value().get_lower_32(),
        u8::MAX as u32,
        "The least significant byte of r isn't 255"
    );
    r_plus_one_bytes[31] =
        ctx.load_constant(r_plus_one_bytes[31].value() + Fr::one());
    assert!(!assert_byte_decomposition_is_in_field::<Fr, NUM_PARTS>(
        ctx,
        &chip,
        r_plus_one_bytes.iter().rev(),
    ));

    let max_bytes = core::iter::repeat(u8::MAX)
        .take(32)
        .map(|byte| ctx.load_constant(Fr::from(byte as u64)))
        .collect_vec();
    assert!(!assert_byte_decomposition_is_in_field::<Fr, NUM_PARTS>(
        ctx,
        &chip,
        max_bytes.iter().rev(),
    ));
}

/// Runs [`test_assert_is_in_field_for_num_parts`] for all `NUM_PARTS`
/// dividing 32.
#[test]
fn test_assert_is_in_field() {
    test_assert_is_in_field_for_num_parts::<2>();
    test_assert_is_in_field_for_num_parts::<4>();
    test_assert_is_in_field_for_num_parts::<8>();
    test_assert_is_in_field_for_num_parts::<16>();
    test_assert_is_in_field_for_num_parts::<32>();
}

/// Checks that [`commitment_point_limbs_to_bytes`] returns the right result.
#[test]
fn test_commitment_point_limbs_to_bytes() {
    let mut builder = GateThreadBuilder::<Fr>::mock();
    let ctx = builder.main(0);
    let range = RangeChip::default(8);
    let commitment_point = parse_commitment_point();
    let commitment_point_limbs =
        g1affine_into_limbs(&commitment_point, LIMB_BITS, NUM_LIMBS);
    let native_commitment_bytes =
        commitment_point::commitment_point_limbs_to_bytes(
            &commitment_point_limbs[..],
            LIMB_BITS,
            NUM_LIMBS,
        );
    let assigned_commitment_point_limbs =
        ctx.assign_witnesses(commitment_point_limbs);
    let assigned_bytes =
        g1_point_limbs_to_bytes(ctx, &range, &assigned_commitment_point_limbs);
    let assigned_commitment_bytes = assigned_bytes
        .iter()
        .map(|byte| byte.value().get_lower_32() as u8)
        .collect_vec();
    assert_eq!(
        assigned_commitment_bytes, native_commitment_bytes,
        "Commitment bytes mismatch"
    );
}

/// Checks that [`compose_into_field_element`] computes the right result.
#[test]
fn test_compose_into_field_element() {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let bytes =
        OUTPUT_BYTES.map(|byte| ctx.load_witness(Fr::from(byte as u64)));
    let range = RangeChip::default(8);
    let field_element = compose_into_field_element(ctx, &range, &bytes);
    let expected_element = field_element_from_str::<Fr>(FIELD_ELEMENT_HEX);
    assert_eq!(
        field_element.value(),
        &expected_element,
        "Field element mismatch"
    );
}
