//! Native implementation of the algorithm in `FixedBatchVerifyCircuit`
use crate::{
    batch_verify::{
        common::{
            native::{
                compute_vk_keccak_hash_with_domain_tag,
                compute_vk_poseidon_hash,
            },
            types::{Proof, PublicInputs, VerificationKey},
        },
        fixed::types::{
            UPA_V0_9_0_CHALLENGE_DOMAIN_TAG_STRING,
            UPA_V0_9_0_CIRCUITID_DOMAIN_TAG_STRING,
        },
    },
    utils::hashing::WrongFieldHasher,
    CircuitWithLimbsConfig, EccPrimeField,
};
use core::iter::once;
use halo2_base::{
    halo2_proofs::halo2curves::{
        bn256::{
            multi_miller_loop, Fr, G1Affine, G2Affine, G2Prepared, Gt, G1,
        },
        pairing::MillerLoopResult,
    },
    utils::CurveAffineExt,
};
use halo2_ecc::fields::FieldExtConstructor;

/// "Prepared" here means that all curve points have been accumulated and we
/// have a sequence of pairs of G1 and G2 points ready for passing to a
/// multi-Miller loop.
pub(crate) struct PreparedProof {
    /// Rescaled pairs (r^i * A_i, B_i)
    pub ab_pairs: Vec<(G1Affine, G2Affine)>,
    /// (-sum_i r^i * P, Q)
    pub rp: (G1Affine, G2Affine),
    /// (-PI, h)
    pub pi: (G1Affine, G2Affine),
    /// (- sum_i r^i C_i, D)
    pub zc: (G1Affine, G2Affine),
}

pub(crate) fn prepare_public_inputs(
    vk: &VerificationKey,
    inputs: &PublicInputs,
) -> G1Affine {
    let mut pi = G1::from(vk.s[0]);
    for i in 0..inputs.0.len() {
        pi += vk.s[i + 1] * inputs.0[i];
    }
    G1Affine::from(pi)
}

pub(crate) fn pairing(pairs: &[(&G1Affine, &G2Affine)]) -> Gt {
    // Store the prepared G2 elements, so we can create references to them.
    let prepared_g2: Vec<G2Prepared> =
        pairs.iter().map(|(_, b)| G2Prepared::from(**b)).collect();
    let pairs: Vec<(&G1Affine, &G2Prepared)> = pairs
        .iter()
        .zip(prepared_g2.iter())
        .map(|((a, _), b)| (*a, b))
        .collect();
    let miller_out = multi_miller_loop(pairs.as_slice());
    miller_out.final_exponentiation()
}

pub(crate) fn check_pairing(pairs: &[(&G1Affine, &G2Affine)]) -> bool {
    let pairing_out = pairing(pairs);
    pairing_out == Gt::identity()
}

pub fn verify(
    vk: &VerificationKey,
    proof: &Proof,
    inputs: &PublicInputs,
) -> bool {
    assert!(vk.s.len() == inputs.0.len() + 1);

    // Multiply PIs by VK.s

    let pi = prepare_public_inputs(vk, inputs);

    // Compute the product of pairings

    // This mimics the arrangement in circuit:
    // check_miller_pairs(&vec![
    //     (&proof.a, &G2Prepared::from_affine(proof.b)),
    //     (&-vk.alpha, &G2Prepared::from_affine(vk.beta)),
    //     (&-pi, &G2Prepared::from_affine(vk.gamma)),
    //     (&-proof.c, &G2Prepared::from_affine(vk.delta)),
    // ])

    check_pairing(&[
        (&proof.a, &proof.b),
        (&-vk.alpha, &vk.beta),
        (&-pi, &vk.gamma),
        (&-proof.c, &vk.delta),
    ])
}

/// Compute the VK hash.  This is not useful in the native case, but is used
/// to check the in-circuit implementation.
pub fn compute_circuit_id<C1, C2, const DEGREE: usize>(
    vk: &VerificationKey<C1, C2>,
) -> [u8; 32]
where
    C1: CurveAffineExt,
    C2: CurveAffineExt,
    C1::ScalarExt: EccPrimeField,
    C1::Base: EccPrimeField,
    C2::Base: FieldExtConstructor<C1::Base, DEGREE>,
{
    compute_vk_keccak_hash_with_domain_tag(
        vk,
        UPA_V0_9_0_CIRCUITID_DOMAIN_TAG_STRING,
    )
}

pub(crate) fn compute_r_powers(r: Fr, num_powers: usize) -> Vec<Fr> {
    assert!(num_powers >= 2);
    let mut powers = Vec::<Fr>::with_capacity(num_powers);
    powers.push(Fr::from(1));
    powers.push(r);
    for _ in 2..num_powers {
        powers.push(powers.last().unwrap() * r);
    }

    assert!(powers.len() == num_powers);
    powers
}

pub(crate) fn compute_f_j(
    inputs: &Vec<&PublicInputs>,
    r_powers: &[Fr],
    sum_r_powers: &Fr,
    j: usize,
) -> Fr {
    if j == 0 {
        return *sum_r_powers;
    }

    let mut res = inputs[0].0[j - 1];
    for i in 1..inputs.len() {
        let r_pow_i = r_powers[i];
        let input = inputs[i].0[j - 1];
        res += r_pow_i * input;
    }
    res
}

pub(crate) fn compute_minus_pi(
    s: &Vec<G1Affine>,
    inputs: &Vec<&PublicInputs>,
    r_powers: &[Fr],
    sum_r_powers: Fr,
) -> G1Affine {
    let num_inputs = inputs[0].0.len();
    assert!(s.len() == num_inputs + 1);

    // f_j is the sum of r_i * PI_i[j] (j-th input to the i-th proof)
    //
    //   f_j = \sum_{0}^{n-1} r^i PI_{i,j}
    //
    // n = num_proofs
    //
    // Implicitly, each input set includes 1 at position 0, hence:
    //
    //   f_0 = \sum_{0}^{n-1} r^i = sum_r_powers
    //   f_j = \sum_{0}^{n-1} r^i = PI_{i,j-1}

    let mut pi = s[0] * compute_f_j(inputs, r_powers, &sum_r_powers, 0);
    #[allow(clippy::needless_range_loop)] // make start idx clear with for
    for j in 1..num_inputs + 1 {
        let pi_i = s[j] * compute_f_j(inputs, r_powers, &sum_r_powers, j);

        pi += pi_i;
    }

    G1Affine::from(-pi)
}

#[allow(non_snake_case)]
pub(crate) fn compute_minus_ZC(
    proofs_and_inputs: &[(&Proof, &PublicInputs)],
    r_powers: &[Fr],
) -> G1Affine {
    let z_C: G1 = proofs_and_inputs
        .iter()
        .zip(r_powers.iter())
        .map(|(p_i, r_power)| p_i.0.c * r_power)
        .reduce(|a, b| a + b)
        .unwrap();
    G1Affine::from(-z_C)
}

#[allow(non_snake_case)]
pub(crate) fn compute_r_i_A_i_B_i(
    proofs_and_inputs: &[(&Proof, &PublicInputs)],
    r_powers: &[Fr],
) -> Vec<(G1Affine, G2Affine)> {
    let A_is = proofs_and_inputs.iter().map(|p_i| p_i.0.a);
    let A_i_r_is = A_is
        .zip(r_powers.iter())
        .map(|(A, r_i)| G1Affine::from(A * r_i));

    let B_is = proofs_and_inputs.iter().map(|p_i| p_i.0.b);
    A_i_r_is.zip(B_is).collect()
}

#[allow(non_snake_case)]
pub(crate) fn compute_prepared_proof(
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
    r: Fr,
) -> PreparedProof {
    let num_proofs = proofs_and_inputs.len();
    assert!(num_proofs > 0);
    let r_powers: Vec<Fr> = compute_r_powers(r, num_proofs);
    assert!(r_powers[0] == Fr::from(1));
    assert!(r_powers[num_proofs - 1] == r_powers[1] * r_powers[num_proofs - 2]);

    let sum_r_powers: Fr =
        r_powers.iter().copied().reduce(|a, b| (a + b)).unwrap();

    // TODO: remove these once all issues are fixed.

    // Accumulated public inputs

    let minus_pi = compute_minus_pi(
        &vk.s,
        &proofs_and_inputs.iter().map(|p_i| p_i.1).collect(),
        &r_powers,
        sum_r_powers,
    );

    // Compute z_C

    let minus_z_C: G1Affine = compute_minus_ZC(proofs_and_inputs, &r_powers);

    // Compute ( \sum_i r^i ) * P

    let minus_r_P: G1Affine = G1Affine::from(-(vk.alpha * sum_r_powers));

    // Construct (A_i * r^i, B_i)

    let r_i_A_i_B_i = compute_r_i_A_i_B_i(proofs_and_inputs, &r_powers);

    PreparedProof {
        ab_pairs: r_i_A_i_B_i,
        rp: (minus_r_P, vk.beta),
        pi: (minus_pi, vk.gamma),
        zc: (minus_z_C, vk.delta),
    }
}

pub(crate) fn get_pairing_pairs(
    prep_proof: &PreparedProof,
) -> Vec<(&G1Affine, &G2Affine)> {
    let miller_pairs = prep_proof
        .ab_pairs
        .iter()
        .chain(once(&prep_proof.rp))
        .chain(once(&prep_proof.pi))
        .chain(once(&prep_proof.zc))
        .map(|(a, b)| (a, b));
    miller_pairs.collect()
}

/// Compute the challenge point used for the linear combination in the proof
/// batching.  For testing purposes, this matches the in-circuit
/// implementation.
pub fn compute_r(
    vk_hash: &Fr,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
) -> Fr {
    // Only the limb bits and the number of bits are relevant, the
    // degree is just an arbitrary number.
    let circuit_config = CircuitWithLimbsConfig::from_degree_bits(1);
    let mut poseidon = WrongFieldHasher::new(
        &circuit_config,
        Some(UPA_V0_9_0_CHALLENGE_DOMAIN_TAG_STRING),
    );

    // Absorb the domain_tag, vk_hash, followed by each instance entry.
    poseidon.hasher.update(&[*vk_hash]);
    for p_i in proofs_and_inputs {
        poseidon.absorb_g1(&p_i.0.a);
        poseidon.absorb_g2(&p_i.0.b);
        poseidon.absorb_g1(&p_i.0.c);
        poseidon.hasher.update(&p_i.1 .0);
    }

    poseidon.hasher.squeeze()
}

// TODO: it's useful to break up the construction of the pairs, and the
// preparation, for testing the circuit.  However, we should be able to use
// iterators and only allocate at the end.

pub fn batch_verify_with_challenge(
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
    r: Fr,
) -> bool {
    let prepared_proof: PreparedProof =
        compute_prepared_proof(vk, proofs_and_inputs, r);
    let pairing_pairs = get_pairing_pairs(&prepared_proof);
    check_pairing(&pairing_pairs)
}

/// Run the full batch_verify for a given challenge.  Note that this
/// replicates the in-circuit challenge computation (which conputes the hash
/// of non-native field elements using their limb representation), hence the
/// `circuit_config` requirement here.
pub fn batch_verify(
    circuit_config: &CircuitWithLimbsConfig,
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
) -> bool {
    // CircuitID is expressed as a field element, so use it as-is
    let vk_hash = compute_vk_poseidon_hash(
        circuit_config,
        vk,
        proofs_and_inputs[0].1 .0.len(),
    );
    let r = compute_r(&vk_hash, proofs_and_inputs);
    batch_verify_with_challenge(vk, proofs_and_inputs, r)
}

/// JSON types for IO
pub mod json {
    use crate::batch_verify::{
        common::{
            native::json::{JsonProofAndInputs, JsonVerificationKey},
            types::{Proof, PublicInputs, VerificationKey},
        },
        fixed::types::BatchVerifyInputs,
    };
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use serde::{Deserialize, Serialize};

    /// Json version of the BatchVerifyInputs.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct JsonBatchVerifyInputs {
        pub app_vk: JsonVerificationKey,
        pub app_proofs_and_inputs: Vec<JsonProofAndInputs>,
    }

    /// Read BatchVerifyInputs from JsonBatchVerifyInputs
    impl From<JsonBatchVerifyInputs> for BatchVerifyInputs<Fr> {
        fn from(json: JsonBatchVerifyInputs) -> Self {
            BatchVerifyInputs {
                app_vk: VerificationKey::from(&json.app_vk),
                app_proofs_and_inputs: json
                    .app_proofs_and_inputs
                    .iter()
                    .map(|p_i| {
                        (
                            Proof::from(&p_i.proof),
                            PublicInputs::from(&p_i.inputs),
                        )
                    })
                    .collect(),
            }
        }
    }
}
