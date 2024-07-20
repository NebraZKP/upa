//! Native implementation of the Universal Batch Verifier
use crate::{
    batch_verify::{
        common::{
            native::{
                compute_vk_keccak_hash_with_domain_tag,
                compute_vk_poseidon_hash,
            },
            types::{PublicInputs, VerificationKey},
        },
        universal::types::{
            UniversalBatchVerifierInput,
            UPA_V1_0_0_CHALLENGE_DOMAIN_TAG_STRING,
            UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING,
            UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING_WITH_COMMITMENT,
        },
    },
    utils::{
        commitment_point::be_bytes_to_field_element, hashing::WrongFieldHasher,
    },
    CircuitWithLimbsConfig,
};
use core::borrow::Borrow;
use halo2_base::halo2_proofs::halo2curves::{
    bn256::{multi_miller_loop, Fr, G1Affine, G2Affine, Gt, G1},
    pairing::MillerLoopResult,
};
use itertools::Itertools;
use std::cell::RefCell;

// The pairing check pairs required to verify a single Groth16 proof,
// excluding the public input term, which is accumulated with that for all
// other entries into a single term.
pub(crate) struct PairingCheckPairs {
    groth16_pairs: [(G1Affine, G2Affine); 4],
    /// The `(M, h1)`, `(\pi^{Ped}, h2)` pairs
    /// of the optional Pedersen commitment.
    pedersen_pairs: Option<[(G1Affine, G2Affine); 2]>,
}

impl PairingCheckPairs {
    fn iter(&self) -> impl Iterator<Item = &(G1Affine, G2Affine)> {
        self.groth16_pairs
            .iter()
            .chain(self.pedersen_pairs.iter().flatten())
    }
}

/// Challenge points. Denoted in spec
/// as (r, t).
pub(crate) type ChallengePoints = (Fr, Fr);

/// Computes the vk hash of `vk`.
pub fn compute_circuit_id(vk: &VerificationKey) -> [u8; 32] {
    assert!(vk.is_well_formed());
    let domain_tag = match vk.has_commitment() {
        false => UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING,
        true => UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING_WITH_COMMITMENT,
    };
    compute_vk_keccak_hash_with_domain_tag(vk, domain_tag)
}

/// Computes the challenge points corresponding to `batch`.
pub(crate) fn compute_challenge_points(
    batch: impl IntoIterator<Item = impl Borrow<UniversalBatchVerifierInput>>,
    max_num_public_inputs: usize,
) -> ChallengePoints {
    // Only the limb bits and the number of bits are relevant, the
    // degree is just an arbitrary number.
    let circuit_config = CircuitWithLimbsConfig::from_degree_bits(1);
    let mut poseidon = WrongFieldHasher::new(
        &circuit_config,
        Some(UPA_V1_0_0_CHALLENGE_DOMAIN_TAG_STRING),
    );
    for entry in batch {
        let entry = entry.borrow();
        // Unlike (non-universal) BV, CircuitID is not a field element (it is
        // [u8; 32]) so compute the Poseidon hash of VK to use in the
        // challenge.
        let vk_hash = compute_vk_poseidon_hash(
            &circuit_config,
            &entry.vk,
            max_num_public_inputs,
        );
        poseidon.hasher.update(&[vk_hash]);
        poseidon.absorb_g1(&entry.proof.a);
        poseidon.absorb_g2(&entry.proof.b);
        poseidon.absorb_g1(&entry.proof.c);
        if let Some(m) = entry.proof.m.get(0) {
            poseidon.absorb_g1(m);
            poseidon.absorb_g1(&entry.proof.pok[0]);
        } else {
            #[cfg(test)]
            {
                let m = G1Affine::generator();
                let pok = -G1Affine::generator();
                poseidon.absorb_g1(&m);
                poseidon.absorb_g1(&pok);
            }
        }
        poseidon.hasher.update(entry.inputs.0.as_slice());

        #[cfg(test)]
        {
            let len = entry.inputs.0.len();
            let zeroes = vec![Fr::zero(); max_num_public_inputs - len];
            poseidon.hasher.update(zeroes.as_slice());
        }
    }

    let r = poseidon.hasher.squeeze();
    let t = poseidon.hasher.squeeze();

    (r, t)
}

/// Returns the pairs which will be the input for the Groth16 pairing check.
pub(crate) fn get_pairs<B, I>(
    batch: B,
    max_num_public_inputs: usize,
) -> Vec<(G1Affine, G2Affine)>
where
    B: IntoIterator<Item = I>,
    I: Borrow<UniversalBatchVerifierInput>,
{
    let batch = update_batch(batch);

    // Generate the challenge
    let (r, t) = compute_challenge_points(batch.iter(), max_num_public_inputs);

    // Track the current power of r
    let mut challenge = Fr::one();

    let mut all_pairs = Vec::<(G1Affine, G2Affine)>::new();
    for entry in batch {
        {
            assert!(
                entry.inputs.0.len() <= max_num_public_inputs,
                "Too many public inputs"
            );
        }
        let pairs = compute_pairing_check_pairs(&entry, &challenge, &t);
        all_pairs.extend(pairs.iter());

        challenge *= r;
    }

    all_pairs
}

/// Updates `batch`, adding the hash of each entry's commitment point (when present)
/// to its public inputs.
pub(crate) fn update_batch<B, I>(batch: B) -> Vec<UniversalBatchVerifierInput>
where
    B: IntoIterator<Item = I>,
    I: Borrow<UniversalBatchVerifierInput>,
{
    batch
        .into_iter()
        .map(|entry| update_entry(entry.borrow()))
        .collect()
}

/// Updates `entry`, adding the hash of the commitment point (if present) to `entry.inputs`.
fn update_entry(
    entry: &UniversalBatchVerifierInput,
) -> UniversalBatchVerifierInput {
    entry.assert_well_formed();
    let UniversalBatchVerifierInput {
        vk,
        proof,
        mut inputs,
    } = entry.clone();
    if entry.has_commitment() {
        let extra_input = be_bytes_to_field_element(
            &entry
                .proof
                .compute_commitment_hash_bytes_from_commitment_point()
                .expect("This cannot fail for entries with commitment"),
        );
        inputs.0.push(extra_input);
    }
    UniversalBatchVerifierInput { vk, proof, inputs }
}

/// Run the universal batch verification algorithm on a batch of proofs.
///
/// # Note
///
/// The extra parameter `max_num_public_inputs`, while not necessary to
/// run the verification algorithm, has an effect on the computation of
/// the challenge. This proves useful for the tests in `component`, where
/// we want each native step to return the same value as the circuit
/// implementation.
pub fn verify_universal_groth16_batch<B, I>(
    batch: B,
    max_num_public_inputs: usize,
) -> bool
where
    B: IntoIterator<Item = I>,
    I: Borrow<UniversalBatchVerifierInput>,
{
    let all_pairs = get_pairs(batch, max_num_public_inputs)
        .into_iter()
        .map(|(a, b)| (a, b.into()))
        .collect_vec();
    // Perform the pairing check
    let miller_out = multi_miller_loop(
        all_pairs
            .iter()
            .map(|(a, b)| (a, b))
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let final_exp = miller_out.final_exponentiation();
    final_exp == Gt::identity()
}

pub(crate) fn compute_pi_term_for_entry_without_commitment(
    vk_s: &[G1Affine],
    inputs: &PublicInputs,
) -> G1 {
    vk_s.iter()
        .skip(1)
        .zip_eq(inputs.0.iter())
        .fold(G1::from(vk_s[0]), |accum, (vk_s_i, x_i)| {
            accum + (vk_s_i * x_i)
        })
}

pub(crate) fn compute_pi_term_for_entry(
    entry: &UniversalBatchVerifierInput,
) -> G1 {
    // Compute vk_s[0] + \sum_{i=1}^\ell inputs[i] * vk_s[i]
    let mut s = compute_pi_term_for_entry_without_commitment(
        &entry.vk.s,
        &entry.inputs,
    );
    if entry.has_commitment() {
        s += entry.proof.m[0];
    }
    s
}

/// Compute the group points that must be checked for a Groth16 pairing check,
/// using the challenge factor.
pub(crate) fn compute_pairing_check_pairs(
    entry: &UniversalBatchVerifierInput,
    factor: &Fr,
    t: &Fr,
) -> PairingCheckPairs {
    // Return pairs:
    //   [
    //    (-factor * A, B),
    //    ( factor * alpha, beta),
    //    ( factor * pi_term, gamma),
    //    ( factor * C, delta)
    //   ]
    // Option:
    //  [
    //   ( t * factor * M, h1),
    //   ( t * factor * pok, h2)
    // ]

    let pi_term = compute_pi_term_for_entry(entry);
    let groth16_pairs = [
        (G1Affine::from(entry.proof.a * -factor), entry.proof.b),
        (G1Affine::from(entry.vk.alpha * factor), entry.vk.beta),
        (G1Affine::from(pi_term * factor), entry.vk.gamma),
        (G1Affine::from(entry.proof.c * factor), entry.vk.delta),
    ];

    let proof = RefCell::new(entry.proof.clone());
    let vk = RefCell::new(entry.vk.clone());

    // For tests, we want to pad the proofs so we have the same outputs
    // as in the circuit
    #[cfg(test)]
    {
        proof.borrow_mut().pad(entry.has_commitment());
        vk.borrow_mut().pad(entry.inputs.0.len());
    }

    let pedersen_pairs_closure = || {
        [
            (
                G1Affine::from(proof.borrow().m[0] * factor * t),
                vk.borrow().h1[0],
            ),
            (
                G1Affine::from(proof.borrow().pok[0] * factor * t),
                vk.borrow().h2[0],
            ),
        ]
    };
    let pedersen_pairs =
        vk.borrow().has_commitment().then(pedersen_pairs_closure);

    PairingCheckPairs {
        groth16_pairs,
        pedersen_pairs,
    }
}

/// JSON types for IO
pub mod json {
    use crate::{
        batch_verify::{
            common::{
                native::json::*,
                types::{Proof, PublicInputs, VerificationKey},
            },
            universal::{
                types::UniversalBatchVerifierInput,
                UniversalBatchVerifierInputs,
            },
        },
        utils::file::load_json,
    };
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct JsonUniversalBatchVerifierInput {
        pub vk: JsonVerificationKey,
        pub proof: JsonProof,
        pub inputs: JsonPublicInputs,
    }

    /// Read UniversalBatchVerifierInput from JsonUniversalBatchVerifierInput
    impl From<&JsonUniversalBatchVerifierInput>
        for UniversalBatchVerifierInput<Fr>
    {
        fn from(json: &JsonUniversalBatchVerifierInput) -> Self {
            UniversalBatchVerifierInput::new(
                VerificationKey::from(&json.vk),
                Proof::from(&json.proof),
                PublicInputs::from(&json.inputs),
            )
        }
    }

    /// Json version of UniversalBatchVerifierInputs.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct JsonUniversalBatchVerifierInputs(
        pub Vec<JsonUniversalBatchVerifierInput>,
    );

    /// Read UniversalBatchVerifierInputs from JsonUniversalBatchVerifierInputs
    impl From<JsonUniversalBatchVerifierInputs>
        for UniversalBatchVerifierInputs<Fr>
    {
        fn from(json: JsonUniversalBatchVerifierInputs) -> Self {
            UniversalBatchVerifierInputs(
                json.0
                    .iter()
                    .map(|json_ubv_input| {
                        UniversalBatchVerifierInput::from(json_ubv_input)
                    })
                    .collect(),
            )
        }
    }

    pub fn load_app_vk_proof_and_inputs(
        filename: &str,
    ) -> UniversalBatchVerifierInput {
        let vk_proof_pi_json: JsonUniversalBatchVerifierInput =
            load_json(filename);
        UniversalBatchVerifierInput::from(&vk_proof_pi_json)
    }

    pub fn load_app_vk_proof_and_inputs_batch(
        filename: &str,
    ) -> UniversalBatchVerifierInputs<Fr> {
        let vks_proofs_pis_json: JsonUniversalBatchVerifierInputs =
            load_json(filename);
        UniversalBatchVerifierInputs::from(vks_proofs_pis_json)
    }
}
