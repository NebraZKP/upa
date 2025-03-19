//! Native implementation of the Universal Batch Verifier
use crate::{
    batch_verify::{
        common::{
            native::{
                compute_vk_keccak_hash_with_domain_tag,
                compute_vk_poseidon_hash,
            },
            types::VerificationKey,
        },
        universal::types::{
            UniversalBatchVerifierInput,
            UPA_V1_0_0_CHALLENGE_DOMAIN_TAG_STRING,
            UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING,
        },
    },
    utils::hashing::WrongFieldHasher,
    CircuitWithLimbsConfig,
};
use core::borrow::Borrow;
use halo2_base::halo2_proofs::halo2curves::{
    bn256::{multi_miller_loop, Fr, G1Affine, G2Affine, Gt, G1},
    pairing::MillerLoopResult,
};
use itertools::Itertools;

// The pairing check pairs required to verify a single Groth16 proof,
// excluding the public input term, which is accumulated with that for all
// other entries into a single term.
pub(crate) struct PairingCheckPairs {
    groth16_pairs: [(G1Affine, G2Affine); 4],
}

impl PairingCheckPairs {
    fn iter(&self) -> impl Iterator<Item = &(G1Affine, G2Affine)> {
        self.groth16_pairs.iter()
    }
}

/// Challenge points. Denoted in spec
/// as (r, t).
pub(crate) type ChallengePoints = (Fr, Fr);

/// Computes the vk hash of `vk`.
pub fn compute_circuit_id(vk: &VerificationKey) -> [u8; 32] {
    let domain_tag = UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING;
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
    let (r, _t) = compute_challenge_points(batch.iter(), max_num_public_inputs);

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
        let pairs = compute_pairing_check_pairs(&entry, &challenge);
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
/// TODO: Without commitment this is just assert_well_formed
fn update_entry(
    entry: &UniversalBatchVerifierInput,
) -> UniversalBatchVerifierInput {
    entry.assert_well_formed();
    entry.clone()
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

pub(crate) fn compute_pi_term_for_entry(
    entry: &UniversalBatchVerifierInput,
) -> G1 {
    entry
        .vk
        .s
        .iter()
        .skip(1)
        .zip_eq(entry.inputs.0.iter())
        .fold(G1::from(entry.vk.s[0]), |accum, (vk_s_i, x_i)| {
            accum + (vk_s_i * x_i)
        })
}

/// Compute the group points that must be checked for a Groth16 pairing check,
/// using the challenge factor.
pub(crate) fn compute_pairing_check_pairs(
    entry: &UniversalBatchVerifierInput,
    factor: &Fr,
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

    // For tests, we want to pad the proofs so we have the same outputs
    // as in the circuit
    #[cfg(test)]
    {
        use std::cell::RefCell;
        let vk = RefCell::new(entry.vk.clone());
        vk.borrow_mut().pad(entry.inputs.0.len());
    }
    PairingCheckPairs { groth16_pairs }
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
