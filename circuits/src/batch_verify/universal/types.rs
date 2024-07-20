use crate::{
    batch_verify::common::{
        ecc::EcPointPair,
        native::unsafe_proof_generation::sample_proofs_inputs_vk,
        types::{Proof, PublicInputs, VerificationKey},
    },
    utils::commitment_point::be_bytes_to_field_element,
    CircuitWithLimbsConfig, EccPrimeField, UpaConfig,
};
use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, AssignedValue};
use itertools::Itertools;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};

pub(crate) const UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING: &str =
    "UPA Groth16 circuit id";
pub(crate) const UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING_WITH_COMMITMENT: &str =
    "UPA Groth16 with commitment circuit id";
pub(crate) const UPA_V1_0_0_CHALLENGE_DOMAIN_TAG_STRING: &str =
    "UPA v1.0.0 Challenge";

/// Parameters of the Universal Batch Verifier circuit
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UniversalBatchVerifierConfig {
    /// Columns have length `2^degree_bits`. Commonly referred to as `k`.
    pub degree_bits: u32,

    /// Lookup tables have length `2^lookup_bits`
    pub lookup_bits: usize,

    /// Size of limbs for CRT arithmetic
    pub limb_bits: usize,

    /// Number of limbs for CRT arithmetic
    pub num_limbs: usize,

    /// Number of app proofs in a single batch
    pub inner_batch_size: u32,

    /// Maximum number of public inputs allowed.
    pub max_num_public_inputs: u32,
}

impl UniversalBatchVerifierConfig {
    pub fn from_circuit_config(
        circuit_config: &CircuitWithLimbsConfig,
        batch_size: u32,
        max_num_public_inputs: u32,
    ) -> Self {
        UniversalBatchVerifierConfig {
            degree_bits: circuit_config.degree_bits,
            lookup_bits: circuit_config.lookup_bits,
            limb_bits: circuit_config.limb_bits,
            num_limbs: circuit_config.num_limbs,
            inner_batch_size: batch_size,
            max_num_public_inputs,
        }
    }

    pub fn circuit_config(&self) -> CircuitWithLimbsConfig {
        CircuitWithLimbsConfig {
            degree_bits: self.degree_bits,
            lookup_bits: self.lookup_bits,
            limb_bits: self.limb_bits,
            num_limbs: self.num_limbs,
        }
    }

    pub fn from_upa_config_file(config_file: &str) -> Self {
        UniversalBatchVerifierConfig::from(&UpaConfig::from_file(config_file))
    }
}

impl From<&UpaConfig> for UniversalBatchVerifierConfig {
    fn from(config: &UpaConfig) -> Self {
        UniversalBatchVerifierConfig {
            degree_bits: config.bv_config.degree_bits,
            lookup_bits: config.bv_config.lookup_bits,
            limb_bits: config.bv_config.limb_bits,
            num_limbs: config.bv_config.num_limbs,
            inner_batch_size: config.inner_batch_size,
            max_num_public_inputs: config.max_num_app_public_inputs,
        }
    }
}

// For specifying how these display in benchmark groups
impl core::fmt::Display for UniversalBatchVerifierConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "UBV degree: {}", self.degree_bits)?;
        writeln!(
            f,
            "Max number of public inputs: {}",
            self.max_num_public_inputs
        )?;
        write!(f, "Inner batch size: {}", self.inner_batch_size)
    }
}

/// A single entry in a batch of proofs to check.
///
/// # Note
///
/// This struct holds the *padded* verification key, proof, and public inputs,
/// as well as the original (unpadded) length as a field element. It holds a
/// boolean flag for the presence of a non-trivial Pedersen commitment. The circuit
/// will compute the witness from this struct. It can only be created from
/// a [`UniversalBatchVerifierInput`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchEntry<F = Fr>
where
    F: EccPrimeField,
{
    /// The number of ordinary Groth16 public inputs,
    /// excluding the commitment hash if present.
    len: F,
    has_commitment: bool,
    vk: VerificationKey,
    proof: Proof,
    inputs: PublicInputs<F>,
    commitment_hash: F,
}

impl<F: EccPrimeField> BatchEntry<F> {
    /// Creates a new [`BatchEntry`] from `ubv_input` and `config`.
    pub fn from_ubv_input_and_config(
        ubv_input: &UniversalBatchVerifierInput<F>,
        config: &UniversalBatchVerifierConfig,
    ) -> Self {
        ubv_input.assert_consistent(config);

        let len = ubv_input.inputs.0.len();
        let total_len = config.max_num_public_inputs as usize;
        let has_commitment = ubv_input.has_commitment();

        let mut vk = ubv_input.vk.clone();
        vk.pad(total_len);
        let mut proof = ubv_input.proof.clone();
        proof.pad(has_commitment);

        // We compute the commitment hash. It will be the right one if the
        // proof had a commitment, and a meaningless one if it had been padded
        let commitment_hash = be_bytes_to_field_element(
            &proof
                .compute_commitment_hash_bytes_from_commitment_point()
                .expect("failed to hash commitment point"),
        );

        let mut inputs = ubv_input.inputs.clone();
        // If the commitment hash comes from a proper commitment point,
        // we make it the len-th public input
        if has_commitment {
            inputs.0.push(commitment_hash);
        }
        inputs.pad(total_len);

        Self {
            len: F::from(len as u64),
            has_commitment,
            vk,
            proof,
            inputs,
            commitment_hash,
        }
    }

    /// Creates a dummy [`BatchEntry`] for `config`.
    pub fn dummy(config: &UniversalBatchVerifierConfig) -> Self {
        let num_public_inputs = config.max_num_public_inputs as usize;
        let len = F::from(num_public_inputs as u64 - 1);
        let has_commitment = true;
        let vk = VerificationKey::default_with_length(
            num_public_inputs,
            has_commitment,
        );
        let proof = Proof::default_with_commitment(has_commitment);
        let inputs = PublicInputs::default_with_length(num_public_inputs);
        Self {
            len,
            has_commitment,
            vk,
            proof,
            inputs,
            commitment_hash: Default::default(),
        }
    }

    /// The unpadded length of the public inputs,
    /// excluding the commitment hash if present.
    pub fn len(&self) -> &F {
        &self.len
    }

    pub fn has_commitment(&self) -> bool {
        self.has_commitment
    }

    pub fn vk(&self) -> &VerificationKey {
        &self.vk
    }

    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    pub fn inputs(&self) -> &PublicInputs<F> {
        &self.inputs
    }

    pub fn commitment_hash(&self) -> &F {
        &self.commitment_hash
    }
}

/// Batch Entries
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchEntries<F: EccPrimeField>(pub Vec<BatchEntry<F>>);

impl<F: EccPrimeField> BatchEntries<F> {
    /// Creates new [`BatchEntries`] from `ubv_inputs` and `config`.
    pub fn from_ubv_inputs_and_config(
        ubv_inputs: &UniversalBatchVerifierInputs<F>,
        config: &UniversalBatchVerifierConfig,
    ) -> Self {
        assert_eq!(
            ubv_inputs.0.len(),
            config.inner_batch_size as usize,
            "Inner batch size mismatch"
        );
        Self(
            ubv_inputs
                .0
                .iter()
                .map(|ubv_input| {
                    BatchEntry::from_ubv_input_and_config(ubv_input, config)
                })
                .collect(),
        )
    }

    /// Creates dummy [`BatchEntries`] for `config`.
    pub(crate) fn dummy(config: &UniversalBatchVerifierConfig) -> Self {
        Self(
            (0..config.inner_batch_size)
                .into_iter()
                .map(|_| BatchEntry::dummy(config))
                .collect(),
        )
    }
}

/// Universal Batch Verifier Input.
///
/// # Note
///
/// This struct holds the *unpadded* verification key, proof, and public inputs.
/// It needs to be converted into a [`BatchEntry`] by providing a
/// [`UniversalBatchVerifierConfig`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UniversalBatchVerifierInput<F = Fr>
where
    F: EccPrimeField,
{
    pub vk: VerificationKey,
    pub proof: Proof,
    pub inputs: PublicInputs<F>,
}

impl<F: EccPrimeField> UniversalBatchVerifierInput<F> {
    /// Builds a new [`UniversalBatchVerifierInput`] from `vk`, `proof` and `inputs`.
    pub fn new(
        vk: VerificationKey,
        proof: Proof,
        inputs: PublicInputs<F>,
    ) -> Self {
        let result = Self { vk, proof, inputs };
        result.assert_well_formed();
        result
    }

    /// Asserts `self` is well formed and consistent with `config`.
    pub fn assert_consistent(&self, config: &UniversalBatchVerifierConfig) {
        self.assert_well_formed();
        let num_commitments = self.vk.h1.len();
        assert!(
            self.inputs.0.len() + num_commitments
                <= config.max_num_public_inputs as usize,
            "Public input length exceeds maximum allowed"
        );
    }

    /// Asserts `self` is well formed.
    pub fn assert_well_formed(&self) {
        let num_commitments = self.vk.h1.len();
        assert_eq!(
            self.vk.s.len(),
            self.inputs.0.len() + 1 + num_commitments,
            "Verification key and public inputs lengths not compatible"
        );
        assert!(
            num_commitments < 2,
            "Number of commitments can only be one or zero"
        );
        assert_eq!(
            num_commitments,
            self.vk.h2.len(),
            "Invalid VK. Inconsistent h1, h2."
        );
        assert_eq!(
            self.proof.m.len(),
            self.proof.pok.len(),
            "Invalid proof. Inconsistent m, pok."
        );
        assert_eq!(
            num_commitments,
            self.proof.m.len(),
            "Proof and VK have inconsistent Pedersen commitments."
        );
    }

    /// Returns `true` if `self` has a commitment
    pub fn has_commitment(&self) -> bool {
        self.vk.has_commitment()
    }

    /// Creates a dummy [`UniversalBatchVerifierInput`] for `config`.
    pub fn dummy(config: &UniversalBatchVerifierConfig) -> Self {
        let num_public_inputs = config.max_num_public_inputs as usize;
        // This function is being called by `dummy_ubv_snark`, which
        // passes this to the UBV prover, which convert this
        // `UniversalBatchVerifierInput` to a `BatchEntry`. If
        // `has_commitment` is `true`, this will fail the consistency
        // check.
        // If one wishes a dummy input with commitment for e.g. keygen,
        // (although it won't make a difference in the generated constraints),
        // use `BatchEntry::dummy` instead.
        let has_commitment = false;
        let vk = VerificationKey::default_with_length(
            num_public_inputs,
            has_commitment,
        );
        let proof = Proof::default_with_commitment(has_commitment);
        let inputs = PublicInputs::default_with_length(num_public_inputs);
        Self { vk, proof, inputs }
    }
}

impl UniversalBatchVerifierInput {
    /// Samples a [`UniversalBatchVerifierInput`] for `config`, with or without
    /// a Pedersen commitment.
    pub fn sample<R>(
        config: &UniversalBatchVerifierConfig,
        has_commitment: bool,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + ?Sized,
    {
        let num_public_inputs = config.max_num_public_inputs as usize;
        let length =
            rng.gen_range(1..=num_public_inputs - has_commitment as usize);
        let (proofs_and_inputs, vk) =
            sample_proofs_inputs_vk(length, has_commitment, 1, rng);
        let (proof, inputs) = proofs_and_inputs[0].clone();

        assert!(length > 0);
        assert!(length + 1 + has_commitment as usize == vk.s.len());
        assert!(length == inputs.0.len());

        Self { vk, proof, inputs }
    }
}

/// Universal Batch Verifier Inputs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UniversalBatchVerifierInputs<F: EccPrimeField>(
    pub Vec<UniversalBatchVerifierInput<F>>,
);

impl<F: EccPrimeField> UniversalBatchVerifierInputs<F> {
    /// Creates dummy [`UniversalBatchVerifierInputs`] for `config`.
    pub fn dummy(config: &UniversalBatchVerifierConfig) -> Self {
        Self(
            (0..config.inner_batch_size)
                .into_iter()
                .map(|_| UniversalBatchVerifierInput::dummy(config))
                .collect(),
        )
    }

    /// Returns the max public input length in the elements of `self`. This is
    /// the minimum `max_num_public_inputs` that a configuration compatible with
    /// `self` must have.
    pub fn max_len(&self) -> usize {
        self.0
            .iter()
            .map(|ubv_input| {
                let has_commitment = ubv_input.has_commitment() as usize;
                ubv_input.inputs.0.len() + has_commitment
            })
            .max()
            .expect(
                "Extracting the max public input length is not allowed to fail",
            )
    }
}

impl UniversalBatchVerifierInputs<Fr> {
    /// Samples [`UniversalBatchVerifierInputs`] compatible with `config`, with
    /// or without Pedersen commitments.
    pub fn sample<R>(
        config: &UniversalBatchVerifierConfig,
        has_commitment: bool,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(
            (0..config.inner_batch_size)
                .into_iter()
                .map(|_| {
                    UniversalBatchVerifierInput::sample(
                        config,
                        has_commitment,
                        rng,
                    )
                })
                .collect(),
        )
    }

    /// Samples [`UniversalBatchVerifierInputs`] compatible with `config`, mixing
    /// inputs with and without Pedersen commitments.
    pub fn sample_mixed<R>(
        config: &UniversalBatchVerifierConfig,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + ?Sized,
    {
        let has_commitment_vec = (0..config.inner_batch_size)
            .into_iter()
            .map(|_| rng.gen())
            .collect_vec();
        Self(
            (0..config.inner_batch_size)
                .into_iter()
                .map(|i| {
                    UniversalBatchVerifierInput::sample(
                        config,
                        has_commitment_vec[i as usize],
                        rng,
                    )
                })
                .collect(),
        )
    }
}

/// Representation of the (A, B), (C, delta) and (alpha, beta) [`EcPointPair`]s
/// for a series of Groth16 proofs
pub(crate) struct Groth16Pairs<F>
where
    F: EccPrimeField,
{
    pub scaled_ab_pairs: Vec<EcPointPair<F>>,
    pub scaled_cd_pairs: Vec<EcPointPair<F>>,
    pub scaled_pi_gamma_pairs: Vec<EcPointPair<F>>,
    pub scaled_alpha_beta_pairs: Vec<EcPointPair<F>>,
    pub scaled_m_h1_pairs: Vec<EcPointPair<F>>,
    pub scaled_pok_h2_pairs: Vec<EcPointPair<F>>,
}

/// Challenge points
pub(crate) type ChallengePoints<F> = (AssignedValue<F>, AssignedValue<F>);
