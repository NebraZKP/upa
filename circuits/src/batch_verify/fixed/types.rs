use crate::{
    batch_verify::common::types::{Proof, PublicInputs, VerificationKey},
    CircuitWithLimbsConfig, EccPrimeField, UpaConfig,
};
use serde::{Deserialize, Serialize};

pub(crate) const UPA_V0_9_0_CIRCUITID_DOMAIN_TAG_STRING: &str =
    "UPA v0.9.0 CircuitId";

pub(crate) const UPA_V0_9_0_CHALLENGE_DOMAIN_TAG_STRING: &str =
    "UPA v0.9.0 Challenge";

/// Parameters of the BatchVerifier circuit
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BatchVerifyConfig {
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

    /// Number of public inputs for each app proof.
    pub num_app_public_inputs: u32,
}

impl BatchVerifyConfig {
    pub fn from_circuit_config(
        circuit_config: &CircuitWithLimbsConfig,
        batch_size: u32,
        num_app_public_inputs: u32,
    ) -> Self {
        BatchVerifyConfig {
            degree_bits: circuit_config.degree_bits,
            lookup_bits: circuit_config.lookup_bits,
            limb_bits: circuit_config.limb_bits,
            num_limbs: circuit_config.num_limbs,
            inner_batch_size: batch_size,
            num_app_public_inputs,
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
        BatchVerifyConfig::from(&UpaConfig::from_file(config_file))
    }
}

impl From<&UpaConfig> for BatchVerifyConfig {
    fn from(config: &UpaConfig) -> Self {
        BatchVerifyConfig {
            degree_bits: config.bv_config.degree_bits,
            lookup_bits: config.bv_config.lookup_bits,
            limb_bits: config.bv_config.limb_bits,
            num_limbs: config.bv_config.num_limbs,
            inner_batch_size: config.inner_batch_size,
            num_app_public_inputs: config.max_num_app_public_inputs,
        }
    }
}

// For specifying how these display in benchmark groups
impl core::fmt::Display for BatchVerifyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "BV degree: {}", self.degree_bits)?;
        writeln!(f, "Number of public inputs: {}", self.num_app_public_inputs)?;
        write!(f, "Inner batch size: {}", self.inner_batch_size)
    }
}

/// Input data to a BatchVerifyCircuit. This is not the same as instance data,
/// but is the input data required to generate a witness.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchVerifyInputs<F: EccPrimeField> {
    /// The Groth16 verification key of the application circuit
    pub app_vk: VerificationKey,
    /// The claimed Groth16 proofs and their corresponding public inputs for
    /// the application circuit
    pub app_proofs_and_inputs: Vec<(Proof, PublicInputs<F>)>,
}
