use super::file::load_json;
use crate::{CircuitConfig, CircuitWithLimbsConfig};
use core::fmt;
use serde::{Deserialize, Serialize};

/// Parameters for each circuit in UPA:
/// - Batch Verifier (BV) circuit
/// - Keccak circuit
/// - Outer verifier circuit
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UpaConfig {
    /// Maximum number of public inputs for each app proof.
    ///
    /// # Note
    ///
    /// In the old protocol (non-universal), this is the *exact* number
    /// of public inputs for each app proof.
    pub max_num_app_public_inputs: u32,

    /// Number of app proofs in an inner batch.
    pub inner_batch_size: u32,

    /// Number of `BatchVerifyCircuit`s being aggregated.
    pub outer_batch_size: u32,

    // Config for Batch Verifier circuit.
    pub bv_config: CircuitWithLimbsConfig,

    // Config for Keccak circuit.
    pub keccak_config: CircuitConfig,

    /// Config for Outer circuit.
    pub outer_config: CircuitWithLimbsConfig,

    /// Output the submission Id
    pub output_submission_id: bool,
}

impl UpaConfig {
    // Checks that the `BatchVerifyConfig`, KeccakConfig, and `OuterConfig`
    // in an `UpaConfig` are compatible with each other.
    pub fn check(&self) -> Result<(), &'static str> {
        // Number of lookup bits should be strictly smaller than the degree
        // for each circuit.
        if self.bv_config.lookup_bits
            > (self.bv_config.degree_bits - 1) as usize
        {
            return Err("BV lookup bits greater or equal to degree bits.");
        }

        if self.keccak_config.lookup_bits
            > (self.keccak_config.degree_bits - 1) as usize
        {
            return Err("Keccak lookup bits greater or equal to degree bits.");
        }

        if self.outer_config.lookup_bits
            > (self.outer_config.degree_bits - 1) as usize
        {
            return Err(
                "Outer circuit lookup bits greater or equal to degree bits.",
            );
        }

        Ok(())
    }

    // Constructor method to load UpaConfig from a JSON file.
    pub fn from_file(config_file: &str) -> Self {
        let config: UpaConfig = load_json(config_file);

        // Panic if check fails
        config.check().unwrap_or_else(|e| {
            panic!("Compatibility check for config {config_file} failed: {e:?}")
        });

        config
    }
}

impl fmt::Display for UpaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Max num public inputs: {}",
            self.max_num_app_public_inputs
        )?;
        writeln!(f, "Inner batch size: {}", self.inner_batch_size)?;
        writeln!(f, "Outer batch size: {}", self.outer_batch_size)?;
        writeln!(f, "BV config: {}", self.bv_config)?;
        writeln!(f, "Keccak config: {}", self.keccak_config)?;
        writeln!(f, "Outer config: {}", self.outer_config)
    }
}
