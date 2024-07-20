#![feature(trait_alias)]
#![allow(deprecated)]

use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::CurveAffine,
        plonk::{Circuit, ProvingKey, VerifyingKey},
    },
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt,
    fs::OpenOptions,
    io::{BufReader, Read},
};
use utils::upa_config::UpaConfig;

// For simplicity, we use this trait even in situations
// where `halo2_base::utils::ScalarField` would suffice.
// (It extends that trait)
pub use halo2_ecc::fields::PrimeField as EccPrimeField;

pub mod batch_verify;
pub mod keccak;
pub mod outer;
pub mod utils;

#[cfg(test)]
mod tests;

const DEFAULT_NUM_LIMBS: usize = 3;

const DEFAULT_LIMB_BITS: usize = 88;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
/// Configuration parameters for a axiom-halo2 circuit (where degree is
/// specified, and numbers of columns are computed).
pub struct CircuitConfig {
    /// Columns have length `2^degree_bits`.  Commonly referred to as `k`.
    pub degree_bits: u32,
    /// Lookup tables have length `2^lookup_bits`
    pub lookup_bits: usize,
}

impl fmt::Display for CircuitConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Degree bits: {}", self.degree_bits)?;
        writeln!(f, "Lookup bits: {}", self.lookup_bits)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
/// Configuration parameters for a axiom-halo2 circuit (where degree is
/// specified, and numbers of columns are computed).
pub struct CircuitWithLimbsConfig {
    /// Columns have length `2^degree_bits`.  Commonly referred to as `k`.
    pub degree_bits: u32,
    /// Lookup tables have length `2^lookup_bits`
    pub lookup_bits: usize,
    /// Size of limbs for CRT arithmetic
    pub limb_bits: usize,
    /// Number of limbs for CRT arithmetic
    pub num_limbs: usize,
}

impl CircuitWithLimbsConfig {
    /// Initialize using default values, given a log-2 degree `k`.  Lookup
    /// bits are set to `k - 1` and the limb configuration uses
    /// DEFAULT_LIMB_BITS and DEFAULT_NUM_LIMBS.
    pub const fn from_degree_bits(k: u32) -> Self {
        Self {
            degree_bits: k,
            lookup_bits: (k - 1) as usize,
            limb_bits: DEFAULT_LIMB_BITS,
            num_limbs: DEFAULT_NUM_LIMBS,
        }
    }

    fn read_from_str(s: &str) -> Self {
        serde_json::from_str(s).unwrap_or_else(|e| {
            panic!("invalid CircuitWithLimbsConfig json: {e}")
        })
    }

    /// Parse the string as a single JSON object with fields of both
    /// `CircuitWithLimbsConfig` and another JSON-deserializable object `C`
    /// (effectively extending the `CircuitWithLimbsConfig` to have other fields).
    pub fn with_child_type<C: DeserializeOwned>(s: &str) -> (Self, C) {
        let circuit_config = Self::read_from_str(s);
        let child = serde_json::from_str::<C>(s)
            .unwrap_or_else(|e| panic!("invalid json: {e}"));
        (circuit_config, child)
    }

    /// Read an extended `CircuitWithLimbsConfig` object.  See the `with_child_type`
    /// method.
    pub fn load_with_child_type<C: DeserializeOwned>(path: &str) -> (Self, C) {
        let f = OpenOptions::new()
            .read(true)
            .open(path)
            .unwrap_or_else(|e| panic!("failed to open file {path}: {e}"));
        let mut s = String::new();
        BufReader::new(f)
            .read_to_string(&mut s)
            .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
        Self::with_child_type(&s)
    }
}

impl fmt::Display for CircuitWithLimbsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Degree bits: {}", self.degree_bits)?;
        writeln!(f, "Lookup bits: {}", self.lookup_bits)?;
        writeln!(f, "Limb bits: {}", self.limb_bits)?;
        writeln!(f, "Num limbs: {}", self.num_limbs)
    }
}

/// Circuit interface. This trait provides methods to build circuits for both
/// keygen and proving such that the caller does not need to handle
/// the underlying environment variables.
pub trait SafeCircuit<'a, F, C>: Circuit<F>
where
    F: EccPrimeField,
    C: CurveAffine<ScalarExt = F>,
{
    /// Circuit Configuration Type
    type CircuitConfig;

    /// Gate Configuration Type
    type GateConfig;

    /// Circuit Inputs Type
    type CircuitInputs: 'a;

    /// Inputs needed for keygen
    type KeygenInputs: 'a;

    type InstanceInputs;

    /// Initializes the circuit for mock circuit generation.
    fn mock(config: &Self::CircuitConfig, inputs: &Self::CircuitInputs)
        -> Self;

    /// Initialize the circuit for keygen. Creates dummy inputs of
    /// the right shape based on the `config`.
    fn keygen(
        config: &Self::CircuitConfig,
        inputs: &Self::KeygenInputs,
    ) -> Self;

    /// Initializes the circuit for proving.
    ///
    /// # Implementation Note
    ///
    /// When this function is called, all the environment variables on
    /// which the circuit depends must already have been set, either because:
    ///
    /// a) we are in a test situation and keygen has been run, or
    ///
    /// b) the [`ProvingKey`] has been loaded by calling
    /// [`read_proving_key`](SafeCircuit::read_proving_key)
    fn prover(
        config: &Self::CircuitConfig,
        gate_config: &Self::GateConfig,
        break_points: MultiPhaseThreadBreakPoints,
        inputs: &Self::CircuitInputs,
    ) -> Self;

    /// Compute instance from inputs, without creating the full circuit and
    /// performing witness gen.  Used for testing (sanity checking instances and
    /// dry-run provers).
    fn compute_instance(
        config: &Self::CircuitConfig,
        inputs: &Self::InstanceInputs,
    ) -> Vec<F>;

    /// Returns the gate configuration.  Intended to be called after the
    /// circuit is initialized using `keygen`, where `GateConfig` should be
    /// stored and used for `prover` operations.
    fn gate_config(&self) -> &Self::GateConfig;

    /// Returns the break points. Intended to be called after the circuit is
    /// initialized using `keygen` and the key generation process has
    /// completed.  The returned break-points should be stored and used for
    /// `prover` operations.
    fn break_points(&self) -> MultiPhaseThreadBreakPoints;

    /// Loads a proving key, given the `circuit_config` and the `gate_config`.
    ///
    /// # Implementation Note
    ///
    /// This function must set all the appropriate environment
    /// variables. Should be called BEFORE the circuit is constructed.
    fn read_proving_key<R>(
        circuit_config: &Self::CircuitConfig,
        gate_config: &Self::GateConfig,
        reader: &mut R,
    ) -> Result<ProvingKey<C>, std::io::Error>
    where
        R: std::io::Read;

    /// Loads a verification key given the `gate_config`.
    ///
    /// # Implementation Note
    ///
    /// This function must ensure that all environment variables are set
    /// correctly.
    fn read_verifying_key<R>(
        gate_config: &Self::GateConfig,
        reader: &mut R,
    ) -> Result<VerifyingKey<C>, std::io::Error>
    where
        R: std::io::Read;
}
