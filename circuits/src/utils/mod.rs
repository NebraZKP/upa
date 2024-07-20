use crate::EccPrimeField;
use halo2_base::gates::builder::GateThreadBuilder;

pub mod base64;
pub mod benchmarks;
pub mod bitmask;
pub mod commitment_point;
pub mod field_element_hex;
pub mod field_elements_hex;
pub mod file;
pub mod hashing;
pub mod keccak_hasher;
pub mod reduced;
pub mod upa_config;
pub mod vk_hex;

/// Convenience function to convert from vectors of pairs (the common format
/// of data in tests, say), to a vector of pairs of refs (commonly used by the
/// batch verification functions).
pub fn to_ref_vec<A, B>(pairs: &[(A, B)]) -> Vec<(&A, &B)> {
    pairs.iter().map(|(a, b)| (a, b)).collect()
}

/// Compute the current cell count for each phase.  Can be called during the
/// vertical gate definition phase using a GateThreadBuilder.
pub fn advice_cell_count<F: EccPrimeField>(
    builder: &GateThreadBuilder<F>,
) -> Vec<usize> {
    builder
        .threads
        .iter()
        .map(|threads| threads.iter().map(|ctx| ctx.advice.len()).sum())
        .collect()
}
