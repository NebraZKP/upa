//! Bitmask utilities

use halo2_base::{
    gates::GateInstructions, utils::ScalarField, AssignedValue, Context,
};

/// Returns a length `n` bitmask `b` with `b[j]=1` if and only if `i = j`.
///
/// # Note
///
/// This function doesn't check that `i < n`. If `i>=n`, it will return a bitmask with all zeroes.
///
/// # Specification
///
/// This function corresponds to the component **l-th bit bitmask**
/// in the variable length keccak and the universal batch verifier specs.
pub fn ith_bit_bitmask<F: ScalarField>(
    ctx: &mut Context<F>,
    chip: &impl GateInstructions<F>,
    i: AssignedValue<F>,
    n: u64,
) -> Vec<AssignedValue<F>> {
    let mut bitmask = Vec::with_capacity(n as usize);
    for idx in 0..n {
        let idx = ctx.load_constant(F::from(idx));
        bitmask.push(chip.is_equal(ctx, idx, i));
    }
    bitmask
}

/// Returns a length `n` bitmask with the first `i` elements equal to 1 and the rest equal to 0.
///
/// # Specification
///
/// This function corresponds to the component **First l bits bitmask**
/// in the variable length keccak and universal batch verifier specs.
pub fn first_i_bits_bitmask<F: ScalarField>(
    ctx: &mut Context<F>,
    chip: &impl GateInstructions<F>,
    i: AssignedValue<F>,
    n: u64,
) -> Vec<AssignedValue<F>> {
    let mut bitmask = Vec::with_capacity(n as usize);
    let mut next_value = ctx.load_constant(F::one());
    for idx in 0..n {
        let idx = ctx.load_constant(F::from(idx));
        let is_equal = chip.is_equal(ctx, idx, i);
        next_value = chip.sub(ctx, next_value, is_equal);
        bitmask.push(next_value);
    }
    bitmask
}
