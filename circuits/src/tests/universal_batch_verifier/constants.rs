use crate::{
    batch_verify::common::ecc::constants::{
        BN254_CURVE_PARAMETER, Q_MINUS_ONE_OVER_THREE, Q_MINUS_ONE_OVER_TWO,
        XI, XI_Q_2, XI_Q_3,
    },
    EccPrimeField,
};
use halo2_base::halo2_proofs::halo2curves::bn256::{Fq, Fr};

/// Asserts that `\sum_i coeffs_i x^{i-1} = F::modulus`.
fn assert_polynomial_relation_constant<F: EccPrimeField>(
    x: u64,
    coeffs: &[u64],
) {
    let x = F::from(x);
    let mut x_power = F::one();
    let coeffs_field = coeffs.iter().map(|coeff| F::from(*coeff));
    let result = coeffs_field.fold(F::zero(), |acc, coeff| {
        let term = acc + coeff * x_power;
        x_power *= x;
        term
    });
    assert_eq!(result, F::zero(), "polynomial relation not satisfied");
}

/// Asserts that 1 + 6x + 18x^2 + 36x^3 + 36x^4 = r.
fn assert_eqn_fr() {
    let coeffs = [1, 6, 18, 36, 36];
    assert_polynomial_relation_constant::<Fr>(BN254_CURVE_PARAMETER, &coeffs);
}

/// Asserts that 1 + 6x + 24x^2 + 36x^3 + 36x^4 = q.
fn assert_eqn_fq() {
    let coeffs = [1, 6, 24, 36, 36];
    assert_polynomial_relation_constant::<Fq>(BN254_CURVE_PARAMETER, &coeffs);
}

/// Asserts that the BN254 curve parameter satisfies the necessary conditions
/// to apply the improved subgroup check in this paper
/// https://eprint.iacr.org/2022/348.pdf
fn assert_curve_parameter_is_valid() {
    assert_ne!(BN254_CURVE_PARAMETER % 13, 4, "x mod 13 = 4");
    assert_ne!(BN254_CURVE_PARAMETER % 97, 92, "x mod 97 = 92");
}

/// Checks all the constants in the [`constants`](crate::batch_verify::common::ecc::constants)
/// module are correct.
#[test]
fn check_constants() {
    // Compute (q-1)/2 and (q-1)/3 and compare
    // to the corresponding constants.
    let two = Fq::one().double();
    let three = Fq::add(&two, &Fq::one());
    let modulus_minus_one = Fq::zero() - Fq::one();
    let modulus_minus_one_over_two =
        modulus_minus_one * (two.invert().unwrap());
    let modulus_minus_one_over_three =
        modulus_minus_one * (three.invert().unwrap());

    assert_eq!(
        modulus_minus_one_over_two,
        Fq::from_raw(Q_MINUS_ONE_OVER_TWO),
        "Incorrect Q_MINUS_ONE_OVER_TWO"
    );
    assert_eq!(
        modulus_minus_one_over_three,
        Fq::from_raw(Q_MINUS_ONE_OVER_THREE),
        "Incorrect Q_MINUS_ONE_OVER_THREE"
    );

    // compute xi^{(q-1)/2} and xi^{(q-1)/3} and
    // compare to the corresponding constants
    let xi_q_2 = XI.pow(&Q_MINUS_ONE_OVER_TWO);
    let xi_q_3 = XI.pow(&Q_MINUS_ONE_OVER_THREE);

    assert_eq!(xi_q_2, XI_Q_2, "Incorrect XI_Q_2");
    assert_eq!(xi_q_3, XI_Q_3, "Incorrect XI_Q_3");

    // Assert BN254_CURVE_PARAMETER validity
    assert_eqn_fr();
    assert_eqn_fq();
    assert_curve_parameter_is_valid();
}
