use crate::{
    batch_verify::common::{
        chip::BatchVerifierChip,
        ecc::constants::{
            BN254_CURVE_PARAMETER, Q_MINUS_ONE_OVER_THREE,
            Q_MINUS_ONE_OVER_TWO, XI, XI_Q_2, XI_Q_3,
        },
        MINIMUM_ROWS,
    },
    tests::{LIMB_BITS, NUM_LIMBS},
    utils::reduced::FromReduced,
    EccPrimeField,
};
use halo2_base::{
    gates::{
        builder::{
            FlexGateConfigParams, GateThreadBuilder, RangeCircuitBuilder,
        },
        range::RangeConfig,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::{Fq, Fq2, Fr, G2Affine},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    safe_types::RangeChip,
};
use halo2_ecc::bn254::FpChip;
use rand::RngCore;
use rand_core::OsRng;
use snark_verifier::util::arithmetic::CurveAffine;

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

/// Subgroup check
#[derive(Clone, Copy, Debug)]
enum SubgroupCheck {
    None,
    Naive,
    Glv,
    Dlzz,
}

/// G2 Elliptic Curve Circuit.
///
/// This circuit assigns `point` and checks whether it belongs
/// to the BN254 G2 curve. It also checks it belongs to the right
/// subgroup of order `r`.
struct G2EllipticCurveCircuit {
    inner: RangeCircuitBuilder<Fr>,
    #[allow(dead_code)] // kept for circuit constraint count
    config: FlexGateConfigParams,
}

impl G2EllipticCurveCircuit {
    /// Builds a new [`G2EllipticCurveCircuit`] in mock mode
    /// which performs `subgroup_check` on `point`
    fn new(
        degree_bits: usize,
        point: G2Affine,
        subgroup_check: SubgroupCheck,
    ) -> Self {
        let mut builder = GateThreadBuilder::mock();
        let ctx = builder.main(0);
        let range = RangeChip::<Fr>::default(degree_bits - 1);
        let fp_chip = FpChip::<Fr>::new(&range, LIMB_BITS, NUM_LIMBS);
        let batch_verifier_chip = BatchVerifierChip::<Fr>::new(&fp_chip);
        let assigned_point = batch_verifier_chip.assign_g2_reduced(ctx, point);
        batch_verifier_chip.assert_g2_point_is_on_curve(ctx, &assigned_point);
        match subgroup_check {
            SubgroupCheck::None => {}
            SubgroupCheck::Naive => batch_verifier_chip
                .assert_g2_subgroup_membership_naive(
                    ctx,
                    &FromReduced::from_reduced(&assigned_point),
                ),
            SubgroupCheck::Glv => batch_verifier_chip
                .assert_g2_subgroup_membership_glv(
                    ctx,
                    &FromReduced::from_reduced(&assigned_point),
                ),
            SubgroupCheck::Dlzz => batch_verifier_chip
                .assert_g2_subgroup_membership(
                    ctx,
                    &FromReduced::from_reduced(&assigned_point),
                ),
        }
        std::env::set_var("LOOKUP_BITS", (degree_bits - 1).to_string());
        let config = builder.config(degree_bits, Some(MINIMUM_ROWS));
        Self {
            inner: RangeCircuitBuilder::mock(builder),
            config,
        }
    }
}

impl Circuit<Fr> for G2EllipticCurveCircuit {
    type Config = RangeConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        RangeCircuitBuilder::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
    }
}

/// `G2_B` constant in the BN254 G2 equation:
/// `x^3 = y^2 + G2_B`
const G2_B: Fq2 = Fq2 {
    c0: Fq::from_raw([
        0x3267e6dc24a138e5,
        0xb5b4c5e559dbefa3,
        0x81be18991be06ac3,
        0x2b149d40ceb8aaae,
    ]),
    c1: Fq::from_raw([
        0xe4a2bd0685c315d2,
        0xa74fa084e52d1852,
        0xcd2cafadeed8fdf4,
        0x009713b03af0fed4,
    ]),
};

/// Samples a valid G2Affine point
fn sample_g2_affine<R>(rng: &mut R) -> G2Affine
where
    R: RngCore + ?Sized,
{
    G2Affine::random(rng)
}

/// Samples a G2Affine point which is not on the curve
fn sample_g2_affine_not_on_curve<R>(rng: &mut R) -> G2Affine
where
    R: RngCore + ?Sized,
{
    let x = Fq2::random(&mut *rng);
    loop {
        let y = Fq2::random(&mut *rng);
        let result = G2Affine { x, y };
        if !bool::from(result.is_on_curve()) {
            return result;
        }
    }
}

/// Samples a G2Affine point which is on the curve but not in the right
/// subgroup
fn sample_g2_affine_not_in_subgroup<R>(rng: &mut R) -> G2Affine
where
    R: RngCore + ?Sized,
{
    loop {
        let x = Fq2::random(&mut *rng);
        let ysign = (rng.next_u32() % 2) as u8;

        let x3 = x.square() * x;
        let y = (x3 + G2_B).sqrt();
        if let Some(y) = Option::<Fq2>::from(y) {
            let sign = y.to_bytes()[0] & 1;
            let y = if ysign ^ sign == 0 { y } else { -y };

            let p_affine = G2Affine { x, y };

            // make sure the sampled point is not in the
            // subgroup
            let r_minus_one = Fr::zero() - Fr::one();
            let is_on_subgroup =
                G2Affine::from(p_affine * r_minus_one) == -p_affine;
            if !is_on_subgroup {
                return p_affine;
            }
        }
    }
}

/// Tests that: the circuit is satisfied for `subgroup_check` for a valid
/// G2 point, it fails for a point not on the curve, and it fails for a point
/// on the curve but not in the subgroup unless we skip the subgroup check.
fn test_g2_membership_for_subgroup_check(subgroup_check: SubgroupCheck) {
    let mut rng = OsRng;
    const DEGREE_BITS: usize = 15;
    let valid_point = sample_g2_affine(&mut rng);
    let not_on_curve = sample_g2_affine_not_on_curve(&mut rng);
    let not_in_subgroup = sample_g2_affine_not_in_subgroup(&mut rng);
    let circuit_valid =
        G2EllipticCurveCircuit::new(DEGREE_BITS, valid_point, subgroup_check);
    MockProver::run(DEGREE_BITS as u32, &circuit_valid, Vec::new())
        .expect("Mock prover run failure")
        .assert_satisfied();
    let circuit_not_on_curve =
        G2EllipticCurveCircuit::new(DEGREE_BITS, not_on_curve, subgroup_check);
    MockProver::run(DEGREE_BITS as u32, &circuit_not_on_curve, Vec::new())
        .expect("Mock prover run failure")
        .verify()
        .expect_err(
            "Verification should fail when the point is not on the curve",
        );
    let circuit_not_in_subgroup = G2EllipticCurveCircuit::new(
        DEGREE_BITS,
        not_in_subgroup,
        subgroup_check,
    );
    let is_satisfied = MockProver::run(
        DEGREE_BITS as u32,
        &circuit_not_in_subgroup,
        Vec::new(),
    )
    .expect("Mock prover run failure")
    .verify();
    match subgroup_check {
        SubgroupCheck::None => {
            is_satisfied.expect(
                "Verification shouldn't fail when the subgroup isn't checked",
            );
        }
        _ => {
            is_satisfied.expect_err(
                "Verification should fail when the subgroup isn't checked",
            );
        }
    }
}

/// Runs [`test_g2_membership_for_subgroup_check`] for all [`SubgroupCheck`]s.
#[test]
fn test_g2_membership() {
    test_g2_membership_for_subgroup_check(SubgroupCheck::Dlzz);
    test_g2_membership_for_subgroup_check(SubgroupCheck::Glv);
    test_g2_membership_for_subgroup_check(SubgroupCheck::Naive);
    test_g2_membership_for_subgroup_check(SubgroupCheck::None);
}
