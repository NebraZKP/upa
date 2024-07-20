use crate::EccPrimeField;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fq, G1Affine, G2Affine};
use halo2_ecc::{
    bn254,
    ecc::EcPoint,
    fields::{fp::FpChip, fp2::Fp2Chip, vector::FieldVector, FieldChip},
};

pub type G1Point<F> =
    EcPoint<F, <FpChip<'static, F, Fq> as FieldChip<F>>::FieldPoint>;
pub type G2Point<F> = EcPoint<
    F,
    FieldVector<<FpChip<'static, F, Fq> as FieldChip<F>>::FieldPoint>,
>;
/// Pairing-ready pair of elliptic curve points
pub(crate) type EcPointPair<F> = (G1Point<F>, G2Point<F>);

/// Returns `g1_point` as a [`G1Affine`] point.
pub fn get_assigned_value_g1point<F: EccPrimeField>(
    fp_chip: &bn254::FpChip<F>,
    g1_point: &G1Point<F>,
) -> G1Affine {
    let x = fp_chip.get_assigned_value(g1_point.x().as_ref());
    let y = fp_chip.get_assigned_value(g1_point.y().as_ref());
    G1Affine { x, y }
}

/// Returns `g2_point` as a [`G2Affine`] point.
pub fn get_assigned_value_g2point<F: EccPrimeField>(
    fp_chip: &bn254::FpChip<F>,
    g2_point: &G2Point<F>,
) -> G2Affine {
    let fp2_chip = Fp2Chip::new(fp_chip);
    let x =
        FieldVector(g2_point.x().0.iter().map(|uint| uint.into()).collect());
    let y =
        FieldVector(g2_point.y().0.iter().map(|uint| uint.into()).collect());
    let x = fp2_chip.get_assigned_value(&x);
    let y = fp2_chip.get_assigned_value(&y);
    G2Affine { x, y }
}

/// Assigned G1 and G2 points where we want a unique representation, e.g. for
/// proof elements, where the protocol should not introduce malleability of
/// the incoming proofs.
pub type G1InputPoint<F> =
    EcPoint<F, <FpChip<'static, F, Fq> as FieldChip<F>>::ReducedFieldPoint>;
pub type G2InputPoint<F> = EcPoint<
    F,
    FieldVector<<FpChip<'static, F, Fq> as FieldChip<F>>::ReducedFieldPoint>,
>;

/// Converts `g1_point` into a [`G1Point`].
pub fn g1_input_point_to_inner<F: EccPrimeField>(
    g1_point: &G1InputPoint<F>,
) -> G1Point<F> {
    EcPoint::new(g1_point.x().inner().clone(), g1_point.y().inner().clone())
}

/// Converts `g2_point` into a [`G2Point`].
pub fn g2_input_point_to_inner<F: EccPrimeField>(
    g2_point: &G2InputPoint<F>,
) -> G2Point<F> {
    let x = FieldVector(
        g2_point
            .x()
            .0
            .iter()
            .map(|reduced| reduced.inner().clone())
            .collect(),
    );
    let y = FieldVector(
        g2_point
            .y()
            .0
            .iter()
            .map(|reduced| reduced.inner().clone())
            .collect(),
    );
    EcPoint::new(x, y)
}
