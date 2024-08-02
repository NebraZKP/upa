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

/// BN254 constants
pub mod constants {
    use halo2_base::halo2_proofs::halo2curves::bn256::{Fq, Fq2};

    /// XI = u + 9, where u^2 = -1 is the element defining
    /// the field extension from Fq to Fq2.
    pub const XI: Fq2 = Fq2 {
        c0: Fq::from_raw([9, 0, 0, 0]),
        c1: Fq::one(),
    };

    /// (q - 1)/2 as little-endian u64 limbs
    pub const Q_MINUS_ONE_OVER_TWO: [u64; 4] = [
        0x9e10460b6c3e7ea3,
        0xcbc0b548b438e546,
        0xdc2822db40c0ac2e,
        0x183227397098d014,
    ];

    /// (q - 1)/3 as little-endian u64 limbs
    pub const Q_MINUS_ONE_OVER_THREE: [u64; 4] = [
        0x69602eb24829a9c2,
        0xdd2b2385cd7b4384,
        0xe81ac1e7808072c9,
        0x10216f7ba065e00d,
    ];

    /// XI^{(q-1)/2}
    pub const XI_Q_2: Fq2 = Fq2 {
        c0: Fq::from_raw([
            0xdc54014671a0135a,
            0xdbaae0eda9c95998,
            0xdc5ec698b6e2f9b9,
            0x063cf305489af5dc,
        ]),
        c1: Fq::from_raw([
            0x82d37f632623b0e3,
            0x21807dc98fa25bd2,
            0x0704b5a7ec796f2b,
            0x07c03cbcac41049a,
        ]),
    };

    /// XI^{(q-1)/3}
    pub const XI_Q_3: Fq2 = Fq2 {
        c0: Fq::from_raw([
            0x99e39557176f553d,
            0xb78cc310c2c3330c,
            0x4c0bec3cf559b143,
            0x2fb347984f7911f7,
        ]),
        c1: Fq::from_raw([
            0x1665d51c640fcba2,
            0x32ae2a1d0b7c9dce,
            0x4ba4cc8bd75a0794,
            0x16c9e55061ebae20,
        ]),
    };

    /// BN254 curve parameter
    pub const BN254_CURVE_PARAMETER: u64 = 4965661367192848881;

    /// BN245 curve parameter bits
    pub const BN254_CURVE_PARAMETER_BITS: usize = 63;
}
