extern crate alloc;

use self::fp2_selectable_chip::Fp2SelectableChip;
use super::ecc::constants::BN254_CURVE_PARAMETER_BITS;
use crate::{
    batch_verify::common::{
        ecc::{
            constants::{BN254_CURVE_PARAMETER, XI_Q_2, XI_Q_3},
            g1_input_point_to_inner, g2_input_point_to_inner,
            get_assigned_value_g1point, get_assigned_value_g2point,
            G1InputPoint, G1Point, G2InputPoint, G2Point,
        },
        types::{Proof, PublicInputs, VerificationKey},
    },
    utils::{
        commitment_point::{get_g1_point_limbs, get_g2_point_limbs},
        hashing::{
            FieldElementRepresentation, InCircuitHash, InCircuitPartialHash,
            PoseidonHasher,
        },
        reduced::FromReduced,
    },
    EccPrimeField,
};
use halo2_base::{
    gates::{GateChip, GateInstructions},
    halo2_proofs::halo2curves::bn256::{Fq, Fq12, Fq2, Fr, G1Affine, G2Affine},
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bn254::{self, pairing::PairingChip, Fp12Chip, Fp2Chip, FqPoint},
    ecc::{check_is_on_curve, scalar_multiply, EcPoint, EccChip},
    fields::{
        fp::{FpChip, Reduced},
        vector::FieldVector,
        FieldChip,
    },
};
use itertools::Itertools;

pub const WINDOW_BITS: usize = 4;
pub const WINDOW_BITS_G2_SUBGROUP_CHECK: usize = 3;

pub struct BatchVerifierChip<'a, F>
where
    F: EccPrimeField,
{
    fp_chip: &'a FpChip<'a, F, Fq>,
}

impl<'a, F> BatchVerifierChip<'a, F>
where
    F: EccPrimeField,
{
    pub fn new(fp_chip: &'a FpChip<F, Fq>) -> BatchVerifierChip<'a, F> {
        BatchVerifierChip { fp_chip }
    }

    pub fn fp_chip(&self) -> &FpChip<'a, F, Fq> {
        self.fp_chip
    }

    pub(crate) fn assign_fq_reduced(
        &self,
        ctx: &mut Context<F>,
        value: Fq,
    ) -> Reduced<ProperCrtUint<F>, Fq> {
        let assigned = self.fp_chip.load_private(ctx, value);
        self.fp_chip.enforce_less_than(ctx, assigned)
    }

    pub(crate) fn assign_fq2_reduced(
        &self,
        ctx: &mut Context<F>,
        value: Fq2,
    ) -> FieldVector<Reduced<ProperCrtUint<F>, Fq>> {
        FieldVector(vec![
            self.assign_fq_reduced(ctx, value.c0),
            self.assign_fq_reduced(ctx, value.c1),
        ])
    }

    pub(crate) fn assign_g1_reduced(
        &self,
        ctx: &mut Context<F>,
        value: G1Affine,
    ) -> EcPoint<F, Reduced<ProperCrtUint<F>, Fq>> {
        EcPoint::new(
            self.assign_fq_reduced(ctx, value.x),
            self.assign_fq_reduced(ctx, value.y),
        )
    }

    pub(crate) fn assign_g2_reduced(
        &self,
        ctx: &mut Context<F>,
        value: G2Affine,
    ) -> EcPoint<F, FieldVector<Reduced<ProperCrtUint<F>, Fq>>> {
        EcPoint::new(
            self.assign_fq2_reduced(ctx, value.x),
            self.assign_fq2_reduced(ctx, value.y),
        )
    }

    pub fn assign_verification_key(
        &self,
        ctx: &mut Context<F>,
        vk: &VerificationKey,
    ) -> AssignedVerificationKey<F> {
        assert!(vk.has_commitment(), "vk must be padded already");

        let result = AssignedVerificationKey {
            alpha: self.assign_g1_reduced(ctx, vk.alpha),
            beta: self.assign_g2_reduced(ctx, vk.beta),
            gamma: self.assign_g2_reduced(ctx, vk.gamma),
            delta: self.assign_g2_reduced(ctx, vk.delta),
            s: vk
                .s
                .iter()
                .copied()
                .map(|s| self.assign_g1_reduced(ctx, s))
                .collect(),
            h1: self.assign_g2_reduced(ctx, vk.h1[0]),
            h2: self.assign_g2_reduced(ctx, vk.h2[0]),
        };

        self.assert_vk_points_on_curve(ctx, &result);
        result
    }

    pub fn assign_public_inputs(
        &self,
        ctx: &mut Context<F>,
        inputs: &PublicInputs<F>,
    ) -> AssignedPublicInputs<F> {
        AssignedPublicInputs(ctx.assign_witnesses(inputs.0.iter().copied()))
    }

    pub fn assign_proof(
        &self,
        ctx: &mut Context<F>,
        proof: &Proof,
    ) -> AssignedProof<F> {
        assert_eq!(
            proof.m.len(),
            proof.pok.len(),
            "Invalid Proof. Inconsistent M, pok lengths."
        );
        match proof.m.len() {
            0 => panic!("Proof.m not padded prior to assignment."),
            1 => {}
            num_commitments => panic!("Multiple commitments are not supported. {num_commitments} were present."),
        }
        let result = AssignedProof {
            a: self.assign_g1_reduced(ctx, proof.a),
            b: self.assign_g2_reduced(ctx, proof.b),
            c: self.assign_g1_reduced(ctx, proof.c),
            m: self.assign_g1_reduced(ctx, proof.m[0]),
            pok: self.assign_g1_reduced(ctx, proof.pok[0]),
        };
        self.assert_proof_points_on_curve(ctx, &result);
        result
    }

    /// Asserts `g1_point` is a valid [`G1Affine`] point.
    pub(crate) fn assert_g1_point_is_on_curve(
        &self,
        ctx: &mut Context<F>,
        g1_point: &G1InputPoint<F>,
    ) {
        check_is_on_curve::<_, _, G1Affine>(
            self.fp_chip(),
            ctx,
            &g1_input_point_to_inner(g1_point),
        );
    }

    /// Asserts `g2_point` is a valid [`G2Affine`] point.
    pub(crate) fn assert_g2_point_is_on_curve(
        &self,
        ctx: &mut Context<F>,
        g2_point: &G2InputPoint<F>,
    ) {
        let fp2_chip = Fp2Chip::new(self.fp_chip());
        check_is_on_curve::<_, _, G2Affine>(
            &fp2_chip,
            ctx,
            &g2_input_point_to_inner(g2_point),
        );
    }

    /// Asserts that, given a `proof = (a, b, c)`, `a` and `c` belong
    /// to [`G1Affine`] and `b` belongs to [`G2Affine`].
    ///
    /// # Specification
    ///
    /// This function performs **Step 1b: Check the proof and verifying key points**
    /// in the universal batch verifier spec.
    pub(crate) fn assert_proof_points_on_curve(
        &self,
        ctx: &mut Context<F>,
        proof: &AssignedProof<F>,
    ) {
        self.assert_g1_point_is_on_curve(ctx, &proof.a);
        self.assert_g2_point_is_on_curve(ctx, &proof.b);
        self.assert_g1_point_is_on_curve(ctx, &proof.c);
        self.assert_g1_point_is_on_curve(ctx, &proof.m);
        self.assert_g1_point_is_on_curve(ctx, &proof.pok);

        // Subgroup check for the g2 point
        self.assert_g2_subgroup_membership(
            ctx,
            &FromReduced::from_reduced(&proof.b),
        );
    }

    /// Asserts that all points in a [`VerificationKey`] are valid affine
    /// elliptic curve points
    ///
    /// # Specification
    ///
    /// This function performs **Step 1b: Check the proof and verifying key points**
    /// in the universal batch verifier spec.
    pub(crate) fn assert_vk_points_on_curve(
        &self,
        ctx: &mut Context<F>,
        vk: &AssignedVerificationKey<F>,
    ) {
        self.assert_g1_point_is_on_curve(ctx, &vk.alpha);
        self.assert_g2_point_is_on_curve(ctx, &vk.beta);
        self.assert_g2_point_is_on_curve(ctx, &vk.gamma);
        self.assert_g2_point_is_on_curve(ctx, &vk.delta);
        for s in vk.s.iter() {
            self.assert_g1_point_is_on_curve(ctx, s);
        }
        self.assert_g2_point_is_on_curve(ctx, &vk.h1);
        self.assert_g2_point_is_on_curve(ctx, &vk.h2);

        // Subgroup check for G2 points
        let beta = FromReduced::from_reduced(&vk.beta);
        let gamma = FromReduced::from_reduced(&vk.gamma);
        let delta = FromReduced::from_reduced(&vk.delta);
        let h1 = FromReduced::from_reduced(&vk.h1);
        let h2 = FromReduced::from_reduced(&vk.h2);

        self.assert_g2_subgroup_membership(ctx, &beta);
        self.assert_g2_subgroup_membership(ctx, &gamma);
        self.assert_g2_subgroup_membership(ctx, &delta);
        self.assert_g2_subgroup_membership(ctx, &h1);
        self.assert_g2_subgroup_membership(ctx, &h2);
    }

    /// Return r^0, r, ... r^{len - 1}
    pub(crate) fn scalar_powers(
        ctx: &mut Context<F>,
        r: AssignedValue<F>,
        len: usize,
    ) -> Vec<AssignedValue<F>> {
        let gate = GateChip::default();
        let mut result = Vec::with_capacity(len);
        result.push(ctx.load_constant(F::one()));
        if len > 1 {
            result.push(r);
            let mut current = r;
            for _ in 2..len {
                current = gate.mul(ctx, current, r);
                result.push(current);
            }
        }
        debug_assert_eq!(result.len(), len);
        result
    }

    /// Returns `(scalar_i * A_i, B_i)`
    pub(crate) fn scale_pairs(
        &self,
        ctx: &mut Context<F>,
        scalars: &[AssignedValue<F>],
        pairs: &[(G1Point<F>, G2Point<F>)],
    ) -> Vec<(G1Point<F>, G2Point<F>)> {
        let mut result = Vec::with_capacity(pairs.len());
        for ((g1, g2), scalar) in pairs.iter().zip_eq(scalars.iter()) {
            result.push((
                scalar_multiply::<_, FpChip<F, Fq>, G1Affine>(
                    self.fp_chip,
                    ctx,
                    g1.clone(),
                    vec![*scalar],
                    F::NUM_BITS as usize,
                    WINDOW_BITS,
                ),
                g2.clone(),
            ))
        }
        result
    }

    pub(crate) fn multi_pairing(
        &self,
        ctx: &mut Context<F>,
        pairs: &[(G1Point<F>, G2Point<F>)],
    ) -> FqPoint<F> {
        // TODO: try to make this more generic.  Current problem is that
        // halo2-ecc::bn254::pairing::PairingChip insists on a
        // halo2-ecc::bn254::FpChip, which is a concrete implementation
        // (i.e. the PairingChip is not generic over types implementing the
        // FieldChip trait, say).  So we cannot pass in self.fp_chip, which is
        // a generic FieldChip.

        let pairing_chip = PairingChip::<F>::new(self.fp_chip);
        let pair_refs = pairs.iter().map(|(a, b)| (a, b)).collect();
        let miller_out = pairing_chip.multi_miller_loop(ctx, pair_refs);
        pairing_chip.final_exp(ctx, miller_out)
    }

    /// Constrain final_exp_out == 1 in GT
    ///
    /// # Specification
    ///
    /// This function performs **Step 7: Check final result** of the
    /// universal batch verifier spec.
    pub(crate) fn check_pairing_result(
        &self,
        ctx: &mut Context<F>,
        final_exp_out: &FqPoint<F>,
    ) {
        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let fp12_one = fp12_chip.load_constant(ctx, Fq12::one());
        fp12_chip.assert_equal(ctx, final_exp_out, fp12_one);
    }

    /// Applies the Frobenius endomorphism to `point`.
    /// This is the untwist-Frobenius-twist `\psi = \phi^{-1} \circ \pi \circ \phi`
    /// automorphism as mentioned in https://eprint.iacr.org/2022/352.pdf page 4.
    pub(crate) fn apply_g2_endomorphism(
        &self,
        ctx: &mut Context<F>,
        point: &G2Point<F>,
    ) -> G2Point<F> {
        let chip = Fp2Chip::new(self.fp_chip());
        let EcPoint { x, y, .. } = point;
        let xi_q_3 = chip.load_constant(ctx, XI_Q_3);
        let xi_q_2 = chip.load_constant(ctx, XI_Q_2);
        let frob_x = chip.conjugate(ctx, x.clone());
        let frob_y = chip.conjugate(ctx, y.clone());
        let new_x = chip.mul(ctx, frob_x, xi_q_3);
        let new_y = chip.mul(ctx, frob_y, xi_q_2);
        EcPoint::new(new_x, new_y)
    }

    /// Asserts that `point` belongs to the subgroup of G2 of order
    /// equal to that of `F`. This is the fully optimized check that asserts
    /// `[x+1]P + \psi([x]P) + \psi^2([x]P) = \psi^3([2x]P)` as in
    /// https://eprint.iacr.org/2022/348.pdf.
    pub fn assert_g2_subgroup_membership(
        &self,
        ctx: &mut Context<F>,
        point: &G2Point<F>,
    ) {
        // Load the ECC and Fp2 chips
        let chip = Fp2Chip::new(self.fp_chip());
        let selectable_chip = Fp2SelectableChip { fp2_chip: &chip };
        let ec_chip = EccChip::new(&selectable_chip);
        // Load and assign the BN254_CURVE_PARAMETER
        let x = ctx.load_constant(F::from(BN254_CURVE_PARAMETER));
        // [x]P
        let xp = ec_chip.scalar_mult::<G2Affine>(
            ctx,
            point.clone(),
            vec![x],
            BN254_CURVE_PARAMETER_BITS,
            WINDOW_BITS_G2_SUBGROUP_CHECK,
        );
        // [2x]P
        let two_xp = ec_chip.double(ctx, xp.clone());
        // [x+1]P
        let xp_plus_one = ec_chip.add_unequal(ctx, xp.clone(), point, true);
        // \psi([x]P)
        let psi_xp = self.apply_g2_endomorphism(ctx, &xp);
        // \psi^2([x]P)
        let psi2_xp = self.apply_g2_endomorphism(ctx, &psi_xp);
        // \psi([2x]P)
        let psi_two_xp = self.apply_g2_endomorphism(ctx, &two_xp);
        // \psi^2([2x]P)
        let psi2_two_xp = self.apply_g2_endomorphism(ctx, &psi_two_xp);
        // \psi^3([2x]P)
        let psi3_two_xp = self.apply_g2_endomorphism(ctx, &psi2_two_xp);
        // [x+1]P + \psi([x]P)
        let lhs = ec_chip.add_unequal(ctx, xp_plus_one, psi_xp, true);
        // [x+1]P + \psi([x]P) + \psi^2([x]P)
        let lhs = ec_chip.add_unequal(ctx, lhs, psi2_xp, true);
        // [x+1]P + \psi([x]P) + \psi^2([x]P) = \psi^3([2x]P)
        ec_chip.assert_equal(ctx, lhs, psi3_two_xp);
    }

    /// Asserts that `point` belongs to the subgroup of G2 of order
    /// equal to that of `F`. This is a partially optimized check that asserts
    /// `[6x^2]P = \psi(P)`.
    #[allow(dead_code)] // kept for testing and benchmarking
    pub(crate) fn assert_g2_subgroup_membership_glv(
        &self,
        ctx: &mut Context<F>,
        point: &G2Point<F>,
    ) {
        // Load the ECC and Fp2 chips
        let chip = Fp2Chip::new(self.fp_chip());
        let selectable_chip = Fp2SelectableChip { fp2_chip: &chip };
        let ec_chip = EccChip::new(&selectable_chip);
        // Load and assign the BN254_CURVE_PARAMETER.
        // TODO: load the constant 6x^2 in one go directly
        let x = ctx.load_constant(F::from(BN254_CURVE_PARAMETER));
        let x_2 = self.fp_chip().gate().mul(ctx, x, x);
        let six = ctx.load_constant(F::from(6));
        let six_x_2 = self.fp_chip().gate().mul(ctx, six, x_2);
        const SIX_X_2_BITS: usize = 127;
        // [6x^2]P
        let six_x_2_p = ec_chip.scalar_mult::<G2Affine>(
            ctx,
            point.clone(),
            vec![six_x_2],
            SIX_X_2_BITS,
            WINDOW_BITS,
        );
        // \psi(P)
        let psi_p = self.apply_g2_endomorphism(ctx, point);
        // \psi(P) = [6x^2]P
        ec_chip.assert_equal(ctx, six_x_2_p, psi_p);
    }

    /// Asserts that `point` belongs to the subgroup of G2 of order
    /// equal to that of `F`. This is the naive check that asserts
    /// `[r]P = O`.
    #[allow(dead_code)] // kept for testing and benchmarking
    pub(crate) fn assert_g2_subgroup_membership_naive(
        &self,
        ctx: &mut Context<F>,
        point: &G2Point<F>,
    ) {
        // Load the ECC and Fp2 chips
        let chip = Fp2Chip::new(self.fp_chip());
        let selectable_chip = Fp2SelectableChip { fp2_chip: &chip };
        let ec_chip = EccChip::new(&selectable_chip);
        // Load and assign `r-1`
        let r_minus_one = ctx.load_constant(F::zero() - F::one());
        // [r-1]P
        let r_minus_one_p = ec_chip.scalar_mult::<G2Affine>(
            ctx,
            point.clone(),
            vec![r_minus_one],
            F::NUM_BITS as usize,
            WINDOW_BITS,
        );
        // - P
        let minus_p = ec_chip.negate(ctx, point.clone());
        // [r-1] P = - P
        ec_chip.assert_equal(ctx, r_minus_one_p, minus_p);
    }
}

/// In-circuit Groth16 Verification Key
#[derive(Clone, Debug)]
pub struct AssignedVerificationKey<F: EccPrimeField> {
    pub alpha: G1InputPoint<F>,
    pub beta: G2InputPoint<F>,
    pub gamma: G2InputPoint<F>,
    pub delta: G2InputPoint<F>,
    pub s: Vec<G1InputPoint<F>>,
    pub h1: G2InputPoint<F>,
    pub h2: G2InputPoint<F>,
}

impl<F: EccPrimeField> AssignedVerificationKey<F> {
    /// Returns a vector with the limbs of `self`, where each FQ element
    /// consists of `num_limbs` elements of `F`.
    pub fn limbs(&self, num_limbs: usize) -> Vec<AssignedValue<F>> {
        let mut result = get_g1_point_limbs(&self.alpha, num_limbs);
        result.append(&mut get_g2_point_limbs(&self.beta, num_limbs));
        result.append(&mut get_g2_point_limbs(&self.gamma, num_limbs));
        result.append(&mut get_g2_point_limbs(&self.delta, num_limbs));
        for s_i in self.s.iter() {
            result.append(&mut get_g1_point_limbs(s_i, num_limbs));
        }
        result.append(&mut get_g2_point_limbs(&self.h1, num_limbs));
        result.append(&mut get_g2_point_limbs(&self.h2, num_limbs));
        result
    }
}

impl AssignedVerificationKey<Fr> {
    pub fn get_assigned_value(
        &self,
        fp_chip: &bn254::FpChip<Fr>,
    ) -> VerificationKey {
        VerificationKey {
            alpha: get_assigned_value_g1point(
                fp_chip,
                &g1_input_point_to_inner(&self.alpha),
            ),
            beta: get_assigned_value_g2point(
                fp_chip,
                &g2_input_point_to_inner(&self.beta),
            ),
            gamma: get_assigned_value_g2point(
                fp_chip,
                &g2_input_point_to_inner(&self.gamma),
            ),
            delta: get_assigned_value_g2point(
                fp_chip,
                &g2_input_point_to_inner(&self.delta),
            ),
            s: self
                .s
                .iter()
                .map(|s_i| {
                    get_assigned_value_g1point(
                        fp_chip,
                        &g1_input_point_to_inner(s_i),
                    )
                })
                .collect(),
            h1: vec![get_assigned_value_g2point(
                fp_chip,
                &g2_input_point_to_inner(&self.h1),
            )],
            h2: vec![get_assigned_value_g2point(
                fp_chip,
                &g2_input_point_to_inner(&self.h2),
            )],
        }
    }
}

/// Absorb an in-circuit VerificationKey.
impl<F: EccPrimeField> InCircuitHash<F> for AssignedVerificationKey<F>
where
    G1InputPoint<F>: InCircuitHash<F>,
    G2InputPoint<F>: InCircuitHash<F>,
{
    fn hash(&self, hasher: &mut PoseidonHasher<F>) {
        self.alpha.hash(hasher);
        self.beta.hash(hasher);
        self.gamma.hash(hasher);
        self.delta.hash(hasher);
        for s in self.s.iter() {
            s.hash(hasher);
        }
        self.h1.hash(hasher);
        self.h2.hash(hasher);
    }
}

impl<F: EccPrimeField> FieldElementRepresentation<F>
    for AssignedVerificationKey<F>
{
    fn representation(&self) -> Vec<AssignedValue<F>> {
        let s_repr =
            self.s.iter().flat_map(|s_i| s_i.representation()).collect();
        [
            self.alpha.representation(),
            self.beta.representation(),
            self.gamma.representation(),
            self.delta.representation(),
            s_repr,
        ]
        .concat()
    }

    fn num_elements(&self) -> usize {
        self.alpha.num_elements()
            + self.beta.num_elements()
            + self.gamma.num_elements()
            + self.delta.num_elements()
            + self.s.len() * self.s[0].num_elements()
    }
}

impl<F: EccPrimeField> InCircuitPartialHash<F> for AssignedVerificationKey<F>
where
    G1InputPoint<F>: InCircuitHash<F>,
    G2InputPoint<F>: InCircuitHash<F>,
{
    fn max_parts(&self) -> usize {
        // Since `self` is assigned, it is expected to be padded to the max length
        // so we can take `max_parts` from `self` instead of a configuration.
        self.s.len()
    }

    fn partial_hash(&self, parts: usize, hasher: &mut PoseidonHasher<F>) {
        assert!(parts < self.max_parts(), "Parts out of range");
        self.alpha.hash(hasher);
        self.beta.hash(hasher);
        self.gamma.hash(hasher);
        self.delta.hash(hasher);
        for s in self.s.iter().take(parts + 1) {
            s.hash(hasher);
        }
    }

    fn parts_to_num_elements(&self, parts: usize) -> usize {
        // For NUM_LIMBS = 3, this is
        // 6 field elements per g1 point + 12 field elements per g2 point.
        self.alpha.num_elements()
            + self.beta.num_elements()
            + self.gamma.num_elements()
            + self.delta.num_elements()
            + self.s[0].num_elements() * (parts + 1)
    }
}

/// In-circuit Groth16 proof
#[derive(Clone, Debug)]
pub struct AssignedProof<F: EccPrimeField> {
    pub a: G1InputPoint<F>,
    pub b: G2InputPoint<F>,
    pub c: G1InputPoint<F>,
    pub m: G1InputPoint<F>,
    pub pok: G1InputPoint<F>,
}

impl<F: EccPrimeField> InCircuitHash<F> for AssignedProof<F> {
    fn hash(&self, hasher: &mut PoseidonHasher<F>) {
        self.a.hash(hasher);
        self.b.hash(hasher);
        self.c.hash(hasher);
        self.m.hash(hasher);
        self.pok.hash(hasher);
    }
}

/// In-circuit public inputs
#[derive(Clone, Debug)]
pub struct AssignedPublicInputs<F: EccPrimeField>(pub Vec<AssignedValue<F>>);

impl<F: EccPrimeField> IntoIterator for AssignedPublicInputs<F> {
    type Item = AssignedValue<F>;
    type IntoIter = alloc::vec::IntoIter<AssignedValue<F>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Implementation of the [`Selectable`] trait for [`Fp2Chip`].
pub mod fp2_selectable_chip {
    use crate::EccPrimeField;
    use halo2_base::{self, AssignedValue, Context};
    use halo2_ecc::{
        bigint::{select, select_by_indicator, CRTInteger, ProperCrtUint},
        bn254::Fp2Chip,
        fields::{vector::FieldVector, FieldChip, Selectable},
    };
    use num_bigint::BigUint;

    type Fp2FieldPoint<F> = FieldVector<ProperCrtUint<F>>;

    /// Wrapper of a [`Fp2Chip`] implementing [`Selectable`].
    #[derive(Clone, Copy, Debug)]
    pub struct Fp2SelectableChip<'a, F>
    where
        F: EccPrimeField,
    {
        pub fp2_chip: &'a Fp2Chip<'a, F>,
    }

    impl<'a, F> FieldChip<F> for Fp2SelectableChip<'a, F>
    where
        F: EccPrimeField,
    {
        const PRIME_FIELD_NUM_BITS: u32 =
            <Fp2Chip<'a, F> as FieldChip<F>>::PRIME_FIELD_NUM_BITS;
        type FieldPoint = <Fp2Chip<'a, F> as FieldChip<F>>::FieldPoint;
        type UnsafeFieldPoint =
            <Fp2Chip<'a, F> as FieldChip<F>>::UnsafeFieldPoint;
        type FieldType = <Fp2Chip<'a, F> as FieldChip<F>>::FieldType;
        type RangeChip = <Fp2Chip<'a, F> as FieldChip<F>>::RangeChip;
        type ReducedFieldPoint =
            <Fp2Chip<'a, F> as FieldChip<F>>::ReducedFieldPoint;

        fn native_modulus(&self) -> &BigUint {
            self.fp2_chip.native_modulus()
        }

        fn range(&self) -> &Self::RangeChip {
            self.fp2_chip.range()
        }

        fn limb_bits(&self) -> usize {
            self.fp2_chip.limb_bits()
        }

        fn get_assigned_value(
            &self,
            x: &Self::UnsafeFieldPoint,
        ) -> Self::FieldType {
            self.fp2_chip.get_assigned_value(x)
        }

        fn load_private(
            &self,
            ctx: &mut Context<F>,
            fe: Self::FieldType,
        ) -> Self::FieldPoint {
            self.fp2_chip.load_private(ctx, fe)
        }

        fn load_constant(
            &self,
            ctx: &mut Context<F>,
            fe: Self::FieldType,
        ) -> Self::FieldPoint {
            self.fp2_chip.load_constant(ctx, fe)
        }

        fn add_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            b: impl Into<Self::UnsafeFieldPoint>,
        ) -> Self::UnsafeFieldPoint {
            self.fp2_chip.add_no_carry(ctx, a, b)
        }

        fn add_constant_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            c: Self::FieldType,
        ) -> Self::UnsafeFieldPoint {
            self.fp2_chip.add_constant_no_carry(ctx, a, c)
        }

        fn sub_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            b: impl Into<Self::UnsafeFieldPoint>,
        ) -> Self::UnsafeFieldPoint {
            self.fp2_chip.sub_no_carry(ctx, a, b)
        }

        fn negate(
            &self,
            ctx: &mut Context<F>,
            a: Self::FieldPoint,
        ) -> Self::FieldPoint {
            self.fp2_chip.negate(ctx, a)
        }

        fn scalar_mul_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            c: i64,
        ) -> Self::UnsafeFieldPoint {
            self.fp2_chip.scalar_mul_no_carry(ctx, a, c)
        }

        fn scalar_mul_and_add_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            b: impl Into<Self::UnsafeFieldPoint>,
            c: i64,
        ) -> Self::UnsafeFieldPoint {
            self.fp2_chip.scalar_mul_and_add_no_carry(ctx, a, b, c)
        }

        fn mul_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            b: impl Into<Self::UnsafeFieldPoint>,
        ) -> Self::UnsafeFieldPoint {
            self.fp2_chip.mul_no_carry(ctx, a, b)
        }

        fn check_carry_mod_to_zero(
            &self,
            ctx: &mut Context<F>,
            a: Self::UnsafeFieldPoint,
        ) {
            self.fp2_chip.check_carry_mod_to_zero(ctx, a)
        }

        fn carry_mod(
            &self,
            ctx: &mut Context<F>,
            a: Self::UnsafeFieldPoint,
        ) -> Self::FieldPoint {
            self.fp2_chip.carry_mod(ctx, a)
        }

        fn range_check(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            max_bits: usize,
        ) {
            self.fp2_chip.range_check(ctx, a, max_bits)
        }

        fn enforce_less_than(
            &self,
            ctx: &mut Context<F>,
            a: Self::FieldPoint,
        ) -> Self::ReducedFieldPoint {
            self.fp2_chip.enforce_less_than(ctx, a)
        }

        fn is_soft_zero(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::FieldPoint>,
        ) -> AssignedValue<F> {
            self.fp2_chip.is_soft_zero(ctx, a)
        }

        fn is_soft_nonzero(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::FieldPoint>,
        ) -> AssignedValue<F> {
            self.fp2_chip.is_soft_nonzero(ctx, a)
        }

        fn is_zero(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::FieldPoint>,
        ) -> AssignedValue<F> {
            self.fp2_chip.is_zero(ctx, a)
        }

        fn is_equal_unenforced(
            &self,
            ctx: &mut Context<F>,
            a: Self::ReducedFieldPoint,
            b: Self::ReducedFieldPoint,
        ) -> AssignedValue<F> {
            self.fp2_chip.is_equal_unenforced(ctx, a, b)
        }

        fn assert_equal(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::FieldPoint>,
            b: impl Into<Self::FieldPoint>,
        ) {
            self.fp2_chip.assert_equal(ctx, a, b)
        }
    }

    impl<'a, F> Selectable<F, Fp2FieldPoint<F>> for Fp2SelectableChip<'a, F>
    where
        F: EccPrimeField,
    {
        fn select(
            &self,
            ctx: &mut Context<F>,
            a: Fp2FieldPoint<F>,
            b: Fp2FieldPoint<F>,
            sel: AssignedValue<F>,
        ) -> Fp2FieldPoint<F> {
            assert_eq!(
                a.0.len(),
                2,
                "Fp2 field points should have two Fp coordinates"
            );
            assert_eq!(
                b.0.len(),
                2,
                "Fp2 field points should have two Fp coordinates"
            );
            let a_0 = &a.0[0];
            let a_1 = &a.0[1];
            let b_0 = &b.0[0];
            let b_1 = &b.0[1];
            let c_0_crt =
                select::crt(self.gate(), ctx, a_0.into(), b_0.into(), sel);
            let c_1_crt =
                select::crt(self.gate(), ctx, a_1.into(), b_1.into(), sel);
            // TODO: why am I getting memory errors if I simply transmute
            // here? The extra constraints shouldn't be necessary here.
            // See the implementation of the trait
            // impl<'range, F, Fp> Selectable<F, ProperCrtUint<F>>
            // for FpChip<'range, F, Fp>

            let c_0 = self.fp2_chip.fp_chip().carry_mod(ctx, c_0_crt);
            let c_1 = self.fp2_chip.fp_chip().carry_mod(ctx, c_1_crt);

            FieldVector(vec![c_0, c_1])
        }

        fn select_by_indicator(
            &self,
            ctx: &mut Context<F>,
            a: &impl AsRef<[Fp2FieldPoint<F>]>,
            coeffs: &[AssignedValue<F>],
        ) -> Fp2FieldPoint<F> {
            let points = a.as_ref();
            let num_points = points.len();
            let mut first_coordinate: Vec<CRTInteger<F>> =
                Vec::with_capacity(num_points);
            let mut second_coordinate: Vec<CRTInteger<F>> =
                Vec::with_capacity(num_points);
            for point in points {
                assert_eq!(
                    point.0.len(),
                    2,
                    "Fp2 field points should have two Fp coordinates"
                );
                let p_0 = &point.0[0];
                let p_1 = &point.0[1];
                first_coordinate.push(p_0.into());
                second_coordinate.push(p_1.into());
            }
            let c_0_crt = select_by_indicator::crt(
                self.gate(),
                ctx,
                &first_coordinate,
                coeffs,
                &self.fp2_chip.fp_chip().limb_bases,
            );
            let c_1_crt = select_by_indicator::crt(
                self.gate(),
                ctx,
                &second_coordinate,
                coeffs,
                &self.fp2_chip.fp_chip().limb_bases,
            );

            // TODO: why am I getting memory errors if I simply transmute
            // here? The extra constraints shouldn't be necessary here.
            let c_0 = self.fp2_chip.fp_chip().carry_mod(ctx, c_0_crt);
            let c_1 = self.fp2_chip.fp_chip().carry_mod(ctx, c_1_crt);

            FieldVector(vec![c_0, c_1])
        }
    }
}
