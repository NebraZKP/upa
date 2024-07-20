extern crate alloc;

use crate::{
    batch_verify::common::{
        ecc::{
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
    ecc::{check_is_on_curve, scalar_multiply, EcPoint},
    fields::{
        fp::{FpChip, Reduced},
        vector::FieldVector,
        FieldChip,
    },
};
use itertools::Itertools;

pub const WINDOW_BITS: usize = 4;

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
