use crate::{
    batch_verify::{
        common::{
            chip::{
                AssignedProof, AssignedPublicInputs, AssignedVerificationKey,
                BatchVerifierChip, WINDOW_BITS,
            },
            ecc::{G1Point, G2Point},
            types::{Proof, PublicInputs, VerificationKey},
        },
        fixed::types::{
            UPA_V0_9_0_CHALLENGE_DOMAIN_TAG_STRING,
            UPA_V0_9_0_CIRCUITID_DOMAIN_TAG_STRING,
        },
    },
    utils::{advice_cell_count, hashing::PoseidonHasher, reduced::FromReduced},
    EccPrimeField,
};
use core::{iter::once, slice};
use halo2_base::{
    gates::{
        builder::GateThreadBuilder, GateChip, GateInstructions, RangeChip,
    },
    halo2_proofs::halo2curves::bn256::G1Affine,
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bn254::FpChip,
    ecc::{EcPoint, EccChip},
    fields::FieldChip,
};
use log::info;

pub struct FixedBatchVerifierChip<'a, F: EccPrimeField> {
    batch_verifier_chip: &'a BatchVerifierChip<'a, F>,
}

impl<'a, F: EccPrimeField> FixedBatchVerifierChip<'a, F> {
    /// Creates a new [`UniversalBatchVerifierChip`] from `batch_verifier_chip`.
    pub fn new(batch_verifier_chip: &'a BatchVerifierChip<'a, F>) -> Self {
        Self {
            batch_verifier_chip,
        }
    }

    pub fn bv_chip(&self) -> &BatchVerifierChip<'a, F> {
        self.batch_verifier_chip
    }

    /// Returns the [`GateChip`] in `self`.
    pub fn gate(&self) -> &GateChip<F> {
        self.bv_chip().fp_chip().gate()
    }

    /// Returns the [`RangeChip`] in `self`.
    pub fn range(&self) -> &RangeChip<F> {
        self.bv_chip().fp_chip().range()
    }

    /// Returns the [`FpChip`] in `self`.
    pub fn fp_chip(&self) -> &FpChip<'a, F> {
        self.bv_chip().fp_chip()
    }

    pub fn assign_verification_key(
        &self,
        ctx: &mut Context<F>,
        vk: &VerificationKey,
    ) -> AssignedVerificationKey<F> {
        self.bv_chip().assign_verification_key(ctx, vk)
    }

    pub fn assign_public_inputs(
        &self,
        ctx: &mut Context<F>,
        inputs: &PublicInputs<F>,
    ) -> AssignedPublicInputs<F> {
        self.bv_chip().assign_public_inputs(ctx, inputs)
    }

    pub fn assign_proof(
        &self,
        ctx: &mut Context<F>,
        proof: &Proof,
    ) -> AssignedProof<F> {
        self.bv_chip().assign_proof(ctx, proof)
    }

    pub fn compute_r(
        &self,
        ctx: &mut Context<F>,
        vk_hash: &AssignedValue<F>,
        proofs: &Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
    ) -> AssignedValue<F> {
        let mut poseidon = PoseidonHasher::new(
            ctx,
            self.gate(),
            Some(UPA_V0_9_0_CHALLENGE_DOMAIN_TAG_STRING),
        );

        poseidon.absorb(&slice::from_ref(vk_hash));
        for pi in proofs {
            poseidon.absorb(&pi.0);
            poseidon.absorb(&pi.1 .0.as_slice());
        }

        poseidon.squeeze(ctx)
    }

    /// Execute the top-level batch verification by accumulating (as far as
    /// possible) all proofs and public inputs, and performing a single large
    /// pairing check.  Returns the AssignedValue holding the hash of the
    /// verification key.
    pub fn verify(
        &self,
        builder: &mut GateThreadBuilder<F>,
        vk: &AssignedVerificationKey<F>,
        proofs: &Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
    ) -> AssignedValue<F> {
        let vk_hash = self.compute_vk_hash(builder.main(0), vk);
        info!("compute vk_hash: {:?}", advice_cell_count(builder));

        let r = self.compute_r(builder.main(0), &vk_hash, proofs);
        info!("compute r: {:?}", advice_cell_count(builder));

        self.verify_with_challenge(builder, vk, proofs, r);
        info!("verify with challenge: {:?}", advice_cell_count(builder));

        vk_hash
    }

    pub(crate) fn verify_with_challenge(
        &self,
        builder: &mut GateThreadBuilder<F>,
        vk: &AssignedVerificationKey<F>,
        proofs: &Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
        r: AssignedValue<F>,
    ) {
        let prepared = self.prepare_proofs(builder, vk, (*proofs).clone(), r);
        info!("prepare_proofs: {:?}", advice_cell_count(builder));

        let prepared: Vec<_> = prepared.into();
        let pairing_out = self
            .batch_verifier_chip
            .multi_pairing(builder.main(0), &prepared);
        info!("pairing: {:?}", advice_cell_count(builder));

        self.bv_chip()
            .check_pairing_result(builder.main(0), &pairing_out);
        info!("check_pairing: {:?}", advice_cell_count(builder));
    }

    pub(crate) fn compute_vk_hash(
        &self,
        ctx: &mut Context<F>,
        vk: &AssignedVerificationKey<F>,
    ) -> AssignedValue<F> {
        let mut hasher = PoseidonHasher::<F>::new(
            ctx,
            self.gate(),
            Some(UPA_V0_9_0_CIRCUITID_DOMAIN_TAG_STRING),
        );
        hasher.absorb(vk);
        hasher.squeeze(ctx)
    }

    pub(crate) fn prepare_proofs(
        &self,
        builder: &mut GateThreadBuilder<F>,
        vk: &AssignedVerificationKey<F>,
        proofs: Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
        r: AssignedValue<F>,
    ) -> AssignedPreparedProof<F> {
        let gate = GateChip::default();
        let ecc_chip = EccChip::new(self.fp_chip());

        // Compute the powers of r, and their sum
        let r_powers =
            BatchVerifierChip::scalar_powers(builder.main(0), r, proofs.len());
        info!("r_powers: {:?}", advice_cell_count(builder));

        // TODO: clone() here is required by GateInstructions.  Why does it
        // need a full copy?
        let r_sum = gate.sum(builder.main(0), r_powers.clone());
        info!("r_sum: {:?}", advice_cell_count(builder));

        // Process public inputs
        let (proofs, public_inputs): (Vec<_>, Vec<_>) =
            proofs.into_iter().unzip();
        let processed_public_inputs = Self::compute_f_js(
            builder.main(0),
            &r_powers,
            &r_sum,
            &public_inputs,
        );
        info!("compute_f_js: {:?}", advice_cell_count(builder));

        // `fixed_base_msm_in` expects a Vec<Vec<_>> of scalars
        let processed_public_inputs: Vec<_> = processed_public_inputs
            .into_iter()
            .map(|scalar| vec![scalar])
            .collect();

        let vk_s: Vec<EcPoint<F, ProperCrtUint<F>>> =
            Vec::<EcPoint<F, ProperCrtUint<F>>>::from_reduced(&vk.s);
        let pi = ecc_chip.variable_base_msm_in::<G1Affine>(
            builder,
            vk_s.as_slice(),
            processed_public_inputs,
            F::NUM_BITS as usize,
            WINDOW_BITS,
            0, // TODO: Do we ever use a non-zero phase?
        );
        let minus_pi = ecc_chip.negate(builder.main(0), pi);
        info!("aggregate_public_inputs: {:?}", advice_cell_count(builder));

        // Split into Vec<(A,B)>, and Vec<C>.  Also convert into the
        // non-reduced versions of the group elements.
        let (ab_pairs, c_points): (Vec<_>, Vec<_>) = proofs
            .into_iter()
            .map(|proof| {
                (
                    (
                        G1Point::<F>::from_reduced(&proof.a),
                        G2Point::<F>::from_reduced(&proof.b),
                    ),
                    G1Point::<F>::from_reduced(&proof.c),
                )
            })
            .unzip();

        // Combine C points
        let zc = ecc_chip.variable_base_msm_in::<G1Affine>(
            builder,
            &c_points,
            r_powers
                .iter()
                .map(|scalar| vec![*scalar])
                .collect::<Vec<_>>(),
            F::NUM_BITS as usize,
            WINDOW_BITS,
            0,
        );
        let minus_zc = ecc_chip.negate(builder.main(0), zc);
        info!("aggregate_C_points: {:?}", advice_cell_count(builder));

        // Scale (A, B) pairs
        let scaled_ab_pairs =
            self.bv_chip()
                .scale_pairs(builder.main(0), &r_powers, &ab_pairs);
        info!("scale_AB_pairs: {:?}", advice_cell_count(builder));

        // Compute - r_sum * P
        let ctx = builder.main(0);
        let rp = ecc_chip.scalar_mult::<G1Affine>(
            ctx,
            G1Point::<F>::from_reduced(&vk.alpha),
            vec![r_sum],
            F::NUM_BITS as usize,
            WINDOW_BITS,
        );
        let minus_rp = ecc_chip.negate(ctx, rp);
        info!(" -r_sum * P: {:?}", advice_cell_count(builder));

        // Load from vk
        AssignedPreparedProof {
            ab_pairs: scaled_ab_pairs,
            rp: (minus_rp, G2Point::<F>::from_reduced(&vk.beta)),
            pi: (minus_pi, G2Point::<F>::from_reduced(&vk.gamma)),
            zc: (minus_zc, G2Point::<F>::from_reduced(&vk.delta)),
        }
    }

    /// Return the `f_j` values (where f_j is the accumulation of the j-th
    /// public input for each proof).
    pub(crate) fn compute_f_js(
        ctx: &mut Context<F>,
        r_powers: &[AssignedValue<F>],
        r_sum: &AssignedValue<F>,
        public_inputs: &[AssignedPublicInputs<F>],
    ) -> Vec<AssignedValue<F>> {
        let gate = GateChip::default();
        let num_pub_in = public_inputs[0].0.len();

        // Compute the f_j values:
        // f_0 = r_sum
        // f_j = \sum_{i=0}^{N-1} r^i pi[i][j]

        let f_js: Vec<AssignedValue<F>> = once(*r_sum)
            .chain((0..num_pub_in).map(|j| {
                // Iterator over the jth public input of each proof
                let inputs =
                    public_inputs.iter().map(|pub_in| pub_in.0[j].into());
                // TODO: clone (via to_owned) here is because QuantumCell
                // doesn't implement From<&AssignedValue<F>>
                gate.inner_product(ctx, r_powers.to_owned(), inputs)
            }))
            .collect();
        assert!(f_js.len() == num_pub_in + 1);
        f_js
    }
}

/// In-circuit equivalent of PreparedProof.
// TODO: handle hard-coded values
pub(crate) struct AssignedPreparedProof<F: EccPrimeField> {
    pub ab_pairs: Vec<(G1Point<F>, G2Point<F>)>,
    pub rp: (G1Point<F>, G2Point<F>),
    pub pi: (G1Point<F>, G2Point<F>),
    pub zc: (G1Point<F>, G2Point<F>),
}

impl<F: EccPrimeField> From<AssignedPreparedProof<F>>
    for Vec<(G1Point<F>, G2Point<F>)>
{
    fn from(proof: AssignedPreparedProof<F>) -> Self {
        let mut pairs = proof.ab_pairs;
        pairs.push(proof.rp);
        pairs.push(proof.pi);
        pairs.push(proof.zc);
        pairs
    }
}
