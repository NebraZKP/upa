use crate::{
    batch_verify::{
        common::{
            chip::{
                AssignedProof, AssignedPublicInputs, AssignedVerificationKey,
                BatchVerifierChip,
            },
            ecc::{EcPointPair, G1Point, G2Point},
            types::{Proof, PublicInputs, VerificationKey},
        },
        universal::types::{
            BatchEntries, BatchEntry, ChallengePoints, Groth16Pairs,
            UPA_V1_0_0_CHALLENGE_DOMAIN_TAG_STRING,
        },
    },
    utils::{
        advice_cell_count,
        bitmask::{first_i_bits_bitmask, ith_bit_bitmask},
        hashing::PoseidonHasher,
        reduced::FromReduced,
    },
    EccPrimeField,
};
use core::iter::once;
use halo2_base::{
    gates::{
        builder::GateThreadBuilder, GateChip, GateInstructions, RangeChip,
        RangeInstructions,
    },
    halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bn254::FpChip,
    ecc::{EcPoint, EccChip},
    fields::{fp2::Fp2Chip, FieldChip},
};
use itertools::{multiunzip, Itertools};
use log::info;

/// Universal Batch Verifier Chip
pub struct UniversalBatchVerifierChip<'a, F: EccPrimeField> {
    batch_verifier_chip: &'a BatchVerifierChip<'a, F>,
}

impl<'a, F: EccPrimeField> UniversalBatchVerifierChip<'a, F> {
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

    /// Asserts `entry` has been correctly padded with zeroes.
    ///
    /// # Specification
    ///
    /// This function performs **Step 1a: Check the padding** in the
    /// universal batch verifier spec.
    fn check_padding(
        &self,
        ctx: &mut Context<F>,
        entry: &AssignedBatchEntry<F>,
    ) {
        // Bitmask computation
        let max_len = entry.public_inputs.0.len();
        let number_of_non_padding_elements =
            self.gate().add(ctx, entry.len, entry.has_commitment);
        // We must constrain number_of_non_padding_elements < max_len + 1.
        // This can be satisfied due to `number_of_non_padding_elements`
        // overflowing if `entry.len` is too large, so we range check
        // `entry.len` too.

        // A somewhat arbitrary bound low enough to prevent overflow
        const BIT_BOUND: usize = 20;
        assert!(max_len + 1 < 1 << BIT_BOUND, "max_len is too large");
        let max_len_plus_one = ctx.load_constant(F::from((max_len + 1) as u64));
        self.range().range_check(ctx, entry.len, BIT_BOUND);
        self.range().check_less_than(
            ctx,
            number_of_non_padding_elements,
            max_len_plus_one,
            BIT_BOUND + 1, // entry.len < 1<<BIT_BOUND implies
                           // number_of_non_padding_elements < 1<<(BIT_BOUND+1)
        );
        let bitmask = first_i_bits_bitmask(
            ctx,
            self.gate(),
            number_of_non_padding_elements,
            max_len as u64,
        );
        // Verification Key + public input padding check
        let ec_chip = EccChip::new(self.fp_chip());
        let g1generator = EcPoint::<F, ProperCrtUint<F>>::from_reduced(
            &self
                .batch_verifier_chip
                .assign_g1_reduced(ctx, G1Affine::generator()),
        );
        // This returns a bitstring which is 1 if the corresponding vk.s
        // power is the g1 generator and 0 otherwise.
        let is_g1generator =
            Vec::<EcPoint<F, ProperCrtUint<F>>>::from_reduced(&entry.vk.s)
                .into_iter()
                .skip(1)
                .map(|point| ec_chip.is_equal(ctx, point, g1generator.clone()))
                .collect::<Vec<_>>();
        let one = ctx.load_constant(F::from(1));
        for (i, is_g1gen) in is_g1generator.into_iter().enumerate() {
            // Check (1-b)*v == 0 for all public inputs v
            let flipped_bit = self.gate().sub(ctx, one, bitmask[i]);
            let public_input_prod =
                self.gate().mul(ctx, flipped_bit, entry.public_inputs.0[i]);
            self.gate()
                .assert_is_const(ctx, &public_input_prod, &F::zero());
            // Check (1-b)*(1-w) == 0 <==> (1-b) == (1-b)*w, where w
            // is a bit marking whether the i-th vk_s is the g1
            // generator.
            let vk_prod = self.gate().mul(ctx, flipped_bit, is_g1gen);
            ctx.constrain_equal(&vk_prod, &flipped_bit);
        }

        // TODO: We may not need to check the vk padding. In that case, all the code
        // above (after the bitmask computation) can be replaced by the following:
        /*
        // Public input only padding check
        for (i, bit) in bitmask.into_iter().enumerate() {
            // (1-b)*v == 0 <==> b*v == v
            let prod = self.gate().mul(ctx, bit, entry.public_inputs.0[i]);
            ctx.constrain_equal(&prod, &entry.public_inputs.0[i]);
        }
        */

        self.check_vk_commitment_padding(ctx, entry);
        self.check_proof_commitment_padding(ctx, entry)
    }

    /// Enforces that either `vk.h1, vk.h2` are both assigned
    /// as G2 padding point or else `entry.has_commitment` is
    /// assigned as `true`.
    fn check_vk_commitment_padding(
        &self,
        ctx: &mut Context<F>,
        entry: &AssignedBatchEntry<F>,
    ) {
        let fp2_chip = Fp2Chip::new(self.fp_chip());
        let g2_chip = EccChip::new(&fp2_chip);
        // TODO: specify padding points as constants
        let g2_padding_point = G2Affine::generator();
        let g2_padding_point =
            g2_chip.assign_constant_point(ctx, g2_padding_point);

        let vk_h1_is_padding = g2_chip.is_equal(
            ctx,
            G2Point::from_reduced(&entry.vk.h1),
            g2_padding_point.clone(),
        );

        // Repeat for vk.h2
        let vk_h2_is_padding = g2_chip.is_equal(
            ctx,
            G2Point::from_reduced(&entry.vk.h2),
            g2_padding_point,
        );

        let is_satisfied = self.gate().or_and(
            ctx,
            entry.has_commitment,
            vk_h1_is_padding,
            vk_h2_is_padding,
        );
        self.gate().assert_is_const(ctx, &is_satisfied, &F::one());
    }

    /// Enforces that either `proof.m, proof.pok` are assigned as
    /// G1 padding point or else `entry.has_commitment` is
    /// assigned as `true`.
    fn check_proof_commitment_padding(
        &self,
        ctx: &mut Context<F>,
        entry: &AssignedBatchEntry<F>,
    ) {
        // Check proof Pedersen commitment padding
        let g1_chip = EccChip::new(self.fp_chip());
        let g1_padding_point = G1Affine::generator();
        let g1_padding_point =
            g1_chip.assign_constant_point(ctx, g1_padding_point);

        let proof_m_is_padding = g1_chip.is_equal(
            ctx,
            G1Point::from_reduced(&entry.proof.m),
            g1_padding_point.clone(),
        );

        // Repeat for proof.pok
        let minus_g1_padding_point = g1_chip.negate(ctx, g1_padding_point);
        let proof_pok_is_padding = g1_chip.is_equal(
            ctx,
            G1Point::from_reduced(&entry.proof.pok),
            minus_g1_padding_point,
        );

        let is_satisfied = self.gate().or_and(
            ctx,
            entry.has_commitment,
            proof_m_is_padding,
            proof_pok_is_padding,
        );
        self.gate().assert_is_const(ctx, &is_satisfied, &F::one());
    }

    /// Assigns `entry`.
    ///
    /// # Specification
    ///
    /// This function performs **Step 1: Check the entries** in the
    /// universal batch verifier spec.
    fn assign_batch_entry(
        &self,
        ctx: &mut Context<F>,
        entry: &BatchEntry<F>,
    ) -> AssignedBatchEntry<F> {
        let len = ctx.load_witness(*entry.len());
        // Cast boolean `has_commitment` to field element, assign and constrain
        // to boolean value.
        let has_commitment = ctx.load_witness(F::from(entry.has_commitment()));
        self.gate().assert_bit(ctx, has_commitment);
        let vk = self.assign_verification_key(ctx, entry.vk());
        let proof = self.assign_proof(ctx, entry.proof());
        let public_inputs = self.assign_public_inputs(ctx, entry.inputs());
        let commitment_hash = ctx.load_witness(*entry.commitment_hash());
        let result = AssignedBatchEntry {
            len,
            has_commitment,
            vk,
            proof,
            public_inputs,
            commitment_hash,
        };
        self.check_padding(ctx, &result);
        self.constrain_commitment_hash(ctx, &result);
        result
    }

    /// Constrains the index l public input in `entry` to be equal to
    /// `entry.commitment_hash` when `entry.has_commitment = true`
    /// and to equal zero otherwise.
    ///
    ///  # Specification
    ///
    /// This function performs **Step 1c: Constrain Commitment Hash** in the
    /// universal batch verifier spec.
    fn constrain_commitment_hash(
        &self,
        ctx: &mut Context<F>,
        entry: &AssignedBatchEntry<F>,
    ) {
        let max_len = entry.public_inputs.0.len() as u64;
        let bitmask = ith_bit_bitmask(ctx, self.gate(), entry.len, max_len);
        let bits = bitmask.iter().map(|b| QuantumCell::<F>::from(*b));
        let lth_public_input = self.gate().inner_product(
            ctx,
            entry.public_inputs.0.iter().copied(),
            bits,
        );
        let expected =
            self.gate()
                .mul(ctx, entry.commitment_hash, entry.has_commitment);
        ctx.constrain_equal(&lth_public_input, &expected);
    }

    /// Assigns `entries`.
    pub(crate) fn assign_batch_entries(
        &self,
        ctx: &mut Context<F>,
        entries: &BatchEntries<F>,
    ) -> AssignedBatchEntries<F> {
        AssignedBatchEntries(
            entries
                .0
                .iter()
                .map(|entry| self.assign_batch_entry(ctx, entry))
                .collect(),
        )
    }

    /// Computes the hash of the verifying key in `entry`.
    ///
    /// # Specification
    ///
    /// This function performs **Step 2: Compute vk hash** of the
    /// universal batch verifier spec.
    pub(crate) fn compute_vk_hash(
        &self,
        ctx: &mut Context<F>,
        entry: &AssignedBatchEntry<F>,
    ) -> AssignedValue<F> {
        let mut hasher = PoseidonHasher::new(ctx, self.gate(), None);
        hasher.absorb(&entry.vk);
        hasher.squeeze(ctx)
    }

    /// Computes the challenge from `entries`.
    ///
    /// # Specification
    ///
    /// This function performs **Step 3: Compute the challenge point** of the
    /// universal batch verifier spec.
    pub(crate) fn compute_challenge_points<'b, I>(
        &self,
        ctx: &mut Context<F>,
        vk_hashes: I,
        entries: &AssignedBatchEntries<F>,
    ) -> ChallengePoints<F>
    where
        I: IntoIterator<Item = &'b AssignedValue<F>>,
    {
        let mut hasher = PoseidonHasher::new(
            ctx,
            self.gate(),
            Some(UPA_V1_0_0_CHALLENGE_DOMAIN_TAG_STRING),
        );
        for (vk_hash, entry) in vk_hashes.into_iter().zip_eq(entries.0.iter()) {
            hasher.absorb(vk_hash);
            hasher.absorb(&entry.proof);
            hasher.absorb(&entry.public_inputs.0.as_slice());
        }
        let r = hasher.squeeze(ctx);
        let t = hasher.squeeze(ctx);
        (r, t)
    }

    /// Verifies the proofs in `entries`.
    ///
    /// # Specification
    ///
    /// This function performs Steps 2-7 of the universal batch verifier
    /// spec.
    pub fn verify(
        &self,
        builder: &mut GateThreadBuilder<F>,
        entries: &AssignedBatchEntries<F>,
    ) {
        // Step 2: Compute vk hash for every entry
        let vk_hashes = entries
            .0
            .iter()
            .map(|entry| self.compute_vk_hash(builder.main(0), entry))
            .collect_vec();
        info!("compute vk_hash: {:?}", advice_cell_count(builder));
        // Step 3: Compute challenge
        let challenge =
            self.compute_challenge_points(builder.main(0), &vk_hashes, entries);
        info!("compute r: {:?}", advice_cell_count(builder));
        // Steps 4-7: Verify with challenge
        self.verify_with_challenge(builder, entries, challenge);
        info!("verify with challenge: {:?}", advice_cell_count(builder));
    }

    /// Verifies the proofs in `entries` against `challenge`.
    ///
    /// # Specification
    ///
    /// This function performs Steps 4-7 of the universal batch verifier
    /// spec.
    fn verify_with_challenge(
        &self,
        builder: &mut GateThreadBuilder<F>,
        entries: &AssignedBatchEntries<F>,
        challenge: ChallengePoints<F>,
    ) {
        // Steps 4 and 5
        let prepared_proofs = self.prepare_proofs(builder, entries, challenge);
        info!("prepare_proofs: {:?}", advice_cell_count(builder));

        let prepared_proofs = prepared_proofs.into_iter().collect_vec();

        // Step 6: compute the pairing
        let pairing_output = self
            .bv_chip()
            .multi_pairing(builder.main(0), &prepared_proofs);
        info!("pairing: {:?}", advice_cell_count(builder));

        // Step 7: check final result
        self.bv_chip()
            .check_pairing_result(builder.main(0), &pairing_output);
        info!("check_pairing: {:?}", advice_cell_count(builder));
    }

    /// Prepares the proofs in `entries` for verification.
    ///
    /// # Specification
    ///
    /// This function computes Steps 4 and 5 of the universal batch
    /// verifier spec.
    pub(crate) fn prepare_proofs(
        &self,
        builder: &mut GateThreadBuilder<F>,
        entries: &AssignedBatchEntries<F>,
        challenge: ChallengePoints<F>,
    ) -> AssignedPreparedProof<F> {
        let batch_size = entries.0.len();

        // Compute the powers of r, and their sum
        let r_powers = BatchVerifierChip::scalar_powers(
            builder.main(0),
            challenge.0,
            batch_size,
        );
        info!("r_powers: {:?}", advice_cell_count(builder));

        // Steps 4 and 5: compute other pairs
        let pairs =
            self.compute_pairs(builder, &r_powers, entries, challenge.1);
        info!("compute_pairs: {:?}", advice_cell_count(builder));

        AssignedPreparedProof {
            ab_pairs: pairs.scaled_ab_pairs,
            cd_pairs: pairs.scaled_cd_pairs,
            pi_gamma_pairs: pairs.scaled_pi_gamma_pairs,
            alpha_beta_pairs: pairs.scaled_alpha_beta_pairs,
            m_h1_pairs: pairs.scaled_m_h1_pairs,
            pok_h2_pairs: pairs.scaled_pok_h2_pairs,
        }
    }

    /// Computes the [`Groth16Pairs`] corresponding to `proofs` and `vk`.
    ///
    /// # Specification
    ///
    /// This function performs **Step 4: compute public input pairs** and
    /// **Step 5: Compute the other pairs** of the universal batch verifier
    /// spec.
    fn compute_pairs(
        &self,
        builder: &mut GateThreadBuilder<F>,
        r_powers: &[AssignedValue<F>],
        entries: &AssignedBatchEntries<F>,
        t: AssignedValue<F>,
    ) -> Groth16Pairs<F> {
        // Step 4: compute public input pairs (PI, vk.gamma)
        let pi_pairs = self.compute_pi_pairs(builder, entries);
        info!("public_input_pair: {:?}", advice_cell_count(builder));

        let ctx = builder.main(0);
        let minus_r_powers = r_powers
            .iter()
            .map(|r_power| self.gate().neg(ctx, *r_power))
            .collect_vec();
        let rt_powers = r_powers
            .iter()
            .map(|r_power| self.gate().mul(ctx, *r_power, t))
            .collect_vec();

        let (vk, proofs, _) = entries.unzip();
        let (ab_pairs, cd_pairs, alpha_beta_pairs): (Vec<_>, Vec<_>, Vec<_>) =
            proofs
                .iter()
                .zip(vk.iter())
                .map(|(proof, vk)| {
                    (
                        (
                            G1Point::<F>::from_reduced(&proof.a),
                            G2Point::<F>::from_reduced(&proof.b),
                        ),
                        (
                            G1Point::<F>::from_reduced(&proof.c),
                            G2Point::<F>::from_reduced(&vk.delta),
                        ),
                        (
                            G1Point::<F>::from_reduced(&vk.alpha),
                            G2Point::<F>::from_reduced(&vk.beta),
                        ),
                    )
                })
                .multiunzip();

        let (m_pairs, pok_pairs) = self.pedersen_pairs(entries);

        let scaled_ab_pairs =
            self.bv_chip().scale_pairs(ctx, &minus_r_powers, &ab_pairs);

        let scaled_cd_pairs =
            self.bv_chip().scale_pairs(ctx, r_powers, &cd_pairs);

        let scaled_alpha_beta_pairs =
            self.bv_chip().scale_pairs(ctx, r_powers, &alpha_beta_pairs);

        let scaled_pi_gamma_pairs =
            self.bv_chip().scale_pairs(ctx, r_powers, &pi_pairs);

        let scaled_m_h1_pairs =
            self.bv_chip().scale_pairs(ctx, &rt_powers, &m_pairs);

        let scaled_pok_h2_pairs =
            self.bv_chip().scale_pairs(ctx, &rt_powers, &pok_pairs);

        Groth16Pairs {
            scaled_ab_pairs,
            scaled_cd_pairs,
            scaled_pi_gamma_pairs,
            scaled_alpha_beta_pairs,
            scaled_m_h1_pairs,
            scaled_pok_h2_pairs,
        }
    }

    /// Computes the public input [`EcPointPair`] for `inputs` and `vk`.
    #[allow(dead_code)]
    #[deprecated]
    fn public_input_pair(
        &self,
        builder: &mut GateThreadBuilder<F>,
        r_powers: &[AssignedValue<F>],
        vks: &[AssignedVerificationKey<F>],
        inputs: &[AssignedPublicInputs<F>],
    ) -> EcPointPair<F> {
        // Initialize EC chip
        let ec_chip = EccChip::new(self.fp_chip());
        // Step 1: scale public inputs
        let batch_size = inputs.len();
        let mut scaled_inputs = Vec::with_capacity(batch_size);
        for (input, r_power) in inputs.iter().zip_eq(r_powers.iter()) {
            let scaled_input = input
                .0
                .iter()
                .map(|input| self.gate().mul(builder.main(0), *input, *r_power))
                .collect_vec();
            scaled_inputs.push(scaled_input);
        }
        // Step 2: extract the G1 powers from the vks
        let vk_s = vks
            .iter()
            .map(|vk| Vec::<EcPoint<F, ProperCrtUint<F>>>::from_reduced(&vk.s))
            .collect_vec();
        // Step 3: for every batch entry, compute
        // \sum_{j=1}^/ell r^i p_{ij} * S_{ij}, where i is the batch entry index
        // and push the result to `partial_sums`.
        let mut partial_sums = Vec::with_capacity(batch_size + 1);
        for (input, vk_i_s) in scaled_inputs.into_iter().zip(vk_s.iter()) {
            let input = input.into_iter().map(|value| vec![value]).collect();
            partial_sums.push(ec_chip.variable_base_msm::<G1Affine>(
                builder,
                &vk_i_s[1..], // We skip the first element
                input,
                F::NUM_BITS as usize,
            ));
        }
        // Step 4: compute \sum_{i=0}^{N-1} r^i * S_{i0} and add it to
        // `partial_sums`.
        let first_element_vk =
            vk_s.iter().map(|vk_s_i| vk_s_i[0].clone()).collect_vec();
        let r_powers: Vec<_> =
            r_powers.iter().map(|power| vec![*power]).collect();
        partial_sums.push(ec_chip.variable_base_msm::<G1Affine>(
            builder,
            first_element_vk.as_slice(),
            r_powers,
            F::NUM_BITS as usize,
        ));
        // Step 5: add all the partial sums together
        let ones = (0..batch_size + 1)
            .into_iter()
            .map(|_| vec![builder.main(0).load_constant(F::one())])
            .collect_vec();
        let pi_term = ec_chip.variable_base_msm::<G1Affine>(
            builder,
            &partial_sums,
            ones,
            1,
        );
        // Note that we're not using any of the gammas but 1 instead. Thus, this circuit
        // only makes sense if all gammas are equal to G2::generator().
        let g2generator = self
            .batch_verifier_chip
            .assign_g2_reduced(builder.main(0), G2Affine::generator());
        (pi_term, G2Point::<F>::from_reduced(&g2generator))
    }

    /// Computes the public input [`Vec<EcPointPair>`] for `inputs` and `vks`.
    ///
    /// # Specification
    ///
    /// This function performs **Step 4: Compute the public input term** of the
    /// universal batch verifier spec.
    pub(crate) fn compute_pi_pairs(
        &self,
        builder: &mut GateThreadBuilder<F>,
        entries: &AssignedBatchEntries<F>,
    ) -> Vec<EcPointPair<F>> {
        // Initialize EC chip
        let ec_chip = EccChip::new(self.fp_chip());

        // Compute the regular Groth16 PI term:
        //
        //   vk_i.s[0] + \sum_j=1^\ell x_i . vk_i.s[j]
        // =    lhs    +      rhs
        let ctx = builder.main(0);
        let one = ctx.load_constant(F::one());

        entries
            .0
            .iter()
            .map(|entry| {
                let mut ss = Vec::<EcPoint<F, ProperCrtUint<F>>>::from_reduced(
                    &entry.vk.s,
                );
                ss.push(<EcPoint<F, ProperCrtUint<F>>>::from_reduced(
                    &entry.proof.m,
                ));
                let inputs: Vec<_> = once(&one)
                    .chain(entry.public_inputs.0.iter())
                    .chain(once(&entry.has_commitment))
                    .map(|i| vec![*i])
                    .collect();
                assert!(ss.len() > 1);
                assert!(!inputs.is_empty());
                assert!(inputs.len() == ss.len());
                let pi_term = ec_chip.variable_base_msm::<G1Affine>(
                    builder,
                    &ss[..],
                    inputs,
                    F::NUM_BITS as usize,
                );

                (pi_term, G2Point::<F>::from_reduced(&entry.vk.gamma))
            })
            .collect()
    }

    /// Computes the Pedersen pairs (M, h1), (pok, h2).
    fn pedersen_pairs(
        &self,
        entries: &AssignedBatchEntries<F>,
    ) -> (Vec<EcPointPair<F>>, Vec<EcPointPair<F>>) {
        entries
            .0
            .iter()
            .map(|entry| {
                let m_pair = (
                    G1Point::<F>::from_reduced(&entry.proof.m),
                    G2Point::<F>::from_reduced(&entry.vk.h1),
                );
                let pok_pair = (
                    G1Point::<F>::from_reduced(&entry.proof.pok),
                    G2Point::<F>::from_reduced(&entry.vk.h2),
                );
                (m_pair, pok_pair)
            })
            .unzip()
    }
}

/// Assigned Batch Entry
#[derive(Clone, Debug)]
pub struct AssignedBatchEntry<F: EccPrimeField> {
    /// Assigned length of the public inputs
    pub(super) len: AssignedValue<F>,
    /// Pedersen commitment flag. Constrained to boolean values.
    pub(super) has_commitment: AssignedValue<F>,
    /// Assigned Verification Key
    pub(super) vk: AssignedVerificationKey<F>,
    /// Assigned Proof
    pub(super) proof: AssignedProof<F>,
    /// Assigned Public Inputs
    pub(super) public_inputs: AssignedPublicInputs<F>,
    /// Commitment Hash
    pub(super) commitment_hash: AssignedValue<F>,
}

/// Assigned Batch Entries
#[derive(Clone, Debug)]
pub struct AssignedBatchEntries<F: EccPrimeField>(
    pub Vec<AssignedBatchEntry<F>>,
);

/// Unzipped Assigned Entry
type UnzippedAssignedEntry<F> = (
    Vec<AssignedVerificationKey<F>>,
    Vec<AssignedProof<F>>,
    Vec<AssignedPublicInputs<F>>,
);

impl<F: EccPrimeField> AssignedBatchEntries<F> {
    /// Returns the [`AssignedPublicInputs`] in `self`.
    pub fn public_inputs(&self) -> Vec<AssignedPublicInputs<F>> {
        self.0
            .iter()
            .map(|batch_entry| batch_entry.public_inputs.clone())
            .collect()
    }

    /// Unzips `self`, returning an [`UnzippedAssignedEntry`].
    pub fn unzip(&self) -> UnzippedAssignedEntry<F> {
        multiunzip(
            self.0
                .iter()
                .cloned()
                .map(|entry| (entry.vk, entry.proof, entry.public_inputs)),
        )
    }
}

// TODO: why is this distinct from types.Groth16Pairs?

/// Assigned Prepared Proof
#[derive(Clone, Debug)]
pub(crate) struct AssignedPreparedProof<F: EccPrimeField> {
    /// (A, B) pairs
    pub(crate) ab_pairs: Vec<EcPointPair<F>>,
    /// (C, delta) pairs
    pub(crate) cd_pairs: Vec<EcPointPair<F>>,
    /// Public input pairs
    pub(crate) pi_gamma_pairs: Vec<EcPointPair<F>>,
    /// (alpha, beta) pairs
    pub(crate) alpha_beta_pairs: Vec<EcPointPair<F>>,
    /// (M, h1) pairs
    pub(crate) m_h1_pairs: Vec<EcPointPair<F>>,
    /// (pok, h2) pairs
    pub(crate) pok_h2_pairs: Vec<EcPointPair<F>>,
}

impl<F: EccPrimeField> AssignedPreparedProof<F> {
    /// Returns an iterator over the [`EcPointPair`]s of `self`,
    /// matching the order in [`native`](super::native).
    #[cfg(test)]
    pub fn iter(&self) -> impl Iterator<Item = &EcPointPair<F>> {
        self.ab_pairs
            .iter()
            .zip_eq(self.alpha_beta_pairs.iter())
            .zip_eq(self.pi_gamma_pairs.iter())
            .zip_eq(self.cd_pairs.iter())
            .zip_eq(self.m_h1_pairs.iter())
            .zip_eq(self.pok_h2_pairs.iter())
            .flat_map(|(((((a, b), c), d), e), f)| [a, b, c, d, e, f])
    }

    pub fn into_iter(self) -> impl Iterator<Item = EcPointPair<F>> {
        self.ab_pairs
            .into_iter()
            .zip_eq(self.alpha_beta_pairs.into_iter())
            .zip_eq(self.pi_gamma_pairs.into_iter())
            .zip_eq(self.cd_pairs.into_iter())
            .zip_eq(self.m_h1_pairs.into_iter())
            .zip_eq(self.pok_h2_pairs.into_iter())
            .flat_map(|(((((a, b), c), d), e), f)| [a, b, c, d, e, f])
    }
}
