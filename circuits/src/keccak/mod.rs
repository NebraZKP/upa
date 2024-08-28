//! Keccak circuit implementation
//!
//! Code derived from [axiom-eth](https://github.com/axiom-crypto/axiom-eth)
//! Licensed under the MIT License.

extern crate alloc;

use self::{
    inputs::{KeccakCircuitInputs, KeccakVarLenInput},
    utils::{
        byte_decomposition, byte_decomposition_list,
        compose_into_field_element, compute_final_digest, compute_proof_id,
        compute_submission_id, digest_as_field_elements,
        encode_digest_as_field_elements, g1_point_limbs_to_bytes,
        g2_point_limbs_to_bytes,
    },
};
use crate::{
    batch_verify::{
        common::types::VerificationKey,
        universal::{
            self,
            types::{
                UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING,
                UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING_WITH_COMMITMENT,
            },
        },
    },
    utils::{
        bitmask::first_i_bits_bitmask,
        commitment_point::{
            commitment_hash_from_commitment_point_limbs, g1affine_into_limbs,
            g2affine_into_limbs, limbs_into_g1affine, limbs_into_g2affine,
        },
        hashing::compute_domain_tag,
        upa_config::UpaConfig,
    },
    EccPrimeField, SafeCircuit,
};
use chip::{
    assign_prover, assigned_cell_from_assigned_value, rows_per_round,
    KeccakChip,
};
use core::{cell::RefCell, fmt, marker::PhantomData, slice::Iter};
use halo2_base::{
    gates::{
        builder::{
            FlexGateConfigParams, GateThreadBuilder, KeygenAssignments,
            MultiPhaseThreadBreakPoints,
        },
        range::{RangeChip, RangeConfig, RangeStrategy},
        GateInstructions, RangeInstructions,
    },
    halo2_proofs::{
        circuit::{self, Layouter, SimpleFloorPlanner},
        halo2curves::{
            bn256::{Fr, G1Affine, G2Affine},
            CurveAffine,
        },
        plonk::{
            Circuit, Column, ConstraintSystem, Error, Instance, ProvingKey,
            VerifyingKey,
        },
        SerdeFormat,
    },
    utils::ScalarField,
    AssignedValue, Context, SKIP_FIRST_PASS,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::CircuitExt;
use std::env::{set_var, var};
use zkevm_keccak::{util::eth_types::Field, KeccakConfig as KeccakBaseConfig};

pub mod chip;
pub mod inputs;
pub mod multivar;
pub mod utils;
pub mod variable;

/// KECCAK Lookup bits
pub const KECCAK_LOOKUP_BITS: usize = 8;

/// Default unusable rows
pub const DEFAULT_UNUSABLE_ROWS: usize = 109;

/// Default number of limbs
pub const NUM_LIMBS: usize = 3;

/// Default limb size in bits
pub const LIMB_BITS: usize = 88;

/// Number of bytes to represent an Fq element
pub const NUM_BYTES_FQ: usize = 32;

/// Max number of keccak rows per round
///
/// # Note
///
/// Empirically more than 50 rows per round makes the rotation offsets too large.
pub const MAX_KECCAK_ROWS_PER_ROUND: u32 = 50;

/// Exposed instances type
type ExposedInstances = (
    // Public inputs
    Vec<circuit::Cell>,
    // Public output. This option should be `Some` in keygen mode and
    // `None` in prover mode.
    Option<[circuit::Cell; 2]>,
);

/// The circuit configuration. This should be sufficient to fully define the
/// circuit structure and generate keys.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeccakConfig {
    /// Log-2 of the number of rows.
    pub degree_bits: u32,
    /// Maximum number of public inputs allowed in a single application instance.
    /// Does not include the circuit ID.
    pub num_app_public_inputs: u32,
    /// Number of application proofs checked by a `BatchVerifyCircuit`.
    pub inner_batch_size: u32,
    /// Number of batches being aggregated.
    pub outer_batch_size: u32,
    /// Log-2 of the number of rows allocated for lookup tables. Usually
    /// `degree_bits - 1`.
    pub lookup_bits: usize,
    /// Output submission Id. If `true`, the circuit outputs the submissionId of
    /// the proofIds it computes as the final digest. If `false`, it outputs the
    /// keccak hash of all proofIds.
    pub output_submission_id: bool,
}

impl KeccakConfig {
    pub fn from_upa_config_file(config_file: &str) -> Self {
        KeccakConfig::from(&UpaConfig::from_file(config_file))
    }
}

impl From<&UpaConfig> for KeccakConfig {
    fn from(config: &UpaConfig) -> Self {
        KeccakConfig {
            degree_bits: config.keccak_config.degree_bits,
            num_app_public_inputs: config.max_num_app_public_inputs,
            inner_batch_size: config.inner_batch_size,
            outer_batch_size: config.outer_batch_size,
            lookup_bits: config.keccak_config.lookup_bits,
            output_submission_id: config.output_submission_id,
        }
    }
}

impl fmt::Display for KeccakConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Keccak degree: {}", self.degree_bits)?;
        writeln!(f, "Num app public inputs: {}", self.num_app_public_inputs)?;
        writeln!(f, "Inner batch size: {}", self.inner_batch_size)?;
        write!(f, "Outer batch size: {}", self.outer_batch_size)
    }
}

/// VerificationKey that has been padded, where all elements are represented as
/// limbs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PaddedVerifyingKeyLimbs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    pub(crate) alpha: Vec<F>,
    pub(crate) beta: Vec<F>,
    pub(crate) gamma: Vec<F>,
    pub(crate) delta: Vec<F>,
    pub(crate) s: Vec<Vec<F>>,
    pub(crate) h1: Vec<F>,
    pub(crate) h2: Vec<F>,
}

impl<F> PaddedVerifyingKeyLimbs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    /// Returns an iterator over the elements of `self`.
    pub fn iter(&self) -> impl Iterator<Item = &F> {
        self.alpha
            .iter()
            .chain(self.beta.iter())
            .chain(self.gamma.iter())
            .chain(self.delta.iter())
            .chain(self.s.iter().flat_map(|s| s.iter()))
            .chain(self.h1.iter())
            .chain(self.h2.iter())
    }

    /// Returns a vector with the elements of `self`.
    pub fn flatten(&self) -> Vec<F> {
        self.iter().copied().collect()
    }

    /// Builds a new [`PaddedVerifyingKeyLimbs`] from `limbs`
    /// with `self.s.len() = len_s`.
    pub fn from_limbs(limbs: &[F], len_s: usize) -> Self {
        assert!(len_s > 0, "length of s can't be zero");
        assert_eq!(
            limbs.len(),
            NUM_LIMBS * (22 + 2 * len_s),
            "Inconsistent length"
        );
        let mut limbs_iter = limbs.iter();

        let take_fq = |limbs_iter: &mut Iter<F>, num_fq: usize| {
            limbs_iter
                .by_ref()
                .take(num_fq * NUM_LIMBS)
                .copied()
                .collect_vec()
        };
        let alpha = take_fq(&mut limbs_iter, 2);
        let beta = take_fq(&mut limbs_iter, 4);
        let gamma = take_fq(&mut limbs_iter, 4);
        let delta = take_fq(&mut limbs_iter, 4);
        let mut s = Vec::with_capacity(len_s);
        for _ in 0..len_s {
            s.push(take_fq(&mut limbs_iter, 2));
        }
        let h1 = take_fq(&mut limbs_iter, 4);
        let h2 = take_fq(&mut limbs_iter, 4);
        Self {
            alpha,
            beta,
            gamma,
            delta,
            s,
            h1,
            h2,
        }
    }

    /// Returns a dummy [`PaddedVerifyingKeyLimbs`] compatible with `config`,
    /// which will be used during keygen.
    pub fn dummy(config: &KeccakConfig) -> Self {
        let g1_generator = G1Affine::generator();
        let g2_generator = G2Affine::generator();
        let g1_generator_limbs =
            g1affine_into_limbs(&g1_generator, LIMB_BITS, NUM_LIMBS);
        let g2_generator_limbs =
            g2affine_into_limbs(&g2_generator, LIMB_BITS, NUM_LIMBS);
        Self {
            alpha: g1_generator_limbs.clone(),
            beta: g2_generator_limbs.clone(),
            gamma: g2_generator_limbs.clone(),
            delta: g2_generator_limbs.clone(),
            s: (0..config.num_app_public_inputs + 1)
                .into_iter()
                .map(|_| g1_generator_limbs.clone())
                .collect(),
            h1: g2_generator_limbs.clone(),
            h2: g2_generator_limbs,
        }
    }

    /// Creates a new [`PaddedVerifyingKeyLimbs`] from `vk`.
    ///
    /// # Note
    ///
    /// The `vk` has to be already paddeed.
    pub fn from_vk(vk: &VerificationKey) -> Self {
        let VerificationKey {
            alpha,
            beta,
            gamma,
            delta,
            s,
            h1,
            h2,
        } = vk;
        assert_eq!(h1.len(), h2.len(), "inconsistent vk");
        assert_eq!(h1.len(), 1, "vk must be already padded");
        Self {
            alpha: g1affine_into_limbs(alpha, LIMB_BITS, NUM_LIMBS),
            beta: g2affine_into_limbs(beta, LIMB_BITS, NUM_LIMBS),
            gamma: g2affine_into_limbs(gamma, LIMB_BITS, NUM_LIMBS),
            delta: g2affine_into_limbs(delta, LIMB_BITS, NUM_LIMBS),
            s: s.iter()
                .map(|s_i| g1affine_into_limbs(s_i, LIMB_BITS, NUM_LIMBS))
                .collect(),
            h1: g2affine_into_limbs(&h1[0], LIMB_BITS, NUM_LIMBS),
            h2: g2affine_into_limbs(&h2[0], LIMB_BITS, NUM_LIMBS),
        }
    }

    /// Converts `self` back into a [`VerificationKey`].
    pub fn vk(&self) -> VerificationKey {
        VerificationKey {
            alpha: limbs_into_g1affine(&self.alpha, LIMB_BITS, NUM_LIMBS),
            beta: limbs_into_g2affine(&self.beta, LIMB_BITS, NUM_LIMBS),
            gamma: limbs_into_g2affine(&self.gamma, LIMB_BITS, NUM_LIMBS),
            delta: limbs_into_g2affine(&self.delta, LIMB_BITS, NUM_LIMBS),
            s: self
                .s
                .iter()
                .map(|s_i| limbs_into_g1affine(s_i, LIMB_BITS, NUM_LIMBS))
                .collect(),
            h1: vec![limbs_into_g2affine(&self.h1, LIMB_BITS, NUM_LIMBS)],
            h2: vec![limbs_into_g2affine(&self.h2, LIMB_BITS, NUM_LIMBS)],
        }
    }
}

/// Internal struct representing a single public input to the keccak circuit,
/// consisting of the vk_hash of an application circuit together with its
/// vector of public inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeccakPaddedCircuitInput<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    /// Length of the application public input, in field elements
    pub len: F,

    /// Verifying key of the application circuit
    pub app_vk: PaddedVerifyingKeyLimbs<F>,

    /// Has commitment flag
    pub has_commitment: F,

    /// Application public inputs
    ///
    /// # Note
    ///
    /// These should be padded to the maximum number of public inputs in
    /// the [`KeccakConfig`]. The circuit won't check the padding, and the
    /// circuit satisfiability is independent of the field elements chosen to
    pub app_public_inputs: Vec<F>,

    /// Commitment point hash
    pub commitment_hash: F,

    /// Commitment point limbs
    pub commitment_point_limbs: Vec<F>,
}

impl<F> KeccakPaddedCircuitInput<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    /// Returns the length, application vk limbs, has_commitment
    /// flag, commitment hash, commitment point limbs, and
    /// public inputs.
    pub fn to_instance_values(&self) -> Vec<F> {
        let mut result = vec![self.len];
        result.extend_from_slice(&self.app_vk.flatten());
        result.push(self.has_commitment);
        result.push(self.commitment_hash);
        result.extend_from_slice(&self.commitment_point_limbs);
        result.extend_from_slice(&self.app_public_inputs);
        result
    }

    /// Generates a dummy [`KeccakPaddedCircuitInput`] for `config` with a given `input_type`.
    pub fn dummy(config: &KeccakConfig) -> Self {
        let app_vk = PaddedVerifyingKeyLimbs::dummy(config);
        let has_commitment = F::zero();
        let app_public_inputs = (0..config.num_app_public_inputs)
            .map(|_| Default::default())
            .collect();
        let commitment_hash = Default::default();
        let commitment_point_limbs = vec![Default::default(); NUM_LIMBS * 2];
        Self {
            len: F::from(config.num_app_public_inputs as u64),
            app_vk,
            has_commitment,
            app_public_inputs,
            commitment_hash,
            commitment_point_limbs,
        }
    }

    /// Returns the number of field elements which will be keccak'd together.
    #[cfg(test)]
    pub fn num_field_elements(&self) -> usize {
        self.len.get_lower_32() as usize
    }

    /// Checks if `self` is a valid public input for `config`.
    pub fn is_well_constructed(&self, config: &KeccakConfig) -> bool {
        let length_condition =
            self.len.get_lower_32() <= config.num_app_public_inputs;
        let has_commitment_condition =
            self.commitment_point_limbs.len() == 2 * NUM_LIMBS;
        (config.num_app_public_inputs == self.app_public_inputs.len() as u32)
            && length_condition
            && has_commitment_condition
    }

    /// Pads `var_len_input` with zeros to have length `max_num_public_inputs`.
    fn from_var_len_input(
        var_len_input: &KeccakVarLenInput<F>,
        max_num_public_inputs: usize,
    ) -> Self {
        let commitment_point_coordinates =
            &var_len_input.commitment_point_coordinates;
        let has_commitment = !commitment_point_coordinates.is_empty();
        assert!(
            commitment_point_coordinates.len() < 2,
            "Only up to one commitment point allowed"
        );
        assert!(
            var_len_input.app_public_inputs.len() + has_commitment as usize
                <= max_num_public_inputs,
            "Too many app inputs for config."
        );
        assert_eq!(
            var_len_input.app_public_inputs.len() + has_commitment as usize + 1,
            var_len_input.app_vk.s.len(),
            "vk incompatible with inputs"
        );
        assert_eq!(
            var_len_input.app_vk.h1.len(),
            has_commitment as usize,
            "vk incompatible with proof"
        );
        assert_eq!(
            var_len_input.app_vk.h1.len(),
            var_len_input.app_vk.h2.len(),
            "inconsistent vk"
        );
        let commitment_point = commitment_point_coordinates
            .get(0)
            .map(|commitment_point_coordinates| {
                let m = G1Affine {
                    x: commitment_point_coordinates[0],
                    y: commitment_point_coordinates[1],
                };
                assert!(
                    bool::from(m.is_on_curve()),
                    "Coordinates do not represent a curve point"
                );
                m
            })
            .unwrap_or(G1Affine::generator());
        let commitment_point_limbs =
            g1affine_into_limbs(&commitment_point, LIMB_BITS, NUM_LIMBS);
        let commitment_hash = commitment_hash_from_commitment_point_limbs(
            &commitment_point_limbs,
            LIMB_BITS,
            NUM_LIMBS,
        );

        let padding = (var_len_input.app_public_inputs.len()
            + has_commitment as usize
            ..max_num_public_inputs)
            .into_iter()
            .map(|_| F::zero());
        let mut padded_app_public_inputs =
            var_len_input.app_public_inputs.clone();
        if has_commitment {
            padded_app_public_inputs.push(commitment_hash);
        }
        padded_app_public_inputs.extend(padding);

        let mut vk = var_len_input.app_vk.clone();
        vk.pad(max_num_public_inputs);

        let app_vk = PaddedVerifyingKeyLimbs::from_vk(&vk);

        KeccakPaddedCircuitInput {
            len: F::from(var_len_input.app_public_inputs.len() as u64),
            has_commitment: F::from(has_commitment),
            app_vk,
            app_public_inputs: padded_app_public_inputs,
            commitment_hash,
            commitment_point_limbs,
        }
    }
}

/// Internal struct containing the data required to create a witness, given a
/// proving key (namely, the vk_hash followed by all app public inputs). Note,
/// this does NOT represent an instance of the circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeccakPaddedCircuitInputs<F: EccPrimeField<Repr = [u8; 32]>> {
    pub(crate) inputs: Vec<KeccakPaddedCircuitInput<F>>,
    /// Number of proof ids to take into account for the submission id
    /// computation
    pub(crate) num_proof_ids: Option<F>,
}

impl<F> KeccakPaddedCircuitInputs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    pub(crate) fn from_var_len_inputs(
        value: &[KeccakVarLenInput<F>],
        max_num_public_inputs: usize,
        num_proof_ids: Option<u64>,
    ) -> Self {
        let inputs: Vec<KeccakPaddedCircuitInput<F>> = value
            .iter()
            .map(|var_len_input| {
                KeccakPaddedCircuitInput::from_var_len_input(
                    var_len_input,
                    max_num_public_inputs,
                )
            })
            .collect();
        let num_proof_ids = num_proof_ids.map(F::from);

        KeccakPaddedCircuitInputs {
            inputs,
            num_proof_ids,
        }
    }

    pub(crate) fn from_keccak_circuit_inputs(
        value: &KeccakCircuitInputs<F>,
        max_num_public_inputs: usize,
    ) -> Self {
        KeccakPaddedCircuitInputs::from_var_len_inputs(
            &value.inputs,
            max_num_public_inputs,
            value.num_proof_ids,
        )
    }
}

impl<F: EccPrimeField<Repr = [u8; 32]>> KeccakPaddedCircuitInputs<F> {
    /// Creates some dummy [`KeccakPaddedCircuitInputs`] for `config` with `input_type`.
    pub fn dummy(config: &KeccakConfig) -> Self {
        let num_proof_ids = config.output_submission_id.then_some(F::from(
            (config.inner_batch_size * config.outer_batch_size) as u64,
        ));
        Self {
            inputs: (0..config.inner_batch_size * config.outer_batch_size)
                .map(|_| KeccakPaddedCircuitInput::dummy(config))
                .collect(),
            num_proof_ids,
        }
    }

    /// Checks if `self` consists of valid public inputs for `config`.
    pub fn is_well_constructed(&self, config: &KeccakConfig) -> bool {
        // Total number of inputs should match `inner_batch_size` * `outer_batch_size`
        if config.inner_batch_size * config.outer_batch_size
            != self.inputs.len() as u32
        {
            return false;
        }

        if config.output_submission_id ^ self.num_proof_ids.is_some() {
            return false;
        }

        // Each individual input should be well-constructed.
        self.inputs.iter().all(|input| {
            KeccakPaddedCircuitInput::is_well_constructed(input, config)
        })
    }
}

/// Assigned verifying key, where each field is represented by its
/// `F` limbs.
#[derive(Clone, Debug)]
pub(crate) struct AssignedVerifyingKeyLimbs<F>
where
    F: ScalarField,
{
    pub(crate) alpha: Vec<AssignedValue<F>>,
    pub(crate) beta: Vec<AssignedValue<F>>,
    pub(crate) gamma: Vec<AssignedValue<F>>,
    pub(crate) delta: Vec<AssignedValue<F>>,
    pub(crate) s: Vec<Vec<AssignedValue<F>>>,
    pub(crate) h1: Vec<AssignedValue<F>>,
    pub(crate) h2: Vec<AssignedValue<F>>,
}

impl<F> AssignedVerifyingKeyLimbs<F>
where
    F: ScalarField,
{
    /// Creates a new [`AssignedVerifyingKeyLimbs`] from `vk`, assigning it
    /// to `ctx` as a witness.
    pub fn from_padded_verifying_key(
        ctx: &mut Context<F>,
        vk: PaddedVerifyingKeyLimbs<F>,
    ) -> Self
    where
        F: EccPrimeField<Repr = [u8; 32]>,
    {
        Self {
            alpha: ctx.assign_witnesses(vk.alpha),
            beta: ctx.assign_witnesses(vk.beta),
            gamma: ctx.assign_witnesses(vk.gamma),
            delta: ctx.assign_witnesses(vk.delta),
            s: vk
                .s
                .into_iter()
                .map(|s_i| ctx.assign_witnesses(s_i))
                .collect(),
            h1: ctx.assign_witnesses(vk.h1),
            h2: ctx.assign_witnesses(vk.h2),
        }
    }

    /// Returns an iterator over the elements of `self`.
    pub fn iter(&self) -> impl Iterator<Item = &AssignedValue<F>> {
        self.alpha
            .iter()
            .chain(self.beta.iter())
            .chain(self.gamma.iter())
            .chain(self.delta.iter())
            .chain(self.s.iter().flat_map(|s| s.iter()))
            .chain(self.h1.iter())
            .chain(self.h2.iter())
    }

    /// Returns a vector with the elements of `self`.
    pub fn flatten(&self) -> Vec<AssignedValue<F>> {
        self.iter().copied().collect()
    }
}

/// Assigned Keccak Input
#[derive(Clone, Debug)]
pub(crate) struct AssignedKeccakInput<F: ScalarField> {
    /// Length of the application public input, in field elements
    len: AssignedValue<F>,

    /// Application verifying key
    ///
    /// # Note
    ///
    /// This vk isn't constrained to consist of valid EC points. Furthermore,
    /// the padding of this verifying key isn't constrained to consist of
    /// the G1 generator (for the elements of `app_vk.s`) or the G2 generator
    /// (for `app_vk.h1` and `app_vk.h2`). However, its elements (i.e. its
    /// flattened representation) will be copy constrained one-to-one to the
    /// limbs of a fully constrained (in the UBV circuit) Groth16 verification key.
    pub(crate) app_vk: AssignedVerifyingKeyLimbs<F>,

    /// Has commitment flag.
    ///
    /// # Note
    ///
    /// This flag isn't constrained to be boolean in the keccak circuit.
    /// However, it will be copy-constrained in the outer circuit to another
    /// value which is known to be boolean (because it is constrained in the
    /// UBV circuit).
    pub(crate) has_commitment: AssignedValue<F>,

    /// Application public inputs
    ///
    /// # Note
    ///
    /// These should be padded to the maximum number of public inputs in
    /// the [`KeccakConfig`]. The circuit won't check the padding, and the
    /// circuit satisfiability is independent of the field elements chosen to
    app_public_inputs: Vec<AssignedValue<F>>,

    /// Commitment point hash
    pub(crate) commitment_hash: AssignedValue<F>,

    /// Commitment point limbs
    pub(crate) commitment_point_limbs: Vec<AssignedValue<F>>,
}

impl<F: ScalarField> AssignedKeccakInput<F> {
    /// Returns the length of `self`.
    pub fn len(&self) -> &AssignedValue<F> {
        &self.len
    }

    /// Returns the application public inputs in `self`.
    pub fn public_inputs(&self) -> Vec<AssignedValue<F>> {
        self.app_public_inputs.clone()
    }

    /// Flattens `self`, returning a vector of [`AssignedValue`]s.
    pub fn to_instance_values(&self) -> Vec<AssignedValue<F>> {
        let mut result = vec![self.len];
        result.extend_from_slice(&self.app_vk.flatten());
        result.push(self.has_commitment);
        result.push(self.commitment_hash);
        result.extend_from_slice(&self.commitment_point_limbs);
        result.extend_from_slice(&self.app_public_inputs);
        result
    }

    /// Assigns `input` to the `ctx`, returning a [`AssignedKeccakInput`].
    pub fn from_keccak_padded_input(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        input: KeccakPaddedCircuitInput<F>,
    ) -> Self
    where
        F: EccPrimeField<Repr = [u8; 32]>,
    {
        let max_len = input.app_public_inputs.len() as u64;

        let len = ctx.load_witness(input.len);
        let app_public_inputs = ctx.assign_witnesses(input.app_public_inputs);
        let commitment_hash = ctx.load_witness(input.commitment_hash);
        let commitment_point_limbs =
            ctx.assign_witnesses(input.commitment_point_limbs);
        let app_vk = AssignedVerifyingKeyLimbs::from_padded_verifying_key(
            ctx,
            input.app_vk,
        );
        let has_commitment = ctx.load_witness(input.has_commitment);
        // Constrain `len + has_commitment < MAX_LEN`
        let len_inputs_and_commitment =
            range.gate.add(ctx, len, has_commitment);
        range.check_less_than_safe(ctx, len_inputs_and_commitment, max_len + 1);
        // Constrain `len > 0`
        let is_len_zero = range.gate.is_zero(ctx, len);
        range.gate.assert_is_const(ctx, &is_len_zero, &F::zero());
        Self {
            len,
            app_vk,
            has_commitment,
            app_public_inputs,
            commitment_hash,
            commitment_point_limbs,
        }
    }
}

/// Assigned Keccak Inputs
#[derive(Clone, Debug)]
pub(crate) struct AssignedKeccakInputs<F: ScalarField> {
    pub inputs: Vec<AssignedKeccakInput<F>>,
    /// Number of proof ids for the submission id computation.
    /// Note: this is a witness and not part of the instance
    #[allow(dead_code)] // Kept for consistency with the other two
    // keccak input structs. Also it is useful in case we want to make
    // num_proof_ids a public input (instead of a witness) in the
    // future
    pub num_proof_ids: Option<AssignedValue<F>>,
}

impl<F> AssignedKeccakInputs<F>
where
    F: Field,
{
    /// Flattens `self`.
    pub fn to_instance_values(&self) -> Vec<AssignedValue<F>> {
        self.inputs
            .iter()
            .flat_map(AssignedKeccakInput::to_instance_values)
            .collect()
    }
}

/// Keccak gate configuration. The data that must be saved after keygen,
/// and reloaded at prove/verify time.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeccakGateConfig {
    flex_gate_config_params: FlexGateConfigParams,
    rows_per_round: u32,
    lookup_bits: usize,
}

impl KeccakGateConfig {
    /// Returns the number of flex gate columns in `self`. This number is
    /// necessary to determine which columns in the circuit will contain
    /// the keccak input words and the keccak output bytes, and thus have
    /// to be enabled for the permutation argument.
    pub fn num_flex_cols(&self) -> usize {
        self.flex_gate_config_params.num_advice_per_phase[0]
            + self.flex_gate_config_params.num_lookup_advice_per_phase[0]
            + (self.flex_gate_config_params.num_advice_per_phase[0] > 1)
                as usize
    }
}

/// The Keccak circuit.  Note that all initalizaters should *ignore* environment variables,
/// accepting all parameters via [`KeccakConfig`]. This will avoid conflicts with
/// other previously used circuits. However, initializers should *set* any
/// environment variables required for later operations.
pub struct KeccakCircuit<F = Fr, C = G1Affine>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
{
    /// Builder
    builder: RefCell<GateThreadBuilder<F>>,
    /// Break points
    break_points: RefCell<MultiPhaseThreadBreakPoints>,
    /// Keccak chip
    keccak: KeccakChip<F>,
    /// Public inputs
    pub(crate) public_inputs: AssignedKeccakInputs<F>,
    /// Public output
    pub(crate) public_output: [AssignedValue<F>; 2],
    /// Gate config
    config: KeccakGateConfig,
    _marker: PhantomData<C>,
}

impl<F, C> KeccakCircuit<F, C>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
{
    /// Computes the circuit Id as a [`multi_var_query`](KeccakChip::multi_var_query)
    /// of the limbs of `assigned_input.app_vk`.
    fn compute_circuit_id(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        assigned_input: &AssignedKeccakInput<F>,
    ) -> Vec<AssignedValue<F>> {
        // select domain tag
        let domain_tag_groth16: Vec<AssignedValue<F>> =
            compute_domain_tag(UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING)
                .into_iter()
                .map(|byte| ctx.load_constant(F::from(byte as u64)))
                .collect_vec();
        let domain_tag_groth16_with_commitment: Vec<AssignedValue<F>> =
            compute_domain_tag(
                UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING_WITH_COMMITMENT,
            )
            .into_iter()
            .map(|byte| ctx.load_constant(F::from(byte as u64)))
            .collect_vec();
        let mut domain_tag = Vec::with_capacity(32);
        for (without_commitment, with_commitment) in domain_tag_groth16
            .into_iter()
            .zip_eq(domain_tag_groth16_with_commitment.into_iter())
        {
            domain_tag.push(range.gate.select(
                ctx,
                with_commitment,
                without_commitment,
                assigned_input.has_commitment,
            ));
        }

        // Compute vk_s length as public_inputs.len() + has_commitment + 1
        let len = assigned_input.len();
        let pi_len_plus_has_commitment =
            range.gate.add(ctx, *len, assigned_input.has_commitment);
        let one = ctx.load_constant(F::one());
        let vk_s_len = range.gate.add(ctx, pi_len_plus_has_commitment, one);

        // fixed input = domain_tag || alpha || beta || gamma || delta || vk_s length || vk_s[0] || vk_s[1]
        let mut fixed_input = domain_tag;
        fixed_input.append(&mut g1_point_limbs_to_bytes(
            ctx,
            range,
            &assigned_input.app_vk.alpha,
        ));
        fixed_input.append(&mut g2_point_limbs_to_bytes(
            ctx,
            range,
            &assigned_input.app_vk.beta,
        ));
        fixed_input.append(&mut g2_point_limbs_to_bytes(
            ctx,
            range,
            &assigned_input.app_vk.gamma,
        ));
        fixed_input.append(&mut g2_point_limbs_to_bytes(
            ctx,
            range,
            &assigned_input.app_vk.delta,
        ));
        fixed_input.append(&mut byte_decomposition(ctx, range, &vk_s_len));
        fixed_input.append(&mut g1_point_limbs_to_bytes(
            ctx,
            range,
            &assigned_input.app_vk.s[0],
        ));
        // We require `len > 0`, so this element always exists
        fixed_input.append(&mut g1_point_limbs_to_bytes(
            ctx,
            range,
            &assigned_input.app_vk.s[1],
        ));

        // Variable input vk.s[2..]
        let num_limbs_per_g1 = ctx.load_constant(F::from(2 * NUM_LIMBS as u64));
        let vk_remaining_len =
            range.gate.sub(ctx, pi_len_plus_has_commitment, one);
        let vk_s_len_limbs =
            range.gate.mul(ctx, vk_remaining_len, num_limbs_per_g1);
        let vk_s = assigned_input
            .app_vk
            .s
            .iter()
            .skip(2)
            .flatten()
            .cloned()
            .collect();
        // Variable input vk.h1 || vk.h2
        let mut vk_h = Vec::with_capacity(2 * 4 * NUM_LIMBS);
        let vk_h_max_len = ctx.load_constant(F::from(2 * 4 * NUM_LIMBS as u64));
        let vk_h_len =
            range
                .gate
                .mul(ctx, vk_h_max_len, assigned_input.has_commitment);
        vk_h.extend_from_slice(&assigned_input.app_vk.h1);
        vk_h.extend_from_slice(&assigned_input.app_vk.h2);
        keccak.multi_var_query(
            ctx,
            range,
            fixed_input,
            vec![vk_s, vk_h],
            vec![vk_s_len_limbs, vk_h_len],
        )
    }

    /// For `assigned_input` and `circuit_id`:
    /// 1) computes the byte decomposition of `assigned_input.public_inputs`
    /// 2) computes its proof Id as the [`keccak_var_len`](KeccakChip::keccak_var_len)
    /// query of the concatenatenation of `circuit_id` and the byte decomposition
    /// computed in 1).
    ///
    /// The resulting query added to the keccak chip will be processed later
    /// by [`assign_keccak_cells`](KeccakChip::assign_keccak_cells).
    fn compute_proof_id(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        circuit_id: &[AssignedValue<F>],
        assigned_input: &AssignedKeccakInput<F>,
    ) {
        // Step 1: Byte decomposition of the field elements
        let len = assigned_input.len();
        let field_elements = assigned_input.public_inputs();
        let mut byte_repr = circuit_id.to_owned();
        byte_repr.append(&mut byte_decomposition_list(
            ctx,
            range,
            &field_elements,
        ));
        // Step 2: byte length computation
        let byte_len = variable::upa_input_len_to_byte_len(ctx, range, *len);
        // Step 3: Keccak variable length computation
        keccak.keccak_var_len(ctx, range, byte_repr, byte_len);
    }

    /// For `assigned_input.commitment_point_limbs`, computes:
    /// 1) Its byte decomposition
    /// 2) Its word decomposition
    /// 3) Its keccak hash as a [`keccak_fixed_len`](KeccakChip::keccak_fixed_len) query.
    ///
    /// Then it constrains the resulting keccak hash (composed as a field element) to
    /// be equal to `assigned_input.commitment_hash`.
    fn commitment_point_hash_query(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        assigned_input: &AssignedKeccakInput<F>,
    ) {
        // Byte decomposition
        let commitment_point_bytes = g1_point_limbs_to_bytes(
            ctx,
            range,
            &assigned_input.commitment_point_limbs,
        );
        keccak.keccak_fixed_len(ctx, range, commitment_point_bytes);
        let output_bytes = keccak
            .fixed_len_queries()
            .last()
            .expect("Retrieving the last keccak query is not allowed to fail")
            .output_bytes_assigned()
            .try_into()
            .expect("Conversion is not allowed to fail");
        let commitment_hash =
            compose_into_field_element(ctx, range, &output_bytes);
        ctx.constrain_equal(&commitment_hash, &assigned_input.commitment_hash);
    }

    /// Computes the Merkle leaf corresponding to `proof_id`.
    fn compute_leaf(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        proof_id: &[AssignedValue<F>],
    ) -> Vec<AssignedValue<F>> {
        assert_eq!(proof_id.len(), 32, "Invalid number of bytes in proof id");
        keccak.keccak_fixed_len(ctx, range, proof_id.to_vec());
        keccak
            .fixed_len_queries()
            .last()
            .expect("Retrieving the last keccak query is not allowed to fail")
            .output_bytes_assigned()
            .to_vec()
    }

    /// Hashes `left_node` with `right_node`.
    fn hash_pair(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        left_node: &[AssignedValue<F>],
        right_node: &[AssignedValue<F>],
    ) -> Vec<AssignedValue<F>> {
        let mut input_bytes = left_node.to_vec();
        input_bytes.extend_from_slice(right_node);
        keccak.keccak_fixed_len(ctx, range, input_bytes);
        keccak
            .fixed_len_queries()
            .last()
            .expect("Retrieving the last keccak query is not allowed to fail")
            .output_bytes_assigned()
            .to_vec()
    }

    /// Pairwise hashes all elements of `row`.
    fn hash_row(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        row: Vec<Vec<AssignedValue<F>>>,
    ) -> Vec<Vec<AssignedValue<F>>> {
        let number_of_nodes = row.len();
        let mut next_row = Vec::with_capacity(number_of_nodes / 2);
        for i in (0..number_of_nodes).step_by(2) {
            next_row.push(Self::hash_pair(
                ctx,
                range,
                keccak,
                &row[i],
                &row[i + 1],
            ));
        }
        next_row
    }

    /// Groups `proof_ids` in groups of 32 bytes (each representing a proof id).
    /// Keeps the first `num_proof_ids` groups and replaces the rest with zeroes.
    fn pad_proof_ids(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        proof_ids: &[AssignedValue<F>],
        num_proof_ids: AssignedValue<F>,
    ) -> Vec<Vec<AssignedValue<F>>> {
        let mut proof_ids = proof_ids
            .iter()
            .chunks(32)
            .into_iter()
            .map(|chunk| chunk.into_iter().copied().collect_vec())
            .collect_vec();
        let total_num_proof_ids = proof_ids.len();
        assert_eq!(
            (total_num_proof_ids & (total_num_proof_ids - 1)),
            0,
            "The number of (padded) proof ids must be a power of two in submission id mode"
        );
        assert!(
            total_num_proof_ids > 1,
            "Only circuits with more than 1 proof id supported"
        );

        let zero = ctx.load_constant(F::zero());
        let bitmask = first_i_bits_bitmask(
            ctx,
            &range.gate,
            num_proof_ids,
            total_num_proof_ids as u64,
        );

        for (proof_id, bit) in proof_ids.iter_mut().zip(bitmask.iter()) {
            for byte in proof_id.iter_mut() {
                *byte = range.gate.select(ctx, *byte, zero, *bit)
            }
        }

        proof_ids
    }

    /// Computes the leaves of the Merkle tree from `proof_ids`,
    fn compute_leaves(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        proof_ids: &[AssignedValue<F>],
        num_proof_ids: AssignedValue<F>,
    ) -> Vec<Vec<AssignedValue<F>>> {
        let proof_ids =
            Self::pad_proof_ids(ctx, range, proof_ids, num_proof_ids);
        proof_ids
            .into_iter()
            .map(|proof_id| Self::compute_leaf(ctx, range, keccak, &proof_id))
            .collect_vec()
    }

    /// Computes the submission id from `proof_ids` as bytes.
    pub(crate) fn compute_submission_id_bytes(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        proof_ids: &[AssignedValue<F>],
        num_proof_ids: AssignedValue<F>,
    ) -> [AssignedValue<F>; 32] {
        let mut current_row =
            Self::compute_leaves(ctx, range, keccak, proof_ids, num_proof_ids);

        while current_row.len() > 1 {
            current_row = Self::hash_row(ctx, range, keccak, current_row);
        }
        current_row
            .into_iter()
            .next()
            .expect("Retrieving the root bytes is not allowed to fail")
            .try_into()
            .expect("Conversion from vector to array is not allowed to fail")
    }

    /// Computes the submission id from `proof_ids`.
    fn compute_submission_id(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        proof_ids: &[AssignedValue<F>],
        num_proof_ids: AssignedValue<F>,
    ) -> [AssignedValue<F>; 2] {
        let submission_id_bytes = Self::compute_submission_id_bytes(
            ctx,
            range,
            keccak,
            proof_ids,
            num_proof_ids,
        );
        encode_digest_as_field_elements(ctx, range, &submission_id_bytes)
    }

    /// Computes the final digest as the keccak hash of all `proof_ids`.
    fn compute_linear_final_digest(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak: &mut KeccakChip<F>,
        proof_ids: &[AssignedValue<F>],
    ) -> [AssignedValue<F>; 2] {
        keccak.keccak_fixed_len(ctx, range, proof_ids.to_vec());
        let public_output_bytes = keccak
            .fixed_len_queries()
            .last()
            .expect("Retrieving the last keccak query is not allowed to fail")
            .output_bytes_assigned();
        let public_output_bytes = public_output_bytes
            .to_vec()
            .try_into()
            .expect("Conversion from vector to array is not allowed to fail");
        encode_digest_as_field_elements(ctx, range, &public_output_bytes)
    }

    /// Instantiates a new [`KeccakCircuit`] from `degree_bits`, `builder` and `inputs`.
    fn new(
        config: &KeccakConfig,
        mut builder: GateThreadBuilder<F>,
        inputs: KeccakPaddedCircuitInputs<F>,
    ) -> Self {
        let witness_gen_only = builder.witness_gen_only();
        let ctx = builder.main(0);
        let lookup_bits = config.lookup_bits;
        let range = RangeChip::default(lookup_bits);
        let mut keccak = KeccakChip::default();
        let mut public_inputs = Vec::new();
        // Assign and constrain `num_proof_ids`
        assert!(
            config.output_submission_id ^ inputs.num_proof_ids.is_none(),
            "Config incompatible with inputs"
        );
        let num_proof_ids =
            inputs.num_proof_ids.map(|npi| ctx.load_constant(npi));
        if config.output_submission_id {
            range.check_less_than_safe(
                ctx,
                num_proof_ids.expect("Num proof ids has been assigned before"),
                (config.inner_batch_size * config.outer_batch_size + 1).into(),
            );
        }
        for input in inputs.inputs {
            let assigned_input = AssignedKeccakInput::from_keccak_padded_input(
                ctx, &range, input,
            );
            let circuit_id = Self::compute_circuit_id(
                ctx,
                &range,
                &mut keccak,
                &assigned_input,
            );
            // Specification: Proof ID Computation
            Self::compute_proof_id(
                ctx,
                &range,
                &mut keccak,
                &circuit_id,
                &assigned_input,
            );
            // Specification: Curve-to-Field Hash
            Self::commitment_point_hash_query(
                ctx,
                &range,
                &mut keccak,
                &assigned_input,
            );
            public_inputs.push(assigned_input);
        }

        // Specification: Final Digest Computation.
        // Here we select only the even var_len_queries because those
        // contain the proofIds. The odd ones contain the circuitIds
        // which are not hashes into the final digest.
        let proof_ids = keccak
            .var_len_queries()
            .iter()
            .skip(1)
            .step_by(2) // we skip the circuitId computations
            .flat_map(|query| query.output_bytes_assigned().to_vec())
            .collect::<Vec<_>>();
        let public_output = match config.output_submission_id {
            true => Self::compute_submission_id(
                ctx,
                &range,
                &mut keccak,
                &proof_ids,
                num_proof_ids.expect("Num proof ids has been assigned before"),
            ),
            false => Self::compute_linear_final_digest(
                ctx,
                &range,
                &mut keccak,
                &proof_ids,
            ),
        };
        // Compute optimal parameters
        let config = if witness_gen_only {
            serde_json::from_str(
                &var("KECCAK_GATE_CONFIG").expect("KECCAK_GATE_CONFIG not set"),
            )
            .expect("Deserialization error")
        } else {
            Self::config(
                &builder,
                &mut keccak,
                config.degree_bits,
                Some(DEFAULT_UNUSABLE_ROWS),
                Some(lookup_bits),
            )
        };
        Self {
            builder: RefCell::new(builder),
            break_points: RefCell::new(Default::default()),
            keccak,
            public_inputs: AssignedKeccakInputs {
                inputs: public_inputs,
                num_proof_ids,
            },
            public_output,
            config,
            _marker: PhantomData,
        }
    }

    /// Returns the public output.
    pub fn public_output(&self) -> &[AssignedValue<F>] {
        self.public_output.as_slice()
    }

    /// Returns the intermediate outputs.
    pub fn keccak_output_bytes(&self) -> Vec<&AssignedValue<F>> {
        self.keccak
            .var_len_queries()
            .iter()
            .flat_map(|query| query.output_bytes_assigned())
            .chain(
                self.keccak
                    .fixed_len_queries()
                    .iter()
                    .flat_map(|query| query.output_bytes_assigned()),
            )
            .collect()
    }

    /// Calculates the optimal [`KeccakGateConfig`] for a given `degree_bits`.
    pub(crate) fn config(
        builder: &GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        degree_bits: u32,
        minimum_rows: Option<usize>,
        lookup_bits: Option<usize>,
    ) -> KeccakGateConfig {
        let optimal_rows_per_round = rows_per_round(
            (1 << degree_bits) - minimum_rows.unwrap_or(0),
            keccak.total_keccak_perms(),
        );
        let flex_gate_config_params =
            builder.config(degree_bits as usize, minimum_rows);
        let mut params = KeccakGateConfig {
            flex_gate_config_params,
            rows_per_round: 0,
            lookup_bits: lookup_bits.unwrap_or(KECCAK_LOOKUP_BITS),
        };

        params.rows_per_round =
            std::cmp::min(optimal_rows_per_round, MAX_KECCAK_ROWS_PER_ROUND);
        keccak.num_rows_per_round = params.rows_per_round as usize;
        set_var("KECCAK_LOOKUP_BITS", params.lookup_bits.to_string());
        set_var(
            "KECCAK_GATE_CONFIG",
            serde_json::to_string(&params).unwrap(),
        );
        set_var("FLEX_GATE_NUM_COLS", params.num_flex_cols().to_string());
        set_var("KECCAK_DEGREE", degree_bits.to_string());
        set_var("KECCAK_ROWS", params.rows_per_round.to_string());
        params
    }

    /// Extracts the cells containing the public inputs in `self`.
    fn extract_public_inputs(
        &self,
        assignments: &KeygenAssignments<F>,
    ) -> Vec<circuit::Cell> {
        self.public_inputs
            .to_instance_values()
            .iter()
            .map(|assigned_value| {
                assigned_cell_from_assigned_value(assigned_value, assignments)
            })
            .collect()
    }

    /// Extracts the two cells containing the public output in `self`.
    fn extract_public_output(
        &self,
        assignments: &KeygenAssignments<F>,
    ) -> [circuit::Cell; 2] {
        self.public_output
            .map(|po| assigned_cell_from_assigned_value(&po, assignments))
    }

    /// Synthesizes `self`, generating constraints. Returns the [`Cell`](circuit::Cell)s
    /// corresponding to the public inputs and outputs so we can later expose them.
    ///
    /// The keccak chip defines (wide) gates and rows, unrelated to the Context columns,
    /// and allocates cells in the context for the inputs as 64-bit words, and for output bytes.
    /// However, it does not add contraints in the Context - that is done here.
    ///
    /// We must:
    /// a) constrain the input 64-bit words to be correct given the byte inputs (in the Context)
    /// b) copy-constrain the input 64-bit words in the Context to those in the Keccak rows
    /// c) copy-constrain the output bytes in the Context to those in the Keccak rows
    ///
    /// The input byte cells of the last Keccak query are already given as the outputs from all previous queries, and
    /// so the copy-constraints given above constrain the final output to be the desired final digest.
    fn synthesize(
        &self,
        config: &KeccakCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) -> ExposedInstances {
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");
        config
            .keccak
            .load_aux_tables(layouter)
            .expect("load keccak lookup tables");
        let mut first_pass = SKIP_FIRST_PASS;
        let witness_gen_only = self.builder.borrow().witness_gen_only();
        let mut assigned_public_outputs = None;
        let mut assigned_public_inputs = Vec::new();
        layouter
            .assign_region(
                || "KeccakCircuitBuilder generated circuit",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    if witness_gen_only {
                        let builder = &mut self.builder.borrow_mut();
                        let break_points = &mut self.break_points.borrow_mut();
                        // Generate keccak constraints
                        assign_prover(
                            &mut region,
                            &config.range.gate,
                            &config.range.lookup_advice,
                            builder,
                            break_points,
                        );
                        self.keccak
                            .assign_keccak_cells(&mut region, &config.keccak);
                    } else {
                        let start = std::time::Instant::now();
                        let builder = self.builder.borrow();
                        // Builder cell assignments
                        let assignments = builder.assign_all(
                            &config.range.gate,
                            &config.range.lookup_advice,
                            &config.range.q_lookup,
                            &mut region,
                            Default::default(),
                        );
                        // Expose public inputs
                        let extracted_public_inputs =
                            self.extract_public_inputs(&assignments);
                        assigned_public_inputs.extend(extracted_public_inputs);
                        // Expose public output
                        let public_output =
                            self.extract_public_output(&assignments);
                        assigned_public_outputs = Some(public_output);

                        let (fixed_len_cells, var_len_cells) = self
                            .keccak
                            .assign_keccak_cells(&mut region, &config.keccak);

                        self.keccak.constrain_fixed_queries(
                            &mut region,
                            &assignments,
                            &fixed_len_cells,
                        );

                        self.keccak.constrain_var_queries(
                            &mut region,
                            &assignments,
                            &var_len_cells,
                        );
                        // Update break points
                        *self.break_points.borrow_mut() =
                            assignments.break_points;
                        log::info!(
                            "keccak keygen constraint gen {:?}",
                            start.elapsed()
                        );
                    }
                    Ok(())
                },
            )
            .unwrap();
        (assigned_public_inputs, assigned_public_outputs)
    }
}

// NOTE: only implemented for F = bn256::Fr, since the implementation relies on
// digest_as_field_elements, which is field dependent.
impl<'a> SafeCircuit<'a, Fr, G1Affine> for KeccakCircuit<Fr, G1Affine> {
    type CircuitConfig = KeccakConfig;
    type GateConfig = KeccakGateConfig;
    type CircuitInputs = KeccakCircuitInputs<Fr>;
    type KeygenInputs = ();
    type InstanceInputs = KeccakCircuitInputs<Fr>;

    fn mock(
        config: &Self::CircuitConfig,
        inputs: &Self::CircuitInputs,
    ) -> Self {
        let circuit_inputs =
            KeccakPaddedCircuitInputs::from_keccak_circuit_inputs(
                inputs,
                config.num_app_public_inputs as usize,
            );
        assert!(
            circuit_inputs.is_well_constructed(config),
            "Invalid keccak circuit inputs"
        );
        Self::new(config, GateThreadBuilder::mock(), circuit_inputs)
    }

    fn keygen(
        config: &Self::CircuitConfig,
        inputs: &Self::KeygenInputs,
    ) -> Self {
        let _ = inputs;
        Self::new(
            config,
            GateThreadBuilder::keygen(),
            KeccakPaddedCircuitInputs::dummy(config),
        )
    }

    fn prover(
        config: &Self::CircuitConfig,
        gate_config: &Self::GateConfig,
        break_points: MultiPhaseThreadBreakPoints,
        inputs: &Self::CircuitInputs,
    ) -> Self {
        let circuit_inputs =
            KeccakPaddedCircuitInputs::from_keccak_circuit_inputs(
                inputs,
                config.num_app_public_inputs as usize,
            );

        {
            // Check well-formedness of the public inputs w.r.t. the configuration
            assert!(
                circuit_inputs.is_well_constructed(config),
                "Invalid keccak circuit inputs"
            );
            // Check gate_config coincides with KECCAK_GATE_CONFIG
            let gate_config_env =
                var("KECCAK_GATE_CONFIG").expect("KECCAK_GATE_CONFIG not set");
            let gate_config_json = serde_json::to_string(&gate_config)
                .expect("failed to serialize Keccak gate config");
            assert_eq!(
                gate_config_env, gate_config_json,
                "keccak gate configuration mismatch"
            );
            // Check config.lookup_bits coincides with KECCAK_LOOKUP_BITS
            let lookup_bits_env = var("KECCAK_LOOKUP_BITS")
                .expect("KECCAK_LOOKUP_BITS not set")
                .parse::<usize>()
                .expect("Error parsing KECCAK_LOOKUP_BITS");
            assert_eq!(
                lookup_bits_env, config.lookup_bits,
                "lookup bits configuration mismatch"
            );
            assert_eq!(
                lookup_bits_env, gate_config.lookup_bits,
                "lookup bits configuration mismatch"
            );
            // Check gate_config.flex_gate_config_params has the same number of
            // columns as FLEX_GATE_NUM_COLS
            let num_flex_cols = var("FLEX_GATE_NUM_COLS")
                .expect("FLEX_GATE_NUM_COLS not set")
                .parse::<usize>()
                .expect("Error parsing FLEX_GATE_NUM_COLS");
            assert_eq!(
                num_flex_cols,
                gate_config.num_flex_cols(),
                "Flex Gate num cols mismatch"
            );

            // Check config.degree_bits coincides with KECCAK_DEGREE
            let keccak_degree_env = var("KECCAK_DEGREE")
                .expect("KECCAK_DEGREE not set")
                .parse::<u32>()
                .expect("Error parsing KECCAK_DEGREE");
            assert_eq!(
                keccak_degree_env, config.degree_bits,
                "Keccak degree mismatch"
            );
        }
        let circuit =
            Self::new(config, GateThreadBuilder::prover(), circuit_inputs);
        *circuit.break_points.borrow_mut() = break_points;
        circuit
    }

    fn compute_instance(
        config: &Self::CircuitConfig,
        inputs: &Self::InstanceInputs,
    ) -> Vec<Fr> {
        let (proof_ids, padded_inputs): (
            Vec<[u8; 32]>,
            Vec<KeccakPaddedCircuitInput<Fr>>,
        ) = {
            let input_slice = &inputs.inputs;
            let proof_ids: Vec<[u8; 32]> = input_slice
                .iter()
                .map(|i| {
                    let circuit_id =
                        universal::native::compute_circuit_id(&i.app_vk);
                    compute_proof_id(&circuit_id, i.app_public_inputs.iter())
                })
                .collect();

            // [
            //   len_0, vk_limbs_0, has_commitment_0, commitment_hash_0, commitment_limbs_0, padded_inputs_0
            //   len_1, vk_limbs_1, has_commitment_1, commitment_hash_1, commitment_limbs_1, padded_inputs_1
            //   ...
            //   final_digest_0, final_digest_1
            // ]
            (
                proof_ids,
                input_slice
                    .iter()
                    .map(|i| {
                        KeccakPaddedCircuitInput::from_var_len_input(
                            i,
                            config.num_app_public_inputs as usize,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };

        let final_digest = match config.output_submission_id {
            true => compute_submission_id(proof_ids),
            false => compute_final_digest(proof_ids),
        };

        padded_inputs
            .iter()
            .flat_map(|i| i.to_instance_values())
            .chain(digest_as_field_elements(&final_digest).into_iter())
            .collect()
    }

    fn gate_config(&self) -> &Self::GateConfig {
        &self.config
    }

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.break_points.borrow().clone()
    }

    fn read_proving_key<R: std::io::Read>(
        circuit_config: &Self::CircuitConfig,
        gate_config: &Self::GateConfig,
        reader: &mut R,
    ) -> Result<ProvingKey<G1Affine>, std::io::Error> {
        // Set environment variables
        set_var(
            "KECCAK_GATE_CONFIG",
            serde_json::to_string(&gate_config).unwrap(),
        );
        set_var(
            "FLEX_GATE_NUM_COLS",
            gate_config.num_flex_cols().to_string(),
        );
        set_var("KECCAK_DEGREE", circuit_config.degree_bits.to_string());
        set_var("KECCAK_ROWS", gate_config.rows_per_round.to_string());
        set_var("KECCAK_LOOKUP_BITS", gate_config.lookup_bits.to_string());
        // Read public key
        ProvingKey::read::<_, Self>(reader, SerdeFormat::RawBytesUnchecked)
    }

    fn read_verifying_key<R: std::io::Read>(
        gate_config: &Self::GateConfig,
        reader: &mut R,
    ) -> Result<VerifyingKey<G1Affine>, std::io::Error> {
        // Set environment variables
        set_var(
            "KECCAK_GATE_CONFIG",
            serde_json::to_string(&gate_config).unwrap(),
        );
        set_var(
            "FLEX_GATE_NUM_COLS",
            gate_config.num_flex_cols().to_string(),
        );
        set_var(
            "KECCAK_DEGREE",
            gate_config.flex_gate_config_params.k.to_string(),
        );
        set_var("KECCAK_ROWS", gate_config.rows_per_round.to_string());
        set_var("KECCAK_LOOKUP_BITS", gate_config.lookup_bits.to_string());
        // Read verifying key
        VerifyingKey::read::<_, Self>(reader, SerdeFormat::RawBytesUnchecked)
    }
}

/// Keccak Circuit Configuration
#[derive(Clone, Debug)]
pub struct KeccakCircuitConfig<F>
where
    F: Field,
{
    /// Range Configuration
    pub range: RangeConfig<F>,
    /// Keccak Base Configuration
    pub keccak: KeccakBaseConfig<F>,
    /// Instance Column
    pub instance: Column<Instance>,
}

impl<F: Field> KeccakCircuitConfig<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        params: KeccakGateConfig,
    ) -> Self {
        let degree_bits = var("KECCAK_DEGREE")
            .expect("KECCAK_DEGREE not set")
            .parse()
            .expect("Error parsing KECCAK_DEGREE");
        let mut range = RangeConfig::configure(
            meta,
            RangeStrategy::Vertical,
            &params.flex_gate_config_params.num_advice_per_phase,
            &params.flex_gate_config_params.num_lookup_advice_per_phase,
            params.flex_gate_config_params.num_fixed,
            params.lookup_bits,
            degree_bits,
        );
        let keccak = KeccakBaseConfig::new(meta);
        set_var("UNUSABLE_ROWS", meta.minimum_rows().to_string());
        range.gate.max_rows = (1 << degree_bits) - meta.minimum_rows();
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self {
            range,
            keccak,
            instance,
        }
    }
}

impl<F, C> Circuit<F> for KeccakCircuit<F, C>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
{
    type Config = KeccakCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params = serde_json::from_str(
            &var("KECCAK_GATE_CONFIG").expect("KECCAK_GATE_CONFIG not set"),
        )
        .expect("Deserialization error");
        KeccakCircuitConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // We later take the builder, so we need to save this value
        let witness_gen_only = self.builder.borrow().witness_gen_only();
        let (assigned_public_inputs, assigned_public_output) =
            self.synthesize(&config, &mut layouter);
        if !witness_gen_only {
            // Expose public inputs
            let mut layouter = layouter.namespace(|| "expose");
            let number_of_public_inputs = assigned_public_inputs.len();
            for (i, cell) in assigned_public_inputs.iter().enumerate() {
                layouter.constrain_instance(*cell, config.instance, i);
            }
            // Expose public outputs
            for (i, output) in assigned_public_output
                .expect("No public output exposed")
                .iter()
                .enumerate()
            {
                layouter.constrain_instance(
                    *output,
                    config.instance,
                    i + number_of_public_inputs,
                );
            }
        }
        Ok(())
    }
}

impl<F, C> CircuitExt<F> for KeccakCircuit<F, C>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
{
    fn num_instance(&self) -> Vec<usize> {
        vec![self.instances()[0].len()]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![self
            .public_inputs
            .to_instance_values()
            .into_iter()
            .chain(self.public_output.iter().cloned())
            .map(|assigned| *assigned.value())
            .collect()]
    }
}
