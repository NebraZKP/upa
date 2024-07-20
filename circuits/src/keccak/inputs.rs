//! External-facing keccak input types that can be converted into a
//! `KeccakPaddedCircuitInput`. (De)Serializable and provides a type-safe way
//! to specify fixed-len vs var-len.

use super::{KeccakConfig, KeccakInputType};
use crate::{
    batch_verify::common::{
        native::unsafe_proof_generation::sample_proofs_inputs_vk,
        types::VerificationKey,
    },
    utils::{
        field_element_hex,
        field_elements_hex::{
            self, deserialize_coordinates, serialize_coordinates,
        },
        vk_hex,
    },
    EccPrimeField,
};
use halo2_base::halo2_proofs::halo2curves::bn256::Fq;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};

/// A fixed length input to a Keccak `SafeCircuit`.
#[deprecated]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeccakFixedInput<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    /// Hash of the verifying key of the application circuit
    /// NOTE: This should not be renamed to circuit_id so that the Keccak
    /// prover daemon errors if it receives a request from the wrong type
    /// (fixed vs varlen) type of client.
    pub app_vk: VerificationKey,

    /// Application public inputs
    #[serde(with = "field_elements_hex")]
    pub app_public_inputs: Vec<F>,

    /// Commitment point hash
    #[serde(with = "field_element_hex")]
    pub commitment_hash: F,

    /// Proof commitment point limbs
    #[serde(with = "field_elements_hex")]
    pub commitment_point_limbs: Vec<F>,
}

impl<F> KeccakFixedInput<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    /// Samples a [`KeccakFixedInput`] for `config` with a given `input_type`.
    pub fn sample<R>(config: &KeccakConfig, rng: &mut R) -> Self
    where
        R: RngCore,
    {
        let _app_vk_hash = F::random(&mut *rng);
        let _ = config;
        todo!()
    }
}

///  A variable length input to a Keccak SafeCircuit. Corresponds to
/// `KeccakInput` in the typescript `prover-ts` client.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeccakVarLenInput<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    /// The verifying key of the application circuit
    #[serde(with = "vk_hex")]
    pub app_vk: VerificationKey,

    /// Unpadded application public inputs
    #[serde(with = "field_elements_hex")]
    pub app_public_inputs: Vec<F>,

    /// Proof commitment point coordinates
    #[serde(
        serialize_with = "serialize_coordinates",
        deserialize_with = "deserialize_coordinates"
    )]
    pub commitment_point_coordinates: Vec<[Fq; 2]>,
}

impl<F> KeccakVarLenInput<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    /// Samples a [`KeccakVarLenInput`] for `config` with a given `input_type`.
    pub fn sample<R>(config: &KeccakConfig, rng: &mut R) -> Self
    where
        R: RngCore,
    {
        let num_app_public_inputs =
            rng.gen_range(1..=config.num_app_public_inputs);
        let (_, app_vk) = sample_proofs_inputs_vk(
            num_app_public_inputs as usize,
            false,
            1,
            rng,
        );
        let app_public_inputs = (0..num_app_public_inputs)
            .map(|_| F::random(&mut *rng))
            .collect();
        let commitment_point_coordinates = vec![];

        KeccakVarLenInput {
            app_vk,
            app_public_inputs,
            commitment_point_coordinates,
        }
    }
}

/// Type to distinguish between fixed or variable length unpadded
/// inputs to a Keccak `SafeCircuit`. Used to prevent duplicating code-
/// implementing `SafeCircuit` for e.g. two wrapped types Fixed(KeccakCircuit)
/// and VarLen(KeccakCircuit) seems to entail duplicating the `Circuit` and
/// `CircuitExt` trait implementations.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum KeccakCircuitInputs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    Fixed(Vec<KeccakFixedInput<F>>),
    VarLen(Vec<KeccakVarLenInput<F>>),
}

impl<F> KeccakCircuitInputs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    pub fn input_type(&self) -> KeccakInputType {
        match self {
            Self::Fixed(_) => KeccakInputType::Fixed,
            Self::VarLen(_) => KeccakInputType::Variable,
        }
    }

    pub fn sample<R>(
        config: &KeccakConfig,
        input_type: KeccakInputType,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore,
    {
        match input_type {
            KeccakInputType::Fixed => {
                panic!("Fixed keccak input not allowed");
            }
            KeccakInputType::Variable => Self::VarLen(
                (0..config.inner_batch_size * config.outer_batch_size)
                    .map(|_| KeccakVarLenInput::sample(config, rng))
                    .collect(),
            ),
        }
    }
}

impl<F> From<Vec<KeccakFixedInput<F>>> for KeccakCircuitInputs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    fn from(value: Vec<KeccakFixedInput<F>>) -> Self {
        Self::Fixed(value)
    }
}

impl<F> From<Vec<KeccakVarLenInput<F>>> for KeccakCircuitInputs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    fn from(value: Vec<KeccakVarLenInput<F>>) -> Self {
        Self::VarLen(value)
    }
}
