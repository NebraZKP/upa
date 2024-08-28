//! External-facing keccak input types that can be converted into a
//! `KeccakPaddedCircuitInput`.

use super::KeccakConfig;
use crate::{
    batch_verify::common::{
        native::unsafe_proof_generation::sample_proofs_inputs_vk,
        types::VerificationKey,
    },
    utils::{
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

/// Keccak Circuit Inputs type
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeccakCircuitInputs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    pub inputs: Vec<KeccakVarLenInput<F>>,
    pub num_proof_ids: Option<usize>,
}

impl<F> KeccakCircuitInputs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    pub fn sample<R>(config: &KeccakConfig, rng: &mut R) -> Self
    where
        R: RngCore,
    {
        Self::from(
            (0..config.inner_batch_size * config.outer_batch_size)
                .map(|_| KeccakVarLenInput::sample(config, rng))
                .collect::<Vec<_>>(),
        )
    }
}

impl<F> From<Vec<KeccakVarLenInput<F>>> for KeccakCircuitInputs<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    fn from(value: Vec<KeccakVarLenInput<F>>) -> Self {
        Self {
            inputs: value,
            num_proof_ids: None,
        }
    }
}
