use crate::{
    batch_verify::{
        common::{chip::BatchVerifierChip, MINIMUM_ROWS},
        universal::{
            chip::UniversalBatchVerifierChip,
            types::{
                BatchEntries, UniversalBatchVerifierConfig,
                UniversalBatchVerifierInputs,
            },
        },
    },
    keccak::PaddedVerifyingKeyLimbs,
    utils::{
        advice_cell_count,
        commitment_point::{g1affine_into_limbs, get_g1_point_limbs},
    },
    EccPrimeField, SafeCircuit,
};
use core::{iter::once, marker::PhantomData};
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder,
            MultiPhaseThreadBreakPoints, RangeWithInstanceCircuitBuilder,
            RangeWithInstanceConfig,
        },
        RangeChip,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::{
            bn256::{Fr, G1Affine},
            serde::SerdeObject,
            CurveAffine,
        },
        plonk::{Circuit, ConstraintSystem, Error, ProvingKey, VerifyingKey},
        SerdeFormat,
    },
    utils::CurveAffineExt,
    AssignedValue,
};
use halo2_ecc::bn254::FpChip;
use log::info;
use snark_verifier_sdk::CircuitExt;

pub mod chip;
pub mod native;
pub mod types;
pub mod utils;

/// Definition of the full "Universal Batch Verifier" circuit, including public
/// input definition.  Given N proofs each with n (padded) public inputs, the
/// public inputs to this circuit are arranged as follows, repeated once for
/// each proof i = 1 ... N:
///
/// ```test
///   len_i
///   vk_i
///   has_commitment_i
///   commitment_hash_i
///   commitment_point_i
///   PI_i
/// ```
///
/// where `vk_i` and `commitment_point_i` are expressed as their `F` limbs.
pub(crate) fn universal_batch_verify_circuit<F: EccPrimeField>(
    builder: &mut GateThreadBuilder<F>,
    fp_chip: &FpChip<F>,
    ubv_inputs: &BatchEntries<F>,
    num_limbs: usize,
) -> Vec<AssignedValue<F>> {
    let batch_verifier_chip = BatchVerifierChip::new(fp_chip);
    let universal_batch_verifier =
        UniversalBatchVerifierChip::<F>::new(&batch_verifier_chip);
    info!("begin: {:?}", advice_cell_count(builder));

    let assigned_batch_entries = universal_batch_verifier
        .assign_batch_entries(builder.main(0), ubv_inputs);
    info!("assigned batch entries: {:?}", advice_cell_count(builder));

    universal_batch_verifier.verify(builder, &assigned_batch_entries);

    assigned_batch_entries
        .0
        .into_iter()
        .flat_map(|entry| {
            once(entry.len)
                .chain(entry.vk.limbs(num_limbs))
                .chain(once(entry.has_commitment))
                .chain(once(entry.commitment_hash))
                .chain(get_g1_point_limbs(&entry.proof.m, num_limbs))
                .chain(entry.public_inputs)
        })
        .collect()
}

/// Universal Batch Verifier Circuit.
/// Its public input set consists of, for each application proof:
/// - The number of public inputs
/// - The verifying key (limb decomposition)
/// - A flag indicating whether the proof has a Pedersen commitment
/// - The hash of the Pedersen commitment
/// - The Pedersen commitment (limb decomposition)
/// - The public inputs
#[derive(Clone, Debug)]
pub struct UniversalBatchVerifyCircuit<F = Fr, C = G1Affine>
where
    F: EccPrimeField,
    C: CurveAffine<ScalarExt = F>,
{
    inner: RangeWithInstanceCircuitBuilder<F>,
    config: FlexGateConfigParams,
    _marker: PhantomData<C>,
}

impl<F, C> UniversalBatchVerifyCircuit<F, C>
where
    F: EccPrimeField + SerdeObject,
    C: CurveAffineExt<ScalarExt = F> + SerdeObject,
{
    /// Performs the steps that are common to each initialization type.
    /// Namely, creates the GateThreadBuilder in the appropriate mode and
    /// populates it using the application vk and proofs passed in.  Returns
    /// the populated GateThreadBuilder and the AssignedValues that hold the
    /// instance.
    fn create_builder_and_instance(
        stage: CircuitBuilderStage,
        ubv_config: &UniversalBatchVerifierConfig,
        ubv_inputs: &BatchEntries<F>,
    ) -> (GateThreadBuilder<F>, Vec<AssignedValue<F>>) {
        let mut builder = match stage {
            CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
            CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
            CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        };
        let range = RangeChip::<F>::default(ubv_config.lookup_bits);
        let num_limbs = ubv_config.num_limbs;
        let fp_chip = FpChip::<F>::new(
            &range,
            ubv_config.limb_bits,
            ubv_config.num_limbs,
        );
        let instance = universal_batch_verify_circuit::<F>(
            &mut builder,
            &fp_chip,
            ubv_inputs,
            num_limbs,
        );
        (builder, instance)
    }
}

// NOTE: implementation relies on compute_vk_hash, which is only implemented for Fr.
impl<'a> SafeCircuit<'a, Fr, G1Affine>
    for UniversalBatchVerifyCircuit<Fr, G1Affine>
{
    type CircuitConfig = UniversalBatchVerifierConfig;
    type CircuitInputs = UniversalBatchVerifierInputs<Fr>;
    type GateConfig = FlexGateConfigParams;
    type KeygenInputs = ();
    type InstanceInputs = UniversalBatchVerifierInputs<Fr>;

    fn mock(
        config: &Self::CircuitConfig,
        inputs: &Self::CircuitInputs,
    ) -> Self {
        let (builder, instance) = Self::create_builder_and_instance(
            CircuitBuilderStage::Mock,
            config,
            &BatchEntries::from_ubv_inputs_and_config(inputs, config),
        );

        std::env::set_var("LOOKUP_BITS", config.lookup_bits.to_string());
        let config =
            builder.config(config.degree_bits as usize, Some(MINIMUM_ROWS));

        Self {
            inner: RangeWithInstanceCircuitBuilder::mock(builder, instance),
            config,
            _marker: PhantomData,
        }
    }

    fn keygen(
        config: &Self::CircuitConfig,
        inputs: &Self::KeygenInputs,
    ) -> Self {
        let _ = inputs;
        let dummy_inputs = BatchEntries::dummy(config);
        let (builder, instance) = Self::create_builder_and_instance(
            CircuitBuilderStage::Keygen,
            config,
            &dummy_inputs,
        );
        info!("advice cells: {:?}", advice_cell_count(&builder));

        std::env::set_var("LOOKUP_BITS", config.lookup_bits.to_string());
        let config =
            builder.config(config.degree_bits as usize, Some(MINIMUM_ROWS));

        Self {
            inner: RangeWithInstanceCircuitBuilder::keygen(builder, instance),
            config,
            _marker: PhantomData,
        }
    }

    fn prover(
        config: &Self::CircuitConfig,
        gate_config: &Self::GateConfig,
        break_points: MultiPhaseThreadBreakPoints,
        inputs: &Self::CircuitInputs,
    ) -> Self {
        let gate_config_env_json = std::env::var("FLEX_GATE_CONFIG_PARAMS")
            .unwrap_or_else(|_| {
                panic!("FLEX_GATE_CONFIG_PARAMS not set calling prover")
            });
        let gate_config_env: FlexGateConfigParams =
            serde_json::from_str(&gate_config_env_json).unwrap_or_else(|e| {
                panic!(
                "failed reading config FlexGateConfigParams from env var: {e}"
            )
            });

        {
            // Safety check to ensure the environment variables match those
            // passed to the function.
            // Cannot compare as objects, so serialize flex_gate_config_params
            // and compare the strings.
            let gate_config_json = serde_json::to_string(&gate_config)
                .expect("failed to serialize FlexGateConfigParams");
            if gate_config_env_json != gate_config_json {
                panic!(
                    "flex_gate_config_params mismatch.\n\
                         env var: {gate_config_env_json}\n\
                         params:{gate_config_json}",
                );
            }
        }

        let lookup_bits_str = std::env::var("LOOKUP_BITS")
            .unwrap_or_else(|_| panic!("LOOKUP_BITS not set calling prover"));
        let lookup_bits = lookup_bits_str
            .parse::<usize>()
            .unwrap_or_else(|e| panic!("failed parsing lookup bits: {e}"));
        assert_eq!(
            lookup_bits, config.lookup_bits,
            "lookup_bits mismatch.  env var: {lookup_bits}, config:{}",
            config.lookup_bits
        );

        let (builder, instance) = Self::create_builder_and_instance(
            CircuitBuilderStage::Prover,
            config,
            &BatchEntries::from_ubv_inputs_and_config(inputs, config),
        );
        info!("advice cells: {:?}", advice_cell_count(&builder));

        Self {
            inner: RangeWithInstanceCircuitBuilder::prover(
                builder,
                instance,
                break_points,
            ),
            config: gate_config_env,
            _marker: PhantomData,
        }
    }

    fn compute_instance(
        config: &Self::CircuitConfig,
        inputs: &Self::InstanceInputs,
    ) -> Vec<Fr> {
        let circuit_config = config.circuit_config();
        let batch_entries =
            BatchEntries::from_ubv_inputs_and_config(inputs, config);

        // (See comment on universal_batch_verify_circuit).  Instance is:
        // [
        //   ...
        //   len_i, vk_limbs_i, has_commitment_i, commitment_hash_i, commitment_limbs_i, padded_inputs_i
        //   ...
        // ]
        batch_entries
            .0
            .iter()
            .flat_map(|be| {
                once(*be.len())
                    .chain(PaddedVerifyingKeyLimbs::from_vk(be.vk()).flatten())
                    .chain(once(Fr::from(be.has_commitment())))
                    .chain(once(*be.commitment_hash()))
                    .chain(g1affine_into_limbs(
                        &be.proof().m[0],
                        circuit_config.limb_bits,
                        circuit_config.num_limbs,
                    ))
                    .chain(be.inputs().0.iter().copied())
            })
            .collect()
    }

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.inner.break_points()
    }

    fn gate_config(&self) -> &Self::GateConfig {
        &self.config
    }

    fn read_proving_key<R>(
        circuit_config: &Self::CircuitConfig,
        gate_config: &Self::GateConfig,
        reader: &mut R,
    ) -> Result<ProvingKey<G1Affine>, std::io::Error>
    where
        R: std::io::Read,
    {
        // Setup the environment
        std::env::set_var(
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(gate_config).unwrap_or_else(|e| {
                panic!("failed to serialize FlexGateConfigParams: {e}")
            }),
        );
        std::env::set_var(
            "LOOKUP_BITS",
            circuit_config.lookup_bits.to_string(),
        );

        ProvingKey::read::<_, Self>(reader, SerdeFormat::RawBytesUnchecked)
    }

    fn read_verifying_key<R>(
        gate_config: &Self::GateConfig,
        reader: &mut R,
    ) -> Result<VerifyingKey<G1Affine>, std::io::Error>
    where
        R: std::io::Read,
    {
        std::env::set_var(
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(&gate_config).unwrap_or_else(|e| {
                panic!("failed to serialize FlexGateConfigParams: {e}")
            }),
        );

        VerifyingKey::read::<_, Self>(reader, SerdeFormat::RawBytesUnchecked)
    }
}

impl<F, C> Circuit<F> for UniversalBatchVerifyCircuit<F, C>
where
    F: EccPrimeField,
    C: CurveAffine<ScalarExt = F>,
{
    type Config = RangeWithInstanceConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        RangeWithInstanceCircuitBuilder::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
    }
}

impl<F, C> CircuitExt<F> for UniversalBatchVerifyCircuit<F, C>
where
    F: EccPrimeField,
    C: CurveAffine<ScalarExt = F>,
{
    fn num_instance(&self) -> Vec<usize> {
        vec![self.inner.assigned_instances.len()]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        let instances = self
            .inner
            .assigned_instances
            .iter()
            .map(|assigned| *assigned.value())
            .collect();
        vec![instances]
    }
}
