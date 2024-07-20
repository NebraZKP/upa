use crate::{
    batch_verify::{
        common::{
            chip::{AssignedProof, AssignedPublicInputs, BatchVerifierChip},
            types::VerificationKey,
            MINIMUM_ROWS,
        },
        fixed::{
            chip::FixedBatchVerifierChip,
            native::compute_circuit_id,
            types::{BatchVerifyConfig, BatchVerifyInputs},
            utils::dummy_app_proofs_and_inputs,
        },
    },
    utils::{advice_cell_count, hashing::digest_to_field_element},
    EccPrimeField, SafeCircuit,
};
use core::marker::PhantomData;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder,
            MultiPhaseThreadBreakPoints, RangeWithInstanceCircuitBuilder,
            RangeWithInstanceConfig,
        },
        range::RangeChip,
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
    AssignedValue,
};
use halo2_ecc::bn254::FpChip;
use log::info;
use snark_verifier_sdk::CircuitExt;

pub mod chip;
pub mod native;
pub mod types;
pub mod utils;

/// Definition of the full "Batch Verifier" circuit, including public input
/// definition.  For N proofs each with n public inputs, the public inputs are
/// arranged as follows:
///
/// ```test
///   vk_hash
///   PI_1_1  \
///   ...      }  inputs to proof 1
///   PI_1_n  /
///   PI_2_1  \
///   ...      }  inputs to proof 2
///   PI_2_n  /
///   ...
///   ...
///   ...
///   PI_N_1  \
///   ...      }  inputs to proof N
///   PI_N_n  /
/// ```
pub fn batch_verify_circuit<F: EccPrimeField>(
    builder: &mut GateThreadBuilder<F>,
    fp_chip: &FpChip<F>,
    bv_inputs: &BatchVerifyInputs<F>,
    instance: &mut Vec<AssignedValue<F>>,
) {
    let common_bv_chip = BatchVerifierChip::<F>::new(fp_chip);
    let batch_verifier = FixedBatchVerifierChip::<F>::new(&common_bv_chip);
    info!("begin: {:?}", advice_cell_count(builder));

    let assigned_vk = batch_verifier
        .assign_verification_key(builder.main(0), &bv_inputs.app_vk);
    info!("assigned vk: {:?}", advice_cell_count(builder));

    let assigned_proofs_and_inputs: Vec<(
        AssignedProof<F>,
        AssignedPublicInputs<F>,
    )> = bv_inputs
        .app_proofs_and_inputs
        .iter()
        .map(|p_i| {
            (
                batch_verifier.assign_proof(builder.main(0), &p_i.0),
                batch_verifier.assign_public_inputs(builder.main(0), &p_i.1),
            )
        })
        .collect();
    info!(
        "assigned proofs and inputs: {:?}",
        advice_cell_count(builder)
    );

    let vk_hash = batch_verifier.verify(
        builder,
        &assigned_vk,
        &assigned_proofs_and_inputs,
    );
    info!("verify: {:?}", advice_cell_count(builder));

    // Define public inputs.  See doc comment above.
    instance.push(vk_hash);
    for p_i in assigned_proofs_and_inputs {
        instance.extend(p_i.1 .0);
    }
}

/// Batch verifies the application proofs.
/// Its public input set is the hash of the application vk
/// followed by the concatenated public inputs of each application
/// proof (see `batch_verify_circuit`).
pub struct BatchVerifyCircuit<F = Fr, C = G1Affine>
where
    F: EccPrimeField,
    C: CurveAffine<ScalarExt = F>,
{
    inner: RangeWithInstanceCircuitBuilder<F>,
    config: FlexGateConfigParams,
    _marker: PhantomData<C>,
}

impl<F, C> BatchVerifyCircuit<F, C>
where
    F: EccPrimeField + SerdeObject,
    C: CurveAffine<ScalarExt = F> + SerdeObject,
{
    /// Performs the steps that are common to each initialization type.
    /// Namely, creates the GateThreadBuilder in the appropriate mode and
    /// populates it using the application vk and proofs passed in.  Returns
    /// the populated GateThreadBuilder and the AssignedValues that hold the
    /// witness.
    fn create_builder_and_instance(
        stage: CircuitBuilderStage,
        bv_config: &BatchVerifyConfig,
        bv_inputs: &BatchVerifyInputs<F>,
    ) -> (GateThreadBuilder<F>, Vec<AssignedValue<F>>) {
        let mut builder = match stage {
            CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
            CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
            CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        };
        let range = RangeChip::<F>::default(bv_config.lookup_bits);
        let fp_chip =
            FpChip::<F>::new(&range, bv_config.limb_bits, bv_config.num_limbs);
        let mut instance = Vec::new();
        batch_verify_circuit(&mut builder, &fp_chip, bv_inputs, &mut instance);

        (builder, instance)
    }
}

// NOTE: Not generic over the field since we only have a `compute_circuit_id`
// implementation for bn256::Fr.
impl<'a> SafeCircuit<'a, Fr, G1Affine> for BatchVerifyCircuit<Fr, G1Affine> {
    type CircuitConfig = BatchVerifyConfig;
    type GateConfig = FlexGateConfigParams;
    type CircuitInputs = BatchVerifyInputs<Fr>;
    type KeygenInputs = ();
    type InstanceInputs = BatchVerifyInputs<Fr>;

    fn mock(
        config: &Self::CircuitConfig,
        inputs: &Self::CircuitInputs,
    ) -> Self {
        let (builder, instance) = Self::create_builder_and_instance(
            CircuitBuilderStage::Mock,
            config,
            inputs,
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

    fn keygen(config: &Self::CircuitConfig, _: &()) -> Self {
        // Create dummy data for an application circuit with the given number
        // of public inputs per app proof, and number of application circuits.

        // Fixed circuits do not support Pedersen commitments, so only
        // has_commitment = false makes sense here
        let vk = VerificationKey::default_with_length(
            config.num_app_public_inputs as usize,
            false,
        );

        let proofs_and_inputs = dummy_app_proofs_and_inputs(config);

        let (builder, instance) = Self::create_builder_and_instance(
            CircuitBuilderStage::Keygen,
            config,
            &BatchVerifyInputs {
                app_vk: vk,
                app_proofs_and_inputs: proofs_and_inputs,
            },
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
            inputs,
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
        let _ = config;
        let circuit_id =
            digest_to_field_element(&compute_circuit_id(&inputs.app_vk));
        let app_instances = inputs
            .app_proofs_and_inputs
            .iter()
            .map(|(_, i)| i.0.as_slice());

        // [ circuit_id,
        //   app_pi_0_0, app_pi_0_1, ...,
        //   app_pi_1_0, app_pi_1_1, ..
        // ]
        core::iter::once(circuit_id)
            .chain(app_instances.into_iter().flatten().copied())
            .collect()
    }

    fn gate_config(&self) -> &Self::GateConfig {
        &self.config
    }

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.inner.break_points()
    }

    fn read_proving_key<R>(
        config: &Self::CircuitConfig,
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
        std::env::set_var("LOOKUP_BITS", config.lookup_bits.to_string());

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

impl<F, C> Circuit<F> for BatchVerifyCircuit<F, C>
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

impl<F, C> CircuitExt<F> for BatchVerifyCircuit<F, C>
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
