//! Common functionality for Fixed/Universal Outer Circuits.
use crate::{
    keccak::{
        inputs::KeccakCircuitInputs, utils::gen_keccak_snark, KeccakCircuit,
        KeccakConfig,
    },
    utils::upa_config::UpaConfig,
    SafeCircuit,
};
use core::{iter, marker::PhantomData};
use halo2_base::{
    gates::builder::{
        CircuitBuilderStage, FlexGateConfigParams, MultiPhaseThreadBreakPoints,
    },
    halo2_proofs::{
        self,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{Circuit, ProvingKey, VerifyingKey},
        poly::{
            commitment::{ParamsProver, Prover, Verifier},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                msm::DualMSM,
                strategy::GuardKZG,
            },
        },
        SerdeFormat,
    },
    utils::fs::gen_srs,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    halo2::aggregation::{AggregationCircuit, Halo2KzgAccumulationScheme},
    CircuitExt, Snark,
};
use std::env::set_var;

pub type OuterConfig = UpaConfig;
pub type UniversalOuterConfig = UpaConfig;

pub mod universal;
pub mod utils;

/// The number of rows to be set aside for blinding
/// factors when computing `FlexGateConfigParams`.
pub(crate) const MINIMUM_ROWS: usize = 20;

/// Abstracts the `FixedOuterCircuit` and `UniversalOuterCircuit`. In the
/// universal case, `bv` and `BatchVerify` should be understood to mean
/// `ubv` and `UniversalBatchVerify`.
pub trait OuterCircuit {
    /// The configuration of this `OuterCircuit`, generally a [UpaConfig]
    type Config;

    /// The configuration of BV Circuits to be aggregated
    type BatchVerifyConfig;

    fn bv_config(config: &Self::Config) -> Self::BatchVerifyConfig;

    fn keccak_config(config: &Self::Config) -> KeccakConfig;

    fn gate_config(&self) -> &OuterGateConfig;

    fn degree_bits(config: &Self::Config) -> usize;

    fn lookup_bits(config: &Self::Config) -> usize {
        Self::degree_bits(config) - 1
    }

    fn outer_batch_size(config: &Self::Config) -> usize;

    /// Return a (potentially invalid) [Snark] for the corresponding
    /// BV circuit based on the given configuration.
    fn dummy_bv_snark(
        bv_params: &ParamsKZG<Bn256>,
        bv_config: &Self::BatchVerifyConfig,
    ) -> Snark;

    /// Return [KeccakCircuitInputs] corresponding to `bv_instances`.
    fn keccak_inputs_from_bv_instances<'a>(
        bv_config: &Self::BatchVerifyConfig,
        bv_instances: impl ExactSizeIterator<Item = &'a [Fr]>,
        num_proof_ids: Option<u64>,
    ) -> KeccakCircuitInputs<Fr>;

    /// Implementors are expected to have some inner [AggregationCircuit]
    fn inner(&self) -> &AggregationCircuit;

    /// By default, the [AggregationCircuit] will only expose its KZG accumulator
    /// as public inputs. This method adds the final digest to the Outer Circuit public
    /// inputs and copy-constrains all BV circuit inputs to the corresponding
    /// Keccak circuit inputs.
    fn expose_final_digest_and_constrain(
        inner: &mut AggregationCircuit,
        config: &Self::Config,
    );

    /// Implementors are expected to consist of an inner [AggregationCircuit]
    /// as well as an [OuterGateConfig].
    fn from_inner(
        inner: AggregationCircuit,
        gate_config: OuterGateConfig,
    ) -> Self;

    fn new<AS>(
        stage: CircuitBuilderStage,
        config: &Self::Config,
        inputs: OuterCircuitInputs<Self>,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        gate_config: Option<OuterGateConfig>,
    ) -> Self
    where
        AS: for<'a> Halo2KzgAccumulationScheme<'a>,
        Self: core::marker::Sized,
    {
        let snarks = {
            let mut snarks = inputs.bv_snarks;
            snarks.push(inputs.keccak_snark);
            snarks
        };
        // Note: This assumes BV/Keccak use an SRS that has
        // G1 generator (1, 2).
        let verifier_params = gen_srs(0);
        let mut inner = AggregationCircuit::new::<AS>(
            stage,
            break_points,
            Self::lookup_bits(config),
            &verifier_params,
            snarks,
        );
        Self::expose_final_digest_and_constrain(&mut inner, config);

        let gate_config = gate_config.unwrap_or_else(|| {
            // Compute/assign the `OuterGateConfig`
            let lookup_bits = Self::lookup_bits(config);
            set_var("LOOKUP_BITS", lookup_bits.to_string());
            let flex_gate_config_params = inner
                .config(Self::degree_bits(config) as u32, Some(MINIMUM_ROWS));
            OuterGateConfig {
                flex_gate_config_params,
                lookup_bits,
            }
        });
        Self::from_inner(inner, gate_config)
    }
}

/// Outer circuit gate configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OuterGateConfig {
    flex_gate_config_params: FlexGateConfigParams,
    lookup_bits: usize,
}

impl OuterGateConfig {
    pub fn flex_gate_config_params(&self) -> &FlexGateConfigParams {
        &self.flex_gate_config_params
    }

    pub fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    /// Sets the environment variables `FLEX_GATE_CONFIG_PARAMS`
    /// and `LOOKUP_BITS` to the values in `self`.
    pub fn set_environment(&self) {
        std::env::set_var(
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(self.flex_gate_config_params())
                .expect("FGCP to string failed"),
        );
        std::env::set_var("LOOKUP_BITS", self.lookup_bits().to_string());
    }
}

/// Here "Outer Instance" is understood to mean only the final
/// digest. See note on [SafeCircuit::compute_instance] in the
/// [SafeCircuit] impl. Although this could be extracted from
/// `keccak_instance` alone, in practice we wish to enforce consistency
/// of the `bv_instances` and `keccak_instance`. See constructor.
#[derive(Debug, Deserialize, Serialize)]
pub struct OuterInstanceInputs<O: OuterCircuit> {
    /// BatchVerifyCircuit instances
    bv_instances: Vec<Vec<Fr>>,
    /// `KeccakCircuit` instance
    keccak_instance: Vec<Fr>,
    __: PhantomData<O>,
}

impl<O: OuterCircuit> OuterInstanceInputs<O> {
    /// Constructor that enforces consistency of
    /// `keccak_instance` and `bv_instances`.
    pub fn new(
        config: &O::Config,
        bv_instances: Vec<Vec<Fr>>,
        keccak_instance: Vec<Fr>,
    ) -> Self {
        let bv_config = O::bv_config(config);
        let keccak_config = O::keccak_config(config);

        let create_keccak_instance = |i: Option<u64>| {
            let expected_circuit_inputs = O::keccak_inputs_from_bv_instances(
                &bv_config,
                bv_instances.iter().map(|i| i.as_slice()),
                i,
            );
            <KeccakCircuit<Fr, G1Affine> as SafeCircuit<_, _>>::compute_instance(
                &keccak_config,
                &expected_circuit_inputs,
            )
        };

        // We can't compute the submissionId from the bv instances, but we can
        // precompute all possible sids and check the one in `keccak_instance`
        // is one of them
        if keccak_config.output_submission_id {
            let total_batch_size =
                keccak_config.inner_batch_size * keccak_config.outer_batch_size;
            let expected_instances = (1..=total_batch_size)
                .into_iter()
                .map(|i| create_keccak_instance(Some(i as u64)))
                .collect_vec();
            assert!(
                expected_instances.contains(&keccak_instance),
                "Unexpected keccak instance"
            );
        } else {
            let expected_instance = create_keccak_instance(None);
            assert_eq!(
                expected_instance, keccak_instance,
                "Unexpected keccak instance"
            );
        }

        Self {
            bv_instances,
            keccak_instance,
            __: PhantomData,
        }
    }
}

/// The data required to create an outer circuit witness. Consistency
/// of these inputs is enforced by the constructor.
///
/// Note: These are NOT the outer circuit's public inputs; these are
/// the data needed to construct a witness.
#[derive(Debug, Deserialize, Serialize)]
pub struct OuterCircuitInputs<O>
where
    O: OuterCircuit,
{
    /// Batch Verifier Snarks
    bv_snarks: Vec<Snark>,
    /// `KeccakCircuit` Snark
    keccak_snark: Snark,
    /// Outer Circuit type marker that implements
    /// `Send` and `Sync`
    __: PhantomData<fn() -> O>,
}

impl<O> Clone for OuterCircuitInputs<O>
where
    O: OuterCircuit,
{
    #[inline]
    fn clone(&self) -> Self {
        OuterCircuitInputs {
            bv_snarks: self.bv_snarks.clone(),
            keccak_snark: self.keccak_snark.clone(),
            __: self.__,
        }
    }
}

impl<O> OuterCircuitInputs<O>
where
    O: OuterCircuit,
{
    /// Constructor that enforces consistency of public inputs to
    /// `keccak_snark` and `bv_snarks`.
    pub fn new(
        outer_config: &O::Config,
        bv_snarks: Vec<Snark>,
        keccak_snark: Snark,
    ) -> Self {
        // Consistency check
        let _inputs = OuterInstanceInputs::<O>::new(
            outer_config,
            bv_snarks.iter().map(|s| s.instances[0].clone()).collect(),
            keccak_snark.instances[0].clone(),
        );
        Self {
            bv_snarks,
            keccak_snark,
            __: PhantomData,
        }
    }

    /// Returns default data appropriate for Outer Circuit keygen
    /// with specified Outer Circuit config.
    pub fn keygen_default<'p, P, V>(
        outer_config: &O::Config,
        bv_params: &'p ParamsKZG<Bn256>,
        keccak_params: &'p ParamsKZG<Bn256>,
    ) -> Self
    where
        P: Prover<'p, KZGCommitmentScheme<Bn256>>,
        V: Verifier<
            'p,
            KZGCommitmentScheme<Bn256>,
            Guard = GuardKZG<'p, Bn256>,
            MSMAccumulator = DualMSM<'p, Bn256>,
        >,
    {
        let bv_config = O::bv_config(outer_config);
        let keccak_config = O::keccak_config(outer_config);
        let bv_snarks: Vec<Snark> =
            iter::repeat(O::dummy_bv_snark(bv_params, &bv_config))
                .take(O::outer_batch_size(outer_config))
                .collect();
        let total_batch_size =
            keccak_config.inner_batch_size * keccak_config.outer_batch_size;
        let num_proof_ids = keccak_config
            .output_submission_id
            .then_some(total_batch_size as u64);
        let keccak_inputs = O::keccak_inputs_from_bv_instances(
            &bv_config,
            bv_snarks.iter().map(|snark| snark.instances[0].as_slice()),
            num_proof_ids,
        );
        let keccak_config = O::keccak_config(outer_config);
        let keccak_snark = gen_keccak_snark::<P, V>(
            keccak_params,
            &keccak_config,
            &keccak_inputs,
        );

        Self::new(outer_config, bv_snarks, keccak_snark)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OuterKeygenInputs<'p> {
    bv_params: &'p ParamsKZG<Bn256>,
    keccak_params: &'p ParamsKZG<Bn256>,
    pub outer_params: &'p ParamsKZG<Bn256>,
}

impl<'p> OuterKeygenInputs<'p> {
    /// Constructor enforces the requirement for BV and Keccak SRSs to
    /// use `(1, 2)` as the G1 generator.
    pub fn new(
        bv_params: &'p ParamsKZG<Bn256>,
        keccak_params: &'p ParamsKZG<Bn256>,
        outer_params: &'p ParamsKZG<Bn256>,
    ) -> Self {
        assert_eq!(
            bv_params.get_g()[0],
            G1Affine::generator(),
            "BV SRS has unexpected G1 generator."
        );
        assert_eq!(
            bv_params.get_g()[0],
            keccak_params.get_g()[0],
            "Inconsistent BV/Keccak SRS"
        );
        OuterKeygenInputs {
            bv_params,
            keccak_params,
            outer_params,
        }
    }

    /// Return reference to `bv_params`
    pub fn bv_params(&self) -> &'p ParamsKZG<Bn256> {
        self.bv_params
    }

    /// Return reference to `keccak_params`
    pub fn keccak_params(&self) -> &'p ParamsKZG<Bn256> {
        self.keccak_params
    }
}

/// This wrapper allows us to implement `Circuit` and `SafeCircuit` generically.
/// We cannot `impl<O: OuterCircuit> Circuit for O` because we do not own the
/// `trait Circuit` and the compiler cannot be sure that we own the type `O`.
/// The wrapper gets around this because we *do* own `OuterCircuitWrapper<O>`,
/// even if `O` comes from another crate.
///
/// Use of `SHPLONK` or `GWC19` is specified
/// by the types `AS`, `P`, `V`.
///
/// Note: `AS`, `P`, `V` are not constrained to be
/// consistent with each other.
pub struct OuterCircuitWrapper<'p, AS, O, P, V>
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    O: OuterCircuit,
    P: Prover<'p, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'p,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'p, Bn256>,
        MSMAccumulator = DualMSM<'p, Bn256>,
    >,
{
    inner: O,
    __: PhantomData<&'p (AS, P, V)>,
}

impl<'p, AS, O, P, V> OuterCircuitWrapper<'p, AS, O, P, V>
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    O: OuterCircuit,
    P: Prover<'p, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'p,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'p, Bn256>,
        MSMAccumulator = DualMSM<'p, Bn256>,
    >,
{
    pub fn new(inner: O) -> Self {
        Self {
            inner,
            __: PhantomData,
        }
    }
}

impl<'p, AS, O, P, V> Circuit<Fr> for OuterCircuitWrapper<'p, AS, O, P, V>
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    O: OuterCircuit,
    P: Prover<'p, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'p,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'p, Bn256>,
        MSMAccumulator = DualMSM<'p, Bn256>,
    >,
{
    type Config = <AggregationCircuit as Circuit<Fr>>::Config;

    type FloorPlanner = <AggregationCircuit as Circuit<Fr>>::FloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(
        meta: &mut halo2_proofs::plonk::ConstraintSystem<Fr>,
    ) -> Self::Config {
        <AggregationCircuit as Circuit<Fr>>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        self.inner.inner().synthesize(config, layouter)
    }
}

impl<'p, AS, O, P, V> CircuitExt<Fr> for OuterCircuitWrapper<'p, AS, O, P, V>
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    O: OuterCircuit,
    P: Prover<'p, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'p,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'p, Bn256>,
        MSMAccumulator = DualMSM<'p, Bn256>,
    >,
{
    fn num_instance(&self) -> Vec<usize> {
        <AggregationCircuit as CircuitExt<_>>::num_instance(self.inner.inner())
    }

    /// Return public inputs to Outer Circuit.
    ///
    /// This consists of the KZG accumulator formed from the BV/Keccak Snarks,
    /// followed by the Keccak digest of all application proof IDs.
    ///
    /// The KZG accumulator consists of 2 `G1` points, encoded as `4 *
    /// NUM_LIMBS` `Fr` elements. The Keccak digest is encoded as 2 `Fr`
    /// elements (each holding 128 bits or 16 bytes). The length of the entire
    /// instance is therefore `4 * NUM_LIMBS + 2 = 14`.
    fn instances(&self) -> Vec<Vec<Fr>> {
        <AggregationCircuit as CircuitExt<_>>::instances(self.inner.inner())
    }
}

impl<'p, AS, O, P, V> SafeCircuit<'p, Fr, G1Affine>
    for OuterCircuitWrapper<'p, AS, O, P, V>
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    O: OuterCircuit + 'p,
    P: Prover<'p, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'p,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'p, Bn256>,
        MSMAccumulator = DualMSM<'p, Bn256>,
    >,
{
    type CircuitConfig = O::Config;

    type GateConfig = OuterGateConfig;

    type CircuitInputs = OuterCircuitInputs<O>;

    type KeygenInputs = OuterKeygenInputs<'p>;

    type InstanceInputs = OuterInstanceInputs<O>;

    fn mock(
        config: &Self::CircuitConfig,
        inputs: &Self::CircuitInputs,
    ) -> Self {
        Self::new(O::new::<AS>(
            CircuitBuilderStage::Mock,
            config,
            inputs.clone(),
            None,
            None,
        ))
    }

    fn keygen(
        config: &Self::CircuitConfig,
        inputs: &Self::KeygenInputs,
    ) -> Self {
        let keygen_default_inputs =
            OuterCircuitInputs::<O>::keygen_default::<P, V>(
                config,
                inputs.bv_params(),
                inputs.keccak_params(),
            );
        Self::new(O::new::<AS>(
            CircuitBuilderStage::Keygen,
            config,
            keygen_default_inputs,
            None,
            None,
        ))
    }

    fn prover(
        config: &Self::CircuitConfig,
        gate_config: &Self::GateConfig,
        break_points: MultiPhaseThreadBreakPoints,
        inputs: &Self::CircuitInputs,
    ) -> Self {
        flex_gate_params_env_check(&gate_config.flex_gate_config_params);
        lookup_bits_env_check(O::lookup_bits(config));

        Self::new(O::new::<AS>(
            CircuitBuilderStage::Prover,
            config,
            inputs.clone(),
            Some(break_points),
            Some(gate_config.clone()),
        ))
    }

    /// NOTE: the full "instance" here could arguably include group points of
    /// the KZG accumulator, which is a side-effect of the way in which this
    /// circuit is verified (with a deferred pairing).  Since these are
    /// non-trivial to compute (effectively requiring a full prove step), we
    /// consider the "instance" here to refer to just the public inputs related
    /// to core outer circuit logic - namely the final digest.
    fn compute_instance(
        _: &Self::CircuitConfig,
        inputs: &Self::InstanceInputs,
    ) -> Vec<Fr> {
        // Note, the construction of `inputs` requires that that all inputs are
        // consistent, including the final digest.  Hence we can just read that
        // out.
        let keccak_instance = &inputs.keccak_instance;
        let keccak_instance_size = keccak_instance.len();

        keccak_instance[keccak_instance_size - 2..].to_vec()
    }

    fn gate_config(&self) -> &Self::GateConfig {
        O::gate_config(&self.inner)
    }

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.inner.inner().break_points()
    }

    fn read_proving_key<R>(
        _: &Self::CircuitConfig,
        gate_config: &Self::GateConfig,
        reader: &mut R,
    ) -> Result<ProvingKey<G1Affine>, std::io::Error>
    where
        R: std::io::Read,
    {
        gate_config.set_environment();
        ProvingKey::<G1Affine>::read::<_, Self>(
            reader,
            SerdeFormat::RawBytesUnchecked,
        )
    }

    fn read_verifying_key<R>(
        gate_config: &Self::GateConfig,
        reader: &mut R,
    ) -> Result<VerifyingKey<G1Affine>, std::io::Error>
    where
        R: std::io::Read,
    {
        gate_config.set_environment();
        VerifyingKey::<G1Affine>::read::<_, Self>(
            reader,
            SerdeFormat::RawBytesUnchecked,
        )
    }
}

/// Asserts that the environment variable `FLEX_GATE_CONFIG_PARAMS` is
/// equal to (the serialization of) `params`.
pub fn flex_gate_params_env_check(params: &FlexGateConfigParams) {
    let config_json_env = std::env::var("FLEX_GATE_CONFIG_PARAMS")
        .expect("FLEX_GATE_CONFIG_PARAMS not set calling prover");

    // Cannot compare as objects, so serialize flex_gate_config_params
    // and compare the strings.

    let config_json_expected = serde_json::to_string(&params)
        .expect("failed to serialize FlexGateConfigParams");
    assert_eq!(
        config_json_env, config_json_expected,
        "flex_gate_config_params mismatch.\n\
    env var: {config_json_env}\n\
    params:{config_json_expected}"
    );
}

/// Asserts that the environment variable `LOOKUP_BITS` is
/// equal to (the serialization of) `lookup_bits`.
pub fn lookup_bits_env_check(lookup_bits: usize) {
    let lookup_bits_str = std::env::var("LOOKUP_BITS")
        .expect("LOOKUP_BITS not set calling prover");

    assert_eq!(
        lookup_bits_str,
        lookup_bits.to_string(),
        "lookup_bits mismatch.  env var: {lookup_bits_str}, config:{lookup_bits}",
    );
}
