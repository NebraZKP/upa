extern crate alloc;

use crate::{
    outer::{
        OuterCircuit, OuterCircuitInputs, OuterCircuitWrapper, OuterGateConfig,
        OuterKeygenInputs,
    },
    SafeCircuit,
};
use alloc::rc::Rc;
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
        plonk::{
            keygen_pk, keygen_vk, Error as Halo2ProofsError, ProvingKey,
            VerifyingKey,
        },
        poly::{
            commitment::{ParamsProver, Prover, Verifier},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                msm::DualMSM,
                strategy::GuardKZG,
            },
        },
    },
};
use snark_verifier::{
    loader::evm::EvmLoader,
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::SnarkVerifier,
};
use snark_verifier_sdk::{
    evm::{gen_evm_proof, EvmKzgAccumulationScheme},
    halo2::aggregation::{AggregationCircuit, Halo2KzgAccumulationScheme},
    CircuitExt, PlonkVerifier,
};

/// Computes a proving key for `OuterCircuit` of type
/// specified by given `OuterConfig`, `BatchVerifyConfig`
/// using the supplied KZG parameters for outer, batch verify,
/// and keccak circuits.
///
/// Returns proving key, `FlexGateConfigParams`, and break points.
///
/// Use of `SHPLONK` or `GWC19` is specified
/// by the types `AS`, `P`, `V`.
///
/// Note: `AS`, `P`, `V` are not constrained to be
/// consistent with each other.
pub fn gen_outer_pk<'params, AS, O, P, V>(
    outer_config: &O::Config,
    inputs: &'params OuterKeygenInputs,
) -> Result<
    (
        ProvingKey<G1Affine>,
        OuterGateConfig,
        MultiPhaseThreadBreakPoints,
        usize,
    ),
    Halo2ProofsError,
>
// TODO: Why is + 'params required on all types here?
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a> + 'params,
    O: OuterCircuit + 'params,
    P: Prover<'params, KZGCommitmentScheme<Bn256>> + 'params,
    V: Verifier<
            'params,
            KZGCommitmentScheme<Bn256>,
            Guard = GuardKZG<'params, Bn256>,
            MSMAccumulator = DualMSM<'params, Bn256>,
        > + 'params,
{
    let circuit =
        OuterCircuitWrapper::<AS, O, P, V>::keygen(outer_config, inputs);
    let vk = keygen_vk(inputs.outer_params, &circuit)?;
    let pk = keygen_pk(inputs.outer_params, vk, &circuit)?;

    let instance_size: usize = circuit.num_instance()[0];
    assert!(instance_size == 14usize, "unexpected instance size");

    Ok((
        pk,
        circuit.gate_config().clone(),
        circuit.break_points(),
        instance_size,
    ))
}

/// Computes a verifying key for `OuterCircuit` of type
/// specified by given `OuterConfig`, `BatchVerifyConfig`
/// using the supplied KZG parameters for outer, batch verify,
/// and keccak circuits.
///
/// Returns verifying key, `FlexGateConfigParams`, and break points.
///
/// Use of `SHPLONK` or `GWC19` is specified
/// by the types `AS`, `P`, `V`.
///
/// Note: `AS`, `P`, `V` are not constrained to be
/// consistent with each other.
pub fn gen_outer_vk<'params, AS, O, P, V>(
    outer_config: &O::Config,
    inputs: &'params OuterKeygenInputs,
) -> Result<
    (
        VerifyingKey<G1Affine>,
        OuterGateConfig,
        MultiPhaseThreadBreakPoints,
        usize,
    ),
    Halo2ProofsError,
>
// TODO: Why is + 'params required on all types here?
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a> + 'params,
    O: OuterCircuit + 'params,
    P: Prover<'params, KZGCommitmentScheme<Bn256>> + 'params,
    V: Verifier<
            'params,
            KZGCommitmentScheme<Bn256>,
            Guard = GuardKZG<'params, Bn256>,
            MSMAccumulator = DualMSM<'params, Bn256>,
        > + 'params,
{
    let circuit =
        OuterCircuitWrapper::<AS, O, P, V>::keygen(outer_config, inputs);
    let vk = keygen_vk(inputs.outer_params, &circuit)?;

    let instance_size: usize = circuit.num_instance()[0];
    assert!(instance_size == 14usize, "unexpected instance size");

    Ok((
        vk,
        circuit.gate_config().clone(),
        circuit.break_points(),
        instance_size,
    ))
}

/// Returns Yul code for EVM verifier of `OuterCircuit` proofs as
/// a `String`.
///
/// `Shplonk` or `GWC` variant is specified by the type `AS`.
///
/// ## Usage:
///
/// This function expects `num_instances` to be the number of public inputs to
/// the circuit whose verifying key is `outer_vk`.
pub fn gen_outer_evm_verifier<AS>(
    params: &ParamsKZG<Bn256>,
    outer_vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> String
where
    AS: EvmKzgAccumulationScheme,
{
    // Compile verifying key into a `PlonkProtocol`.
    let protocol =
        compile(
            params,
            outer_vk,
            Config::kzg()
                .with_num_instance(num_instance.clone())
                .with_accumulator_indices(
                    AggregationCircuit::accumulator_indices(),
                ),
        );

    // Deciding key for pairing check
    let dk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    // Generate verification code within `loader`
    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::<AS>::read_proof(
        &dk,
        &protocol,
        &instances,
        &mut transcript,
    )
    .unwrap();
    PlonkVerifier::<AS>::verify(&dk, &protocol, &instances, &proof).unwrap();
    loader.yul_code()
}

/// Returns an `UniversalOuterCircuit` EVM proof and accompanying
/// instances. The proof's validity is checked internally
/// by `gen_evm_proof`. Use of `SHPLONK` or `GWC19` is specified
/// by the types `AS`, `P`, `V`.
///
/// Note: `AS`, `P`, `V` are not constrained to be
/// consistent with each other.
pub fn prove_outer<'params, AS, O, P, V>(
    outer_config: &O::Config,
    outer_gate_config: &OuterGateConfig,
    pk: &'params ProvingKey<G1Affine>,
    break_points: MultiPhaseThreadBreakPoints,
    outer_inputs: OuterCircuitInputs<O>,
    outer_srs: &'params ParamsKZG<Bn256>,
) -> (Vec<u8>, Vec<Fr>)
where
    // TODO: Why is + 'params needed on these types?
    AS: for<'a> Halo2KzgAccumulationScheme<'a> + 'params,
    O: OuterCircuit + 'params,
    P: Prover<'params, KZGCommitmentScheme<Bn256>> + 'params,
    V: Verifier<
            'params,
            KZGCommitmentScheme<Bn256>,
            Guard = GuardKZG<'params, Bn256>,
            MSMAccumulator = DualMSM<'params, Bn256>,
        > + 'params,
{
    let circuit = OuterCircuitWrapper::<AS, O, P, V>::prover(
        outer_config,
        outer_gate_config,
        break_points,
        &outer_inputs,
    );
    let instances = circuit.instances();
    (
        gen_evm_proof::<_, P, V>(outer_srs, pk, circuit, instances.clone()),
        instances[0].clone(),
    )
}
