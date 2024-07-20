use crate::{
    batch_verify::universal::{
        types::{UniversalBatchVerifierConfig, UniversalBatchVerifierInputs},
        UniversalBatchVerifyCircuit,
    },
    EccPrimeField, SafeCircuit,
};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::create_proof,
    poly::{
        commitment::{Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            msm::DualMSM,
            strategy::GuardKZG,
        },
    },
};
use itertools::Itertools;
use log::info;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use snark_verifier::{
    loader::native::NativeLoader,
    system::halo2::{compile, Config},
};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{gen_snark, PoseidonTranscript, POSEIDON_SPEC},
    CircuitExt, Snark,
};
use std::time::Instant;

/// Returns a "dummy" snark for a `UniversalBatchVerify` circuit formed
/// from default data of the right type. The proof it contains
/// is not valid. This is intended to be a helper in `OuterCircuit`
/// key generation.
///
/// Use of `Shplonk` or `GWC19` is specified by the generic `P`.
pub(crate) fn dummy_ubv_snark<'params, P>(
    params: &'params ParamsKZG<Bn256>,
    ubv_config: &UniversalBatchVerifierConfig,
) -> Snark
where
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
{
    let circuit =
        UniversalBatchVerifyCircuit::<Fr, G1Affine>::keygen(ubv_config, &());

    let pk = gen_pk(params, &circuit, None);
    let break_points = circuit.break_points();
    let flex_gate_config_params = circuit.gate_config();

    let circuit = UniversalBatchVerifyCircuit::<Fr, G1Affine>::prover(
        ubv_config,
        flex_gate_config_params,
        break_points,
        &UniversalBatchVerifierInputs::dummy(ubv_config),
    );
    // Can't use `gen_snark` because it checks proof's validity
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg()
            .with_num_instance(circuit.num_instance())
            .with_accumulator_indices(UniversalBatchVerifyCircuit::<
                Fr,
                G1Affine,
            >::accumulator_indices()),
    );

    let instances = circuit.instances();
    // Can't use `gen_proof` because it checks proof's validity
    let proof = {
        let now = Instant::now();
        info!("Compute UBV dummy proof");
        let instances = instances.iter().map(Vec::as_slice).collect_vec();
        let mut transcript =
            PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(
                vec![],
                POSEIDON_SPEC.clone(),
            );
        let rng = StdRng::from_seed(Default::default());
        create_proof::<_, P, _, _, _, _>(
            params,
            &pk,
            &[circuit],
            &[&instances],
            rng,
            &mut transcript,
        )
        .unwrap();
        info!("Computed UBV dummy proof in {:?}", now.elapsed());
        transcript.finalize()
    };
    Snark::new(protocol, instances, proof)
}

/// Produce a SNARK of the `UniversalBatchVerifyCircuit`.
/// Use of `Shplonk` or `GWC` is specified by the types `P, V`.
pub fn gen_ubv_snark<'params, P, V>(
    ubv_config: &UniversalBatchVerifierConfig,
    params: &'params ParamsKZG<Bn256>,
    ubv_inputs: &UniversalBatchVerifierInputs<Fr>,
) -> Snark
where
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    let circuit =
        UniversalBatchVerifyCircuit::<_, G1Affine>::keygen(ubv_config, &());

    let pk = gen_pk(params, &circuit, None);
    let break_points = circuit.inner.break_points();
    let flex_gate_config_params = circuit.gate_config();

    let circuit = UniversalBatchVerifyCircuit::<_, G1Affine>::prover(
        ubv_config,
        flex_gate_config_params,
        break_points,
        ubv_inputs,
    );

    gen_snark::<_, P, V>(params, &pk, circuit, None::<&str>)
}
