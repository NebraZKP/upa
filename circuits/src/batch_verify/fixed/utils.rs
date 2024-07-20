//! `BatchVerifyCircuit`-related utility functions.
use crate::{
    batch_verify::{
        common::types::{Proof, PublicInputs, VerificationKey},
        fixed::{BatchVerifyCircuit, BatchVerifyConfig, BatchVerifyInputs},
    },
    CircuitWithLimbsConfig, EccPrimeField, SafeCircuit,
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
use rand_core::OsRng;
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

/// Produce a SNARK of the `BatchVerifyCircuit`.
/// Use of `Shplonk` or `GWC` is specified by the types `P, V`.
pub fn gen_batch_verify_snark<'params, P, V>(
    circuit_config: &CircuitWithLimbsConfig,
    params: &'params ParamsKZG<Bn256>,
    bv_inputs: &BatchVerifyInputs<Fr>,
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
    let bv_config = BatchVerifyConfig::from_circuit_config(
        circuit_config,
        bv_inputs.app_proofs_and_inputs.len() as u32,
        bv_inputs.app_proofs_and_inputs[0].1 .0.len() as u32,
    );
    let circuit = BatchVerifyCircuit::<_, G1Affine>::keygen(&bv_config, &());

    let pk = gen_pk(params, &circuit, None);
    let break_points = circuit.inner.break_points();
    let flex_gate_config_params = circuit.gate_config();

    let circuit = BatchVerifyCircuit::<_, G1Affine>::prover(
        &bv_config,
        flex_gate_config_params,
        break_points,
        bv_inputs,
    );

    gen_snark::<_, P, V>(params, &pk, circuit, None::<&str>)
}

/// Returns a "dummy" snark for a `BatchVerify` circuit formed
/// from default data of the right type. The proof it contains
/// is not valid. This is intended to be a helper in `OuterCircuit`
/// key generation.
///
/// Use of `Shplonk` or `GWC19` is specified by the generic `P`.
pub(crate) fn dummy_batch_verify_snark<'params, P>(
    params: &'params ParamsKZG<Bn256>,
    bv_config: &BatchVerifyConfig,
) -> Snark
where
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
{
    // Fixed circuits do not support Pedersen commitments, so only
    // has_commitment = false makes sense here
    let application_vk = VerificationKey::default_with_length(
        bv_config.num_app_public_inputs as usize,
        false,
    );
    let proofs_and_inputs = dummy_app_proofs_and_inputs::<Fr>(bv_config);

    let circuit = BatchVerifyCircuit::<Fr, G1Affine>::keygen(bv_config, &());

    let pk = gen_pk(params, &circuit, None);
    let break_points = circuit.break_points();
    let flex_gate_config_params = circuit.gate_config();

    let circuit = BatchVerifyCircuit::<Fr, G1Affine>::prover(
        bv_config,
        flex_gate_config_params,
        break_points,
        &BatchVerifyInputs {
            app_vk: application_vk,
            app_proofs_and_inputs: proofs_and_inputs,
        },
    );
    // Can't use `gen_snark` because it checks proof's validity
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg()
            .with_num_instance(circuit.num_instance())
            .with_accumulator_indices(
                BatchVerifyCircuit::<Fr, G1Affine>::accumulator_indices(),
            ),
    );

    let instances = circuit.instances();
    // Can't use `gen_proof` because it checks proof's validity
    let proof = {
        let now = Instant::now();
        info!("Compute BV dummy proof");
        let instances = instances.iter().map(Vec::as_slice).collect_vec();
        let mut transcript =
            PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(
                vec![],
                POSEIDON_SPEC.clone(),
            );
        let rng = OsRng;
        create_proof::<_, P, _, _, _, _>(
            params,
            &pk,
            &[circuit],
            &[&instances],
            rng,
            &mut transcript,
        )
        .unwrap();
        info!("Computed BV dummy proof in {:?}", now.elapsed());
        transcript.finalize()
    };
    Snark::new(protocol, instances, proof)
}

/// Returns proof and public inputs of the right size
/// for this `BatchVerifyConfig`. They are for keygen only
/// and do not form a valid proof.
pub(crate) fn dummy_app_proofs_and_inputs<F: EccPrimeField>(
    bv_config: &BatchVerifyConfig,
) -> Vec<(Proof, PublicInputs<F>)> {
    // Fixed circuits do not support Pedersen commitments, so only
    // has_commitment = false makes sense here
    let has_commitment = false;
    let dummy_pf = Proof::default_with_commitment(has_commitment);
    let dummy_pi = PublicInputs::default_with_length(
        bv_config.num_app_public_inputs as usize,
    );

    core::iter::repeat((dummy_pf, dummy_pi))
        .take(bv_config.inner_batch_size as usize)
        .collect()
}
