use super::super::sample_proofs_inputs_vk;
use crate::{
    batch_verify::fixed::{
        types::{BatchVerifyConfig, BatchVerifyInputs},
        BatchVerifyCircuit,
    },
    CircuitWithLimbsConfig, SafeCircuit,
};
use halo2_base::{
    halo2_proofs::{
        dev::MockProver, halo2curves::bn256::G1Affine, poly::commitment::Params,
    },
    utils::fs::gen_srs,
};
use snark_verifier_sdk::CircuitExt;

/// Mock prover test of `BatchVerifyCircuit`
#[test]
fn batch_verify_circuit() {
    let circuit_config = CircuitWithLimbsConfig::from_degree_bits(21);

    let params = gen_srs(circuit_config.degree_bits);

    // Sample some proofs, determine the number of public inputs and thereby
    // the full BatchVerifyConfig.  Batch size is set to 3 - expected to be
    // sufficient to test all code paths.
    let batch_size = 3;
    let (proofs_and_inputs, application_vk) =
        sample_proofs_inputs_vk(batch_size as usize);
    let num_app_public_inputs = proofs_and_inputs[0].1 .0.len() as u32;
    let bv_config = BatchVerifyConfig::from_circuit_config(
        &circuit_config,
        batch_size,
        num_app_public_inputs,
    );

    let bv_inputs = BatchVerifyInputs {
        app_vk: application_vk,
        app_proofs_and_inputs: proofs_and_inputs,
    };
    let batch_verify_circuit =
        BatchVerifyCircuit::<_, G1Affine>::mock(&bv_config, &bv_inputs);
    let config = batch_verify_circuit.gate_config();

    // Check correct public input values (excluding vk_hash):
    let expected_instance = BatchVerifyCircuit::<_, G1Affine>::compute_instance(
        &bv_config, &bv_inputs,
    );
    assert_eq!(
        batch_verify_circuit.instances()[0],
        expected_instance,
        "Public inputs of batch verify circuit should be vk_hash \
        followed by concatenation of public inputs to each application circuit."
    );

    print!(
        "Batch verify circuit for batch size {batch_size} config: {config:?}"
    );

    let _ = MockProver::run(params.k(), &batch_verify_circuit, vec![vec![]])
        .expect("Batch verify circuit not satisfied");
}
