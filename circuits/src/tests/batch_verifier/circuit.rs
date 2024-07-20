use crate::{
    batch_verify::{
        common::{
            native::json::{load_proof_and_inputs, load_vk},
            types::{Proof, PublicInputs},
        },
        fixed::{batch_verify_circuit, types::BatchVerifyInputs},
    },
    tests::*,
    CircuitWithLimbsConfig,
};
use halo2_base::{
    gates::{builder::GateThreadBuilder, RangeChip},
    halo2_proofs::halo2curves::bn256::Fr,
};
use halo2_ecc::bn254::FpChip;
use serde::Deserialize;

const PATH: &str = "src/tests/configs/circuit.config";

#[derive(Debug, Deserialize)]
struct TestConfig {}

fn run_batch_verify_circuit(
    builder: &mut GateThreadBuilder<Fr>,
    config: &CircuitWithLimbsConfig,
    _test_config: &TestConfig,
    instance: &mut Vec<AssignedValue<Fr>>,
) {
    // Read the vk
    let vk = load_vk(VK_FILE);

    // Read the proofs
    let proofs_and_inputs: Vec<(Proof, PublicInputs)> =
        [PROOF1_FILE, PROOF2_FILE, PROOF3_FILE]
            .iter()
            .map(|e| load_proof_and_inputs(e))
            .collect();

    // NOTE: Default is a greater batch size, but 3 should be sufficient to
    // check all code-paths.
    let range = RangeChip::<Fr>::default(config.lookup_bits);
    let fp_chip = FpChip::<Fr>::new(&range, config.limb_bits, config.num_limbs);
    let bv_inputs = BatchVerifyInputs {
        app_vk: vk,
        app_proofs_and_inputs: proofs_and_inputs,
    };
    batch_verify_circuit(builder, &fp_chip, &bv_inputs, instance);
}

#[test]
fn test_batch_verify_circuit_mock() {
    run_circuit_mock_test(PATH, run_batch_verify_circuit);
}

#[ignore = "takes too long"]
#[test]
fn test_batch_verify_circuit() {
    run_circuit_test(PATH, run_batch_verify_circuit);
}
