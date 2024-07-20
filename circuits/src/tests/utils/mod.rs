use crate::{EccPrimeField, SafeCircuit};
use halo2_base::halo2_proofs::halo2curves::CurveAffine;
use snark_verifier_sdk::CircuitExt;

mod field_elements_hex;

pub fn check_instance<'a, F, C, Circuit>(
    circuit: &Circuit,
    config: &Circuit::CircuitConfig,
    inputs: &Circuit::InstanceInputs,
) -> bool
where
    F: EccPrimeField,
    C: CurveAffine<ScalarExt = F>,
    Circuit: SafeCircuit<'a, F, C> + CircuitExt<F>,
{
    let instances = circuit.instances();
    let expect_instance = Circuit::compute_instance(config, inputs);
    instances[0] == expect_instance
}
