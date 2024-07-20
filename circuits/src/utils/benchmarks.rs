//! Benchmarking utilities and constants

use crate::SafeCircuit;
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey},
        poly::kzg::commitment::ParamsKZG,
    },
};
use serde::Serialize;
use std::{
    fs::File,
    io::{BufWriter, Write},
};

pub const PROOF_BATCH_FILE: &str = "src/tests/data/proof_batch_4_pi.json";
pub const VK_FILE: &str = "src/tests/data/vk.json";
pub const CONTRACT_BYTE_LIMIT: usize = 24576;
pub const BV_CONFIG_FILE: &str = "../circuits/benches/configs/bv_configs.json";
pub const UBV_CONFIG_FILE: &str =
    "../circuits/benches/configs/ubv_configs.json";
pub const KECCAK_CONFIG_FILE: &str =
    "../circuits/benches/configs/keccak_configs.json";
pub const OUTER_CONFIG_FILE: &str =
    "../circuits/benches/configs/outer_configs.json";
pub const UNIVERSAL_OUTER_CONFIG_FILE: &str =
    "../circuits/benches/configs/universal_outer_configs.json";

/// Writes `val` to `file`
pub fn save_json<V: Serialize>(file: &str, val: &V) {
    let file = File::create(file).expect("Error creating a new file");
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, val)
        .unwrap_or_else(|e| panic!("failed writing: {e}"));
    writer
        .write_all(b"\n")
        .expect("Writing a new line is not allowed to fail");
    writer.flush().expect("Flushing is not allowed to fail")
}

/// Generates a proving key for `config`
pub fn keygen<'a, C>(
    config: &C::CircuitConfig,
    keygen_inputs: &'a C::KeygenInputs,
    srs: &ParamsKZG<Bn256>,
) -> (
    ProvingKey<G1Affine>,
    C::GateConfig,
    MultiPhaseThreadBreakPoints,
)
where
    C: SafeCircuit<'a, Fr, G1Affine> + Circuit<Fr>,
    C::GateConfig: Clone,
{
    let circuit = C::keygen(config, keygen_inputs);
    let vk = keygen_vk(srs, &circuit).expect("VK gen failure");
    let pk = keygen_pk(srs, vk, &circuit).expect("PK gen failure");
    (pk, circuit.gate_config().clone(), circuit.break_points())
}
