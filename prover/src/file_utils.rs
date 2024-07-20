use circuits::{
    batch_verify::universal::{
        native::json::JsonUniversalBatchVerifierInput,
        types::UniversalBatchVerifierInput,
    },
    utils::{field_elements_hex, file::load_json},
    EccPrimeField,
};
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, G1Affine},
        plonk::{ProvingKey, VerifyingKey},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
        SerdeFormat,
    },
};
use log::info;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snark_verifier::verifier::plonk::PlonkProtocol;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::Path,
};

#[derive(Debug, Serialize)]
struct InstanceSerializeHelper<'a, F: EccPrimeField<Repr = [u8; 32]>> {
    #[serde(with = "field_elements_hex")]
    pub(crate) instance: &'a [F],
}

#[derive(Debug, Deserialize)]
struct InstanceDeserializeHelper<F: EccPrimeField<Repr = [u8; 32]>> {
    #[serde(with = "field_elements_hex")]
    pub(crate) instance: Vec<F>,
}

/// Fail with a warning if the given path already exists.
pub fn panic_if_file_exists(path: &str) {
    if Path::new(path).exists() {
        panic!("Refusing to overwrite file {path}");
    }
}

pub fn open_file_for_read(path: &str) -> BufReader<File> {
    let f = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap_or_else(|e| panic!("failed to open for read {path}: {e}"));
    BufReader::new(f)
}

/// Create a new file. Panic if the file already exists.
pub fn create_file_no_overwrite(path: &str) -> File {
    return OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|e| panic!("failed to create file {path}: {e}"));
}

/// Create a new file. Panic if the file already exists.
pub fn create_file_buffer_no_overwrite(path: &str) -> BufWriter<File> {
    BufWriter::new(create_file_no_overwrite(path))
}

/// Return the break-points file, given the proving key file
pub fn break_points_file(pk_file: &str) -> String {
    format!("{pk_file}.bps")
}

/// Return the instance file accompanying a proof file
pub fn instance_file(
    instance_file: Option<String>,
    proof_file: &str,
) -> String {
    match instance_file {
        Some(instance_file) => instance_file,
        None => format!("{proof_file}.instance"),
    }
}

/// Return the calldata file accompanying an `OuterCircuit` proof file
pub fn calldata_file(
    calldata_file: Option<String>,
    proof_file: &str,
) -> String {
    match calldata_file {
        Some(calldata_file) => calldata_file,
        None => format!("{proof_file}.calldata"),
    }
}

/// Convenience wrapper that prints an error on failure.
pub fn save_pretty_json_file<T: Serialize>(path: &str, v: &T, desc: &str) {
    let buf = create_file_buffer_no_overwrite(path);
    serde_json::to_writer_pretty(buf, v)
        .unwrap_or_else(|e| panic!("failed writing {desc}: {e}"))
}

/// Convenience wrapper that prints an error on failure.
pub fn save_json_file<T: Serialize>(path: &str, v: &T, desc: &str) {
    let buf = create_file_buffer_no_overwrite(path);
    serde_json::to_writer(buf, v)
        .unwrap_or_else(|e| panic!("failed writing {desc}: {e}"))
}

pub fn save_gate_config<T: Serialize>(path: &str, v: &T) {
    info!("writing gate config: {path}");
    save_json_file(path, v, "gate config")
}

pub fn save_vk(path: &str, vk: &VerifyingKey<G1Affine>) {
    info!("writing VK: {path}");
    let mut buf = create_file_buffer_no_overwrite(path);
    vk.write(&mut buf, SerdeFormat::RawBytesUnchecked)
        .unwrap_or_else(|e| panic!("failed writing verification key: {e}"))
}

pub fn save_break_points(path: &str, bp: &MultiPhaseThreadBreakPoints) {
    info!("writing breakpoints: {path}");
    save_json_file(path, bp, "breakpoints");
}

pub fn save_protocol(path: &str, protocol: &PlonkProtocol<G1Affine>) {
    info!("writing protocol: {path}");
    let buf = create_file_buffer_no_overwrite(path);
    bincode::serialize_into(buf, protocol)
        .unwrap_or_else(|e| panic!("error writing protocol: {e}"))
}

pub fn save_pk(path: &str, pk: &ProvingKey<G1Affine>) {
    info!("writing PK: {path}");
    let mut buf = create_file_buffer_no_overwrite(path);
    pk.write(&mut buf, SerdeFormat::RawBytesUnchecked)
        .expect("failed writing proving key");
}

pub fn save_proof(path: &str, proof: &[u8]) {
    info!("writing proof: {path}");
    let mut f = create_file_no_overwrite(path);
    f.write_all(proof)
        .unwrap_or_else(|e| panic!("failed writing proof: {e}"));
}

/// Saves Yul code to file.
///
/// (This is NOT converting to EVM bytecode.)
pub fn save_yul(path: &str, yul_code: &str) {
    info!("writing yul code: {path}");
    let mut f = create_file_no_overwrite(path);
    f.write_all(yul_code.as_bytes())
        .unwrap_or_else(|e| panic!("failed writing yul code: {e}"));
}

pub fn save_instance<F: EccPrimeField<Repr = [u8; 32]>>(
    path: &str,
    instance: &[F],
) {
    info!("writing instance: {path}");
    save_json_file(path, &InstanceSerializeHelper { instance }, "instance");
}

pub fn save_calldata(path: &str, calldata: &[u8]) {
    info!("writing calldata: {path}");
    let mut f = create_file_no_overwrite(path);
    f.write_all(calldata)
        .unwrap_or_else(|e| panic!("failed writing calldata: {e}"));
}

pub fn load_gate_config<T: DeserializeOwned>(path: &str) -> T {
    info!("loading gate config {path} ...");
    load_json(path)
}

pub fn load_srs(path: &str) -> ParamsKZG<Bn256> {
    info!("loading SRS {path}");
    let mut buf = open_file_for_read(path);
    ParamsKZG::<Bn256>::read(&mut buf)
        .unwrap_or_else(|e| panic!("failed to read srs: {e}"))
}

pub fn load_break_points(path: &str) -> MultiPhaseThreadBreakPoints {
    info!("loading break points: {path}");
    load_json(path)
}

pub fn load_proof(path: &str) -> Vec<u8> {
    info!("loading proof: {path}");
    std::fs::read(path).unwrap_or_else(|e| panic!("error reading proof: {e}"))
}

pub fn load_instance<F: EccPrimeField<Repr = [u8; 32]>>(path: &str) -> Vec<F> {
    info!("loading instance: {path}");
    let helper: InstanceDeserializeHelper<F> = load_json(path);
    helper.instance
}

pub fn load_app_vk_proof_inputs<F: EccPrimeField<Repr = [u8; 32]>>(
    path: &str,
) -> UniversalBatchVerifierInput {
    info!("loading app vk, proof, inputs: {path}");
    let json: JsonUniversalBatchVerifierInput = load_json(path);
    (&json).into()
}

pub fn load_protocol(path: &str) -> PlonkProtocol<G1Affine> {
    let file = open_file_for_read(path);
    bincode::deserialize_from(file)
        .unwrap_or_else(|e| panic!("error reading plonk protocol: {e}"))
}

pub fn load_yul(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("error reading yul code: {e}"))
}

pub fn load_calldata(path: &str) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("error reading calldata: {e}"))
}
