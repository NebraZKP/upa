use crate::UpaConfig;
use serde::de::DeserializeOwned;
use std::{
    fs::{File, OpenOptions},
    io::BufReader,
};

pub fn open_file_for_read(path: &str) -> BufReader<File> {
    let f = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap_or_else(|e| panic!("failed to open for read {path}: {e}"));
    BufReader::new(f)
}

pub fn load_json<T: DeserializeOwned>(filename: &str) -> T {
    let val: T = serde_json::from_reader(
        File::open(filename).unwrap_or_else(|e| panic!("{filename}: {e:?}")),
    )
    .unwrap_or_else(|e| panic!("{filename} JSON: {e:?}"));
    val
}

pub fn ubv_identifier(config: &UpaConfig) -> String {
    format!(
        "ubv_pi_{}_deg_{}_inner_{}",
        config.max_num_app_public_inputs,
        config.bv_config.degree_bits,
        config.inner_batch_size
    )
}

pub fn ubv_file_root(config: &UpaConfig) -> String {
    format!("./benches/_keys/{}", ubv_identifier(config))
}

pub fn keccak_identifier(config: &UpaConfig) -> String {
    format!(
        "keccak_pi_{}_deg_{}_inner_{}_outer_{}",
        config.max_num_app_public_inputs,
        config.keccak_config.degree_bits,
        config.inner_batch_size,
        config.outer_batch_size
    )
}

pub fn keccak_file_root(config: &UpaConfig) -> String {
    format!("./benches/_keys/{}", keccak_identifier(config))
}

pub fn outer_identifier(config: &UpaConfig) -> String {
    format!(
        "outer_pi_{}_deg_{}_inner_{}_outer_{}_ubv_deg_{}_keccak_deg_{}",
        config.max_num_app_public_inputs,
        config.outer_config.degree_bits,
        config.inner_batch_size,
        config.outer_batch_size,
        config.bv_config.degree_bits,
        config.keccak_config.degree_bits
    )
}

pub fn outer_file_root(config: &UpaConfig) -> String {
    format!("./benches/_keys/{}", outer_identifier(config))
}
