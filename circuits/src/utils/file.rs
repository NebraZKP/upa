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
