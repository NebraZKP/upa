use crate::{
    default_values::{OUTER_PROOF, OUTER_VERIFIER_YUL},
    file_utils::{
        calldata_file, instance_file, load_calldata, load_instance, load_proof,
        load_yul,
    },
};
use clap::Parser;
use ethereum_types::Address;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use log::info;
use snark_verifier::loader::evm::{compile_yul, ExecutorBuilder};
use snark_verifier_sdk::evm::encode_calldata;
use std::{
    process::{Command, Stdio},
    time::Instant,
};

#[derive(Debug, Parser)]
pub struct VerifyParams {
    /// Outer circuit verifier Yul code file
    #[arg(short = 'y', long, value_name = "outer-verifier-yul-file", default_value = OUTER_VERIFIER_YUL)]
    pub(crate) verifier_yul: String,

    /// Outer circuit proof file
    #[arg(short = 'p', long, value_name = "outer-proof-file", default_value = OUTER_PROOF)]
    pub(crate) proof: String,

    /// Outer circuit public inputs file
    #[arg(short = 'i', long, value_name = "outer-instance-file")]
    pub(crate) instance: Option<String>,

    /// Outer circuit calldata file
    #[arg(short = 'c', long, value_name = "outer-calldata-file")]
    pub(crate) calldata: Option<String>,

    #[arg(short = 'n', long)]
    /// Load the circuit configs and exit.
    pub(crate) dry_run: bool,
}

/// The system solc version must be 0.8.17. Snark-verifier uses it to compile
/// the Yul code, then runs the result on the "paris" EVM.
pub fn check_solc_version() -> bool {
    let output = Command::new("solc")
        .arg("--version")
        .stdout(Stdio::piped())
        .output()
        .expect("Failed to check solc version.");

    if output.status.success() {
        let version_output = String::from_utf8_lossy(&output.stdout);
        let version_lines: Vec<&str> = version_output.split('\n').collect();
        for line in version_lines {
            if line.starts_with("Version: ") {
                let version = line.trim().to_string();
                if version.contains("0.8.17") {
                    return true;
                } else {
                    log::error!("Error: Found incompatible Solc version: {}. The required version is 0.8.17. Try `svm use 0.8.17`.", version);
                    return false;
                }
            }
        }
    } else {
        log::error!("solc command failed");
    }
    false
}

/// Verify an Outer circuit proof in a simulated EVM.
pub fn verify(params: VerifyParams) {
    if params.dry_run {
        info!("dry-run. Not attempting to load VK");
        return;
    }

    assert!(check_solc_version());

    let calldata = {
        let proof = load_proof(&params.proof);
        let instance_file = instance_file(params.instance, &params.proof);
        let instance: Vec<Fr> = load_instance(&instance_file);
        encode_calldata(&[instance], &proof)
    };

    // Check that the calldata on file matches the proof/PIs
    if params.calldata.is_some() {
        let calldata_file = calldata_file(params.calldata, &params.proof);
        let loaded_calldata = load_calldata(&calldata_file);
        assert_eq!(
            calldata, loaded_calldata,
            "Calldata file inconsistent with proof and PIs"
        );
    }

    let yul_code = load_yul(&params.verifier_yul);
    let byte_code = compile_yul(&yul_code);
    info!("Verifier contract size: {} bytes", byte_code.len());

    info!("Verifying Outer Proof...");
    let now = Instant::now();
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm
            .deploy(caller, byte_code.into(), 0.into())
            .address
            .expect("deploy failed: {e}");

        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

        dbg!("Verifier contract used {} gas", result.gas_used);

        !result.reverted
    };
    info!("Finished verifying outer proof in {:?}", now.elapsed());

    if success {
        println!("Proof is valid.")
    } else {
        println!("Proof is invalid.")
    }
}
