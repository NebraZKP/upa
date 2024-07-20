use crate::{
    default_values::{UBV_GATE_CONFIG, UBV_SRS, UBV_VK},
    file_utils::{
        instance_file, load_gate_config, load_instance, load_proof, load_srs,
        open_file_for_read,
    },
};
use circuits::{
    batch_verify::universal::UniversalBatchVerifyCircuit, SafeCircuit,
};
use clap::Parser;
use halo2_base::{
    gates::builder::FlexGateConfigParams,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        plonk::verify_proof,
        poly::{
            commitment::ParamsProver,
            kzg::{multiopen::VerifierSHPLONK, strategy::SingleStrategy},
        },
    },
};
use log::info;
use snark_verifier::system::halo2::transcript::halo2::ChallengeScalar;
use snark_verifier_sdk::{
    halo2::{PoseidonTranscript, POSEIDON_SPEC},
    NativeLoader,
};
use std::time::Instant;

#[derive(Debug, Parser)]
pub struct VerifyParams {
    #[arg(short = 's', long, value_name = "srs-file", default_value = UBV_SRS)]
    srs: String,

    #[arg(short = 'v', long, value_name = "verification-key-file", default_value = UBV_VK)]
    /// verification key for the UniversalBatchVerifier circuit.
    verification_key: String,

    #[arg(short = 'g', long, value_name = "gate-config-file", default_value = UBV_GATE_CONFIG)]
    /// Gate configuration file
    gate_config: String,

    #[arg(long, value_name = "proof-file")]
    /// Proof file for a batch
    proof: String,

    #[arg(long, value_name = "instance-file")]
    /// Instance file for a batch (defaults to <proof-file>.instance if not given)
    instance: Option<String>,

    #[arg(short = 'n', long)]
    /// Load the circuit configs and exit.
    dry_run: bool,
}

pub fn verify(params: VerifyParams) {
    let instance_file = instance_file(params.instance, &params.proof);

    let gate_config: FlexGateConfigParams =
        load_gate_config(&params.gate_config);

    if params.dry_run {
        info!("dry-run.  not attempting to load VK");
        return;
    }

    info!("loading vk ...");
    let vk = {
        let mut buf = open_file_for_read(&params.verification_key);
        UniversalBatchVerifyCircuit::read_verifying_key(&gate_config, &mut buf)
            .unwrap_or_else(|e| panic!("error reading vk: {e}"))
    };

    let instance: Vec<Fr> = load_instance(&instance_file);
    let proof = load_proof(&params.proof);
    // TODO: Load only the verifier part of the SRS
    let srs = load_srs(&params.srs);

    info!("Verifying UBV proof...");
    let now = Instant::now();
    {
        let mut transcript = PoseidonTranscript::<NativeLoader, _>::from_spec(
            &proof[..],
            POSEIDON_SPEC.clone(),
        );
        verify_proof::<_, VerifierSHPLONK<'_, Bn256>, ChallengeScalar<_>, _, _>(
            srs.verifier_params(),
            &vk,
            SingleStrategy::new(&srs),
            &[&[instance.as_slice()]],
            &mut transcript,
        )
        .unwrap_or_else(|e| panic!("proof verification failed: {e}"));
    };
    info!("Finished verifying UBV proof in {:?}", now.elapsed());

    println!("Verified");
}
