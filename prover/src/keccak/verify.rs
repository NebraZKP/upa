use crate::{
    default_values::{KECCAK_GATE_CONFIG, KECCAK_SRS, KECCAK_VK},
    file_utils::{
        instance_file, load_gate_config, load_instance, load_proof, load_srs,
        open_file_for_read,
    },
};
use circuits::{
    keccak::{KeccakCircuit, KeccakGateConfig},
    SafeCircuit,
};
use clap::Parser;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::verify_proof,
    poly::{
        commitment::ParamsProver,
        kzg::{multiopen::VerifierSHPLONK, strategy::SingleStrategy},
    },
};
use log::info;
use snark_verifier::system::halo2::transcript::halo2::ChallengeScalar;
use snark_verifier_sdk::{
    halo2::{PoseidonTranscript, POSEIDON_SPEC},
    NativeLoader,
};
use std::time::Instant;

#[derive(Parser, Debug)]
pub struct VerifyParams {
    #[arg(short = 's', long, value_name = "srs-file", default_value = KECCAK_SRS)]
    srs: String,

    #[arg(short = 'v', long, value_name = "verification-key-file", default_value = KECCAK_VK)]
    /// verification key for the Keccak circuit.
    verification_key: String,

    #[arg(short = 'g', long, value_name = "gate-config-file", default_value = KECCAK_GATE_CONFIG)]
    /// Circuit specs file
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

    let gate_config: KeccakGateConfig = load_gate_config(&params.gate_config);

    if params.dry_run {
        info!("dry-run.  not attempting to load VK");
        return;
    }

    info!("loading vk ...");
    let vk = {
        let mut buf = open_file_for_read(&params.verification_key);
        KeccakCircuit::<_, G1Affine>::read_verifying_key(&gate_config, &mut buf)
            .unwrap_or_else(|e| panic!("error reading vk: {e}"))
    };

    let instance: Vec<Fr> = load_instance(&instance_file);
    let proof = load_proof(&params.proof);

    // TODO: Load only the verifier part of the SRS

    let srs = load_srs(&params.srs);

    info!("Verifying Keccak proof...");
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
    info!("Finished verifying keccak proof in {:?}", now.elapsed());

    println!("Verified");
}
