use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, ProvingKey},
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
        transcript::TranscriptWriterBuffer,
    },
    utils::fs::gen_srs,
};
use log::info;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use snark_verifier::{
    loader::evm::{compile_yul, encode_calldata, Address, ExecutorBuilder},
    system::halo2::transcript::evm::EvmTranscript,
};
use snark_verifier_sdk::{CircuitExt, Snark, SHPLONK};
use std::time::Instant;
use upa_circuits::{
    batch_verify::{
        common::native::json::{load_proof_and_inputs_batch, load_vk},
        fixed::{types::BatchVerifyInputs, utils::gen_batch_verify_snark},
    },
    keccak::{
        utils::{gen_keccak_snark, keccak_inputs_from_bv_instances},
        KeccakConfig, KECCAK_LOOKUP_BITS,
    },
    outer::{
        fixed::FixedOuterCircuit,
        utils::{gen_outer_evm_verifier, gen_outer_pk},
        OuterCircuitInputs, OuterCircuitWrapper, OuterConfig, OuterGateConfig,
        OuterKeygenInputs,
    },
    utils::{
        benchmarks::{
            CONTRACT_BYTE_LIMIT, OUTER_CONFIG_FILE, PROOF_BATCH_FILE, VK_FILE,
        },
        file::load_json,
        upa_config::UpaConfig,
    },
    SafeCircuit,
};

/// Type alias for the outer circuit with SHPLONK as an accumulation
/// scheme
type OuterCircuit<'a> = OuterCircuitWrapper<
    'a,
    SHPLONK,
    FixedOuterCircuit,
    ProverSHPLONK<'a, Bn256>,
    VerifierSHPLONK<'a, Bn256>,
>;

/// Computes a [`KeccakConfig`] compatible with `outer_config` with `keccak_degree`.
fn keccak_config_from_outer_config(
    outer_config: &OuterConfig,
    keccak_degree: u32,
) -> KeccakConfig {
    KeccakConfig {
        degree_bits: keccak_degree,
        num_app_public_inputs: outer_config.max_num_app_public_inputs,
        inner_batch_size: outer_config.inner_batch_size,
        outer_batch_size: outer_config.outer_batch_size,
        lookup_bits: KECCAK_LOOKUP_BITS,
    }
}

/// Common setup for outer circuit mock/prover/evm tests. Returns `OuterCircuitInputs`.
fn outer_input_setup(
    keccak_config: &KeccakConfig,
    outer_config: &OuterConfig,
    keygen_inputs: &OuterKeygenInputs,
) -> OuterCircuitInputs<FixedOuterCircuit> {
    let bv_inputs = {
        // Sample proof file has 80 samples, PI length 4
        let mut app_proofs_and_inputs =
            load_proof_and_inputs_batch(PROOF_BATCH_FILE);
        app_proofs_and_inputs.truncate(outer_config.inner_batch_size as usize);
        BatchVerifyInputs {
            app_vk: load_vk(VK_FILE),
            app_proofs_and_inputs,
        }
    };

    // Generate BV snarks
    let bv_snarks: Vec<Snark> = {
        // To speed up benchmark we just repeat the same BV snark
        info!("Generating dummy BV snark for outer keygen");
        let bv_snark = gen_batch_verify_snark::<
            ProverSHPLONK<Bn256>,
            VerifierSHPLONK<Bn256>,
        >(
            &outer_config.bv_config,
            keygen_inputs.bv_params(),
            &bv_inputs,
        );
        vec![bv_snark; outer_config.outer_batch_size as usize]
    };
    // Get the corresponding keccak snark
    let keccak_snark = {
        info!("Generating keccak snark for outer keygen");
        let inputs = keccak_inputs_from_bv_instances(
            bv_snarks.iter().map(|s| s.instances[0].as_slice()),
            outer_config.max_num_app_public_inputs as usize,
            outer_config.inner_batch_size as usize,
        );
        gen_keccak_snark::<ProverSHPLONK<Bn256>, VerifierSHPLONK<Bn256>>(
            keygen_inputs.keccak_params(),
            keccak_config,
            &inputs.into(),
        )
    };

    OuterCircuitInputs::new(outer_config, bv_snarks, keccak_snark)
}

/// Generates a proving key for `outer_config`, together with consistent [`OuterCircuitInputs`].
fn outer_circuit_setup(
    keccak_config: &KeccakConfig,
    outer_config: &OuterConfig,
    keygen_inputs: &OuterKeygenInputs,
) -> (
    ProvingKey<G1Affine>,
    OuterGateConfig,
    MultiPhaseThreadBreakPoints,
    OuterCircuitInputs<FixedOuterCircuit>,
) {
    info!("Outer keygen start");
    let now = Instant::now();
    let (pk, outer_gate_config, break_points, _) =
        gen_outer_pk::<
            SHPLONK,
            FixedOuterCircuit,
            ProverSHPLONK<Bn256>,
            VerifierSHPLONK<Bn256>,
        >(outer_config, keygen_inputs)
        .unwrap();
    info!("Outer keygen time: {:?}", now.elapsed());

    let outer_inputs =
        outer_input_setup(keccak_config, outer_config, keygen_inputs);
    (pk, outer_gate_config, break_points, outer_inputs)
}

/// Generates an outer proof from `outer_inputs` using `pk`.
fn outer_circuit_prover(
    outer_config: &OuterConfig,
    outer_gate_config: &OuterGateConfig,
    pk: &ProvingKey<G1Affine>,
    break_points: MultiPhaseThreadBreakPoints,
    outer_inputs: &OuterCircuitInputs<FixedOuterCircuit>,
    keygen_inputs: &OuterKeygenInputs,
) -> (Vec<u8>, Vec<Fr>) {
    // Benchmark from here
    outer_gate_config.set_environment();
    let circuit = OuterCircuit::prover(
        outer_config,
        outer_gate_config,
        break_points,
        outer_inputs,
    );
    let outer_params = keygen_inputs.outer_params;
    let instances = circuit.instances();
    let mut transcript = EvmTranscript::<G1Affine, _, _, _>::init(vec![]);
    let rng = StdRng::from_seed(Default::default());
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<Bn256>,
        _,
        _,
        EvmTranscript<_, _, _, _>,
        _,
    >(
        outer_params,
        pk,
        &[circuit],
        &[&[&instances[0]]],
        rng,
        &mut transcript,
    )
    .expect("proof gen. failure");
    (transcript.finalize(), instances[0].clone())
}

/// EVM Verification Error
#[derive(Clone, Debug)]
enum EvmVerificationError {
    /// Contract too large to be deployed
    ContractTooLarge(usize),
    /// Transaction reverted
    Reverted(String),
}

/// Verifies `proof` against `instances` on an EVM.
fn evm_verify(
    proof: Vec<u8>,
    instances: Vec<Fr>,
    keygen_inputs: &OuterKeygenInputs,
    pk: &ProvingKey<G1Affine>,
) -> Result<u64, EvmVerificationError> {
    // Compile verifier into yul
    let num_instance = vec![instances.len()];
    let verifier_yul = gen_outer_evm_verifier::<SHPLONK>(
        keygen_inputs.outer_params,
        pk.get_vk(),
        num_instance,
    );
    let verifier_byte_code = compile_yul(&verifier_yul);
    let deployed_bytes = verifier_byte_code.len();
    println!("Verifier contract length: {deployed_bytes} bytes");
    if deployed_bytes >= CONTRACT_BYTE_LIMIT {
        return Err(EvmVerificationError::ContractTooLarge(deployed_bytes));
    }
    // Deploy
    let calldata = encode_calldata(&[instances], &proof);
    let mut evm = ExecutorBuilder::default()
        .with_gas_limit(u64::MAX.into())
        .build();

    let caller = Address::from_low_u64_be(0xfe);
    let verifier = evm
        .deploy(caller, verifier_byte_code.into(), 0.into())
        .address
        .unwrap();
    // Verify
    let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());
    if result.reverted {
        return Err(EvmVerificationError::Reverted(format!("{result:?}")));
    }
    Ok(result.gas_used)
}

/// Benchmarks the outer circuit proving time and gas cost for all configurations
/// in the configs folder.
///
/// # Note
///
/// If the EVM verifier contract for a given config is too large and can't be deployed,
/// that config is skipped without performing the benchmark.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("outer_benchmarks");
    group.sample_size(2);

    let configs = black_box(load_json::<Vec<UpaConfig>>(OUTER_CONFIG_FILE));
    const KECCAK_DEGREE: u32 = 16;
    for config in configs {
        let keccak_config =
            black_box(keccak_config_from_outer_config(&config, KECCAK_DEGREE));
        let bv_srs = black_box(gen_srs(config.bv_config.degree_bits));
        let keccak_srs = black_box(gen_srs(keccak_config.degree_bits));
        let outer_srs = black_box(gen_srs(config.outer_config.degree_bits));
        let keygen_inputs =
            black_box(OuterKeygenInputs::new(&bv_srs, &keccak_srs, &outer_srs));
        // Keygen
        let (pk, gate_config, break_points, outer_inputs) = black_box(
            outer_circuit_setup(&keccak_config, &config, &keygen_inputs),
        );
        black_box(println!("Proving Outer Circuit with config: {config:#?}"));
        black_box(println!(
            "Proving Outer Circuit with keccak config: {keccak_config:#?}"
        ));
        black_box(println!(
            "Proving Outer Circuit with gate config: {gate_config:#?}"
        ));
        black_box(println!("Checking deployability and gas costs"));
        black_box(info!("Outer Circuit Prover start"));
        let (proof, instances) = black_box(outer_circuit_prover(
            &config,
            &gate_config,
            &pk,
            break_points.clone(),
            &outer_inputs,
            &keygen_inputs,
        ));
        let gas_per_proof = black_box(
            match evm_verify(proof, instances, &keygen_inputs, &pk) {
                Ok(gas) => {
                    gas / ((config.outer_batch_size * config.inner_batch_size)
                        as u64)
                }
                Err(e) => {
                    println!("EVM Verification Error: {e:?}");
                    continue;
                }
            },
        );
        black_box(println!("Gas cost per proof: {gas_per_proof:?}"));
        group.bench_with_input(
            black_box(BenchmarkId::new("outer", config)),
            &config,
            move |bencher, config| {
                bencher.iter(|| {
                    black_box(info!("Outer Circuit Prover start"));
                    black_box(outer_circuit_prover(
                        config,
                        &gate_config,
                        &pk,
                        break_points.clone(),
                        &outer_inputs,
                        &keygen_inputs,
                    ));
                })
            },
        );
    }
    group.finish()
}

criterion_group!(benches, bench);
criterion_main!(benches);
