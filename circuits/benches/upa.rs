//! Reports all UPA circuit prover times.
use core::iter;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, ProvingKey},
        poly::{
            commitment::Params,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
            },
        },
        transcript::TranscriptWriterBuffer,
    },
    utils::fs::gen_srs,
};
use rand_core::OsRng;
use snark_verifier::{
    loader::{
        evm::{compile_yul, encode_calldata, Address, ExecutorBuilder},
        native::NativeLoader,
    },
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
};
use snark_verifier_sdk::{
    halo2::{PoseidonTranscript, POSEIDON_SPEC},
    CircuitExt, Snark, SHPLONK,
};
use std::time::Instant;
use upa_circuits::{
    batch_verify::universal::{
        types::{UniversalBatchVerifierConfig, UniversalBatchVerifierInputs},
        UniversalBatchVerifyCircuit,
    },
    keccak::{
        inputs::KeccakCircuitInputs, utils::keccak_inputs_from_ubv_instances,
        KeccakCircuit, KeccakConfig,
    },
    outer::{
        universal, utils::gen_outer_evm_verifier, OuterCircuitInputs,
        OuterCircuitWrapper, OuterKeygenInputs,
    },
    utils::{
        benchmarks::{
            keygen, CONTRACT_BYTE_LIMIT, UNIVERSAL_OUTER_CONFIG_FILE,
        },
        file::{load_json, open_file_for_read, outer_file_root, ubv_file_root},
        upa_config::UpaConfig,
    },
    SafeCircuit,
};

type UniversalOuterCircuit<'a> = OuterCircuitWrapper<
    'a,
    SHPLONK,
    universal::UniversalOuterCircuit,
    ProverSHPLONK<'a, Bn256>,
    VerifierSHPLONK<'a, Bn256>,
>;
type UniversalOuterCircuitInputs =
    OuterCircuitInputs<universal::UniversalOuterCircuit>;

// cargo bench --bench upa --features gpu 2>&1 | tee /home/todd/benchmark_logs/foo.log
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("upa_benchmarks");
    group.sample_size(2);

    let upa_configs = load_json::<Vec<UpaConfig>>(UNIVERSAL_OUTER_CONFIG_FILE);
    for config in upa_configs.iter() {
        // Sample UBV inputs from config
        let bv_config: UniversalBatchVerifierConfig = config.into();
        println!("Begin UBV with config {bv_config:?}");
        let bv_inputs =
            UniversalBatchVerifierInputs::sample_mixed(&bv_config, &mut OsRng);
        // UBV Keygen
        let bv_srs = gen_srs(bv_config.degree_bits);
        let (bv_pk, bv_gate_config, bv_break_points) = {
            // keygen::<UniversalBatchVerifyCircuit>(&bv_config, &(), &bv_srs)

            // Rather than generating, load from file located at `benches/_keys`
            let ubv_file_root = ubv_file_root(config);
            let gate_config =
                load_json(&format!("{}.gate_config", ubv_file_root));
            let break_points = load_json(&format!("{}.bps", ubv_file_root));

            let mut buf = open_file_for_read(&format!("{}.pk", ubv_file_root));
            let pk =
                UniversalBatchVerifyCircuit::<_, G1Affine>::read_proving_key(
                    &config.into(),
                    &gate_config,
                    &mut buf,
                )
                .unwrap_or_else(|e| panic!("error reading pk: {e}"));
            (pk, gate_config, break_points)
        };
        println!("UBV gate config {bv_gate_config:?}");
        // Measure UBV Proving Time
        let (bv_proof, bv_instance_single) = black_box({
            let bv_timer = Instant::now();
            let circuit = UniversalBatchVerifyCircuit::prover(
                &bv_config,
                &bv_gate_config,
                bv_break_points,
                &bv_inputs,
            );
            let instances = circuit.instances();
            let mut transcript =
                PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(
                    vec![],
                    POSEIDON_SPEC.clone(),
                );
            let proof = {
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<Bn256>,
                    _,
                    _,
                    _,
                    _,
                >(
                    &bv_srs,
                    &bv_pk,
                    &[circuit],
                    &[&[&instances[0]]],
                    &mut OsRng,
                    &mut transcript,
                )
                .expect("proof gen. failure");
                transcript.finalize()
            };
            let bv_proving_time = bv_timer.elapsed();
            println!(
                "UBV Proving Time:
            \n Configuration: {bv_config:?}
            \n Time: {bv_proving_time:?}"
            );
            (proof, instances)
        });

        // We'll reuse those BV instances and proof
        let bv_instances: Vec<Vec<Vec<Fr>>> =
            iter::repeat(bv_instance_single.clone())
                .take(config.outer_batch_size as usize)
                .collect();

        // Compute Keccak proof, report
        let keccak_config: KeccakConfig = config.into();
        println!("Begin Keccak with config {keccak_config:?}");
        let keccak_inputs: KeccakCircuitInputs<Fr> =
            keccak_inputs_from_ubv_instances(
                bv_instances.iter().map(|s| s[0].as_slice()),
                keccak_config.num_app_public_inputs as usize,
                config.inner_batch_size as usize,
            )
            .into();
        let keccak_srs = gen_srs(keccak_config.degree_bits);
        let (keccak_pk, keccak_gate_config, keccak_break_points) =
            keygen::<KeccakCircuit>(&keccak_config, &(), &keccak_srs);
        println!("Keccak gate config {keccak_gate_config:?}");
        let (keccak_proof, keccak_instances) = {
            let keccak_timer = Instant::now();
            let circuit = KeccakCircuit::prover(
                &keccak_config,
                &keccak_gate_config,
                keccak_break_points,
                &keccak_inputs,
            );
            let instances = circuit.instances();
            let mut transcript =
                PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(
                    vec![],
                    POSEIDON_SPEC.clone(),
                );
            let proof = {
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<Bn256>,
                    _,
                    _,
                    _,
                    _,
                >(
                    &keccak_srs,
                    &keccak_pk,
                    &[circuit],
                    &[&[&instances[0]]],
                    &mut OsRng,
                    &mut transcript,
                )
                .expect("proof gen. failure");
                transcript.finalize()
            };
            let keccak_proving_time = keccak_timer.elapsed();
            println!(
                "Keccak Proving Time:
            \n Configuration: {keccak_config}
            \n Time: {keccak_proving_time:?}"
            );
            (proof, instances)
        };

        // Assemble snarks
        let bv_protocol = compile(
            &bv_srs,
            bv_pk.get_vk(),
            Config::kzg()
                .with_num_instance(vec![bv_instance_single[0].len()])
                .with_accumulator_indices(UniversalBatchVerifyCircuit::<
                    Fr,
                    G1Affine,
                >::accumulator_indices(
                )),
        );
        let bv_snarks = bv_instances
            .into_iter()
            .map(|bv_instance| {
                Snark::new(bv_protocol.clone(), bv_instance, bv_proof.clone())
            })
            .collect();
        let keccak_snark = Snark {
            protocol: compile(
                &keccak_srs,
                keccak_pk.get_vk(),
                Config::kzg()
                    .with_num_instance(vec![keccak_instances[0].len()])
                    .with_accumulator_indices(
                        KeccakCircuit::<Fr, G1Affine>::accumulator_indices(),
                    ),
            ),
            instances: keccak_instances,
            proof: keccak_proof,
        };
        // Compute outer proof, report
        drop(keccak_pk);
        drop(bv_pk);
        println!("Begin UniversalOuter with config {config:?}");
        // let outer_srs = gen_srs(config.outer_config.degree_bits);
        let outer_inputs =
            UniversalOuterCircuitInputs::new(config, bv_snarks, keccak_snark);
        let (outer_srs, outer_pk, outer_gate_config, outer_break_points) = {
            // keygen::<UniversalOuterCircuit>(
            //     config,
            //     &outer_keygen_inputs,
            //     &outer_srs,
            // )

            let srs_file = format!(
                "./benches/_srs/deg_{}.srs",
                config.outer_config.degree_bits
            );
            let mut buf = open_file_for_read(&srs_file);
            let srs = ParamsKZG::<Bn256>::read(&mut buf)
                .unwrap_or_else(|e| panic!("failed to read srs: {e}"));
            // Rather than generating, load from file located at `benches/_keys`
            let outer_file_root = outer_file_root(config);
            let gate_config =
                load_json(&format!("{}.gate_config", outer_file_root));
            let break_points: MultiPhaseThreadBreakPoints =
                load_json(&format!("{}.pk.bps", outer_file_root));
            let mut buf =
                open_file_for_read(&format!("{}.pk", outer_file_root));
            let pk = UniversalOuterCircuit::read_proving_key(
                config,
                &gate_config,
                &mut buf,
            )
            .unwrap_or_else(|e| panic!("error reading pk: {e}"));
            (srs, pk, gate_config, break_points)
        };
        // TODO: Needed?
        let outer_keygen_inputs =
            OuterKeygenInputs::new(&bv_srs, &keccak_srs, &outer_srs);

        println!("UniversalOuter gate config {outer_gate_config:?}");
        let (outer_proof, outer_instances) = {
            let outer_timer = Instant::now();
            let circuit = UniversalOuterCircuit::prover(
                config,
                &outer_gate_config,
                outer_break_points,
                &outer_inputs,
            );
            let instances = circuit.instances();
            let mut transcript =
                <EvmTranscript<G1Affine, _, _, _> as TranscriptWriterBuffer<
                    _,
                    G1Affine,
                    _,
                >>::init(vec![]);
            let proof = {
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<Bn256>,
                    _,
                    _,
                    EvmTranscript<_, _, _, _>,
                    _,
                >(
                    &outer_srs,
                    &outer_pk,
                    &[circuit],
                    &[&[&instances[0]]],
                    &mut OsRng,
                    &mut transcript,
                )
                .expect("proof gen. failure");
                transcript.finalize()
            };
            let outer_proving_time = outer_timer.elapsed();
            println!(
                "Universal Outer Proving Time:
            \n Configuration: {config:?}
            \n Time: {outer_proving_time:?}"
            );
            (proof, instances[0].clone())
        };

        // EVM check, report gas
        let gas_per_proof = black_box(
            match evm_verify(
                outer_proof,
                outer_instances,
                &outer_keygen_inputs,
                &outer_pk,
            ) {
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
        println!("Gas cost per proof: {gas_per_proof:?}");
    }
    group.finish()
}

criterion_group!(benches, bench);
criterion_main!(benches);

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

/// EVM Verification Error
#[derive(Clone, Debug)]
enum EvmVerificationError {
    /// Contract too large to be deployed
    ContractTooLarge(usize),
    /// Transaction reverted
    Reverted(String),
}
