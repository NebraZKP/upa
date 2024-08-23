use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::create_proof,
        poly::{
            commitment::Params,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::ProverSHPLONK,
            },
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    },
    utils::fs::gen_srs,
};
use rand_core::OsRng;
use snark_verifier_sdk::CircuitExt;
use upa_circuits::{
    batch_verify::universal::{
        types::{UniversalBatchVerifierConfig, UniversalBatchVerifierInputs},
        UniversalBatchVerifyCircuit,
    },
    utils::{
        benchmarks::{keygen, UBV_CONFIG_FILE},
        file::{load_json, open_file_for_read, ubv_file_root},
        upa_config::UpaConfig,
    },
    SafeCircuit,
};

/// Benchmarks the universal batch verifier circuit proving time for all configurations
/// in the configs folder.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("UBV_Prover");
    group.sample_size(2);

    let configs = black_box(load_json::<Vec<UpaConfig>>(UBV_CONFIG_FILE));

    for config in configs {
        let upa_config = config.clone();
        let config = black_box(UniversalBatchVerifierConfig::from(&config));
        // Sample app proofs/pi's according to config
        let mut rng = black_box(OsRng);
        let ubv_inputs = black_box(UniversalBatchVerifierInputs::sample_mixed(
            &config, &mut rng,
        ));
        // SRS
        // let srs = black_box(gen_srs(config.degree_bits));
        // Generate pk
        let (srs, pk, gate_config, break_points) = {
            // Current dir: saturn/upa/circuits
            // println!("Current dir: {:?}", std::env::current_dir());
            // keygen::<UniversalBatchVerifyCircuit>(&bv_config, &(), &bv_srs)

            let srs_file = format!("./benches/_srs/deg_{}.srs", config.degree_bits);
            let mut buf = open_file_for_read(&srs_file);
            let srs = ParamsKZG::<Bn256>::read(&mut buf)
                .unwrap_or_else(|e| panic!("failed to read srs: {e}"));

            // Rather than generating, load from file located at `benches/_keys`
            let ubv_file_root = ubv_file_root(&upa_config);
            let gate_config =
                load_json(&format!("{}.gate_config", ubv_file_root));
            let break_points: MultiPhaseThreadBreakPoints =
                load_json(&format!("{}.pk.bps", ubv_file_root));

            let mut buf = open_file_for_read(&format!("{}.pk", ubv_file_root));
            let pk =
                UniversalBatchVerifyCircuit::<_, G1Affine>::read_proving_key(
                    &config.into(),
                    &gate_config,
                    &mut buf,
                )
                .unwrap_or_else(|e| panic!("error reading pk: {e}"));
            (srs, pk, gate_config, break_points)
        };
        black_box(println!("Proving UBV Circuit with config: {config:#?}"));
        black_box(println!(
            "Proving UBV Circuit with gate config: {gate_config:#?}"
        ));

        group.bench_with_input(
            black_box(BenchmarkId::new("UBV_Prover", config)),
            &config,
            move |bencher, config| {
                bencher.iter(|| {
                    let _ = black_box({
                        let circuit =
                            UniversalBatchVerifyCircuit::<Fr, G1Affine>::prover(
                                config,
                                &gate_config,
                                break_points.clone(),
                                &ubv_inputs,
                            );
                        let instances = circuit.instances();
                        // Prove
                        let mut transcript =
                            Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(
                                vec![],
                            );
                        create_proof::<
                            KZGCommitmentScheme<Bn256>,
                            ProverSHPLONK<Bn256>,
                            _,
                            _,
                            _,
                            _,
                        >(
                            &srs,
                            &pk,
                            &[circuit],
                            &[&[&instances[0]]],
                            rng,
                            &mut transcript,
                        )
                        .expect("proof gen. failure");
                        transcript.finalize()
                    });
                })
            },
        );
    }
    group.finish()
}

criterion_group!(benches, bench);
criterion_main!(benches);
