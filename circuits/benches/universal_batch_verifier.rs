use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::create_proof,
        poly::kzg::{
            commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK,
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
        file::load_json,
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
        let config = black_box(UniversalBatchVerifierConfig::from(&config));
        // Sample app proofs/pi's according to config
        let mut rng = black_box(OsRng);
        let ubv_inputs = black_box(UniversalBatchVerifierInputs::sample_mixed(
            &config, &mut rng,
        ));
        // SRS
        let srs = black_box(gen_srs(config.degree_bits));
        // Generate pk
        let (pk, gate_config, break_points) = black_box(keygen::<
            UniversalBatchVerifyCircuit,
        >(
            &config, &(), &srs
        ));
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
