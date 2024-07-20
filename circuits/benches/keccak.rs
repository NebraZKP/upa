use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use halo2_base::{
    gates::builder::MultiPhaseThreadBreakPoints,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey},
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    },
    utils::fs::gen_srs,
};
use rand_core::OsRng;
use snark_verifier_sdk::CircuitExt;
use std::panic;
use upa_circuits::{
    keccak::{
        inputs::KeccakCircuitInputs, KeccakCircuit, KeccakConfig,
        KeccakGateConfig, KeccakInputType,
    },
    utils::{
        benchmarks::KECCAK_CONFIG_FILE, file::load_json, upa_config::UpaConfig,
    },
    SafeCircuit,
};

/// Generates a proving key for `config`
fn keygen(
    config: &KeccakConfig,
    params: &ParamsKZG<Bn256>,
    input_type: &KeccakInputType,
) -> Result<
    (
        ProvingKey<G1Affine>,
        KeccakGateConfig,
        MultiPhaseThreadBreakPoints,
    ),
    KeccakGateConfig,
> {
    let circuit = KeccakCircuit::<Fr, G1Affine>::keygen(config, input_type);
    let gate_config = circuit.gate_config().clone();
    // Keygen panics when `gate_config` is too wide. We catch it here to
    // return an error.
    let (pk, break_points) = match panic::catch_unwind(move || {
        let vk = keygen_vk(params, &circuit).expect("unable to gen. vk");
        let pk = keygen_pk(params, vk, &circuit).expect("unable to gen. pk");
        let break_points = circuit.break_points();
        (pk, break_points)
    }) {
        Ok(value) => value,
        _ => return Err(gate_config),
    };
    Ok((pk, gate_config, break_points))
}

/// Benchmarks the keccak circuit proving time for all configurations
/// in the configs folder.
///
/// # Note
///
/// Configs which are too wide, i.e., those which result in a very high
/// combined number of advice, lookup and keccak columns are discarded before
/// benchmarking.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_benchmarks");
    group.sample_size(2);

    let configs = black_box(load_json::<Vec<UpaConfig>>(KECCAK_CONFIG_FILE));
    let input_type = black_box(
        KeccakInputType::load_from_env().unwrap_or(KeccakInputType::Fixed),
    );
    black_box(println!("Keccak benchmark running with: {input_type:?}"));
    for config in configs {
        let keccak_config = black_box(KeccakConfig::from(&config));
        let mut rng = black_box(OsRng);
        let inputs = black_box(KeccakCircuitInputs::sample(
            &keccak_config,
            input_type,
            &mut rng,
        ));
        // Keygen
        let params = black_box(gen_srs(keccak_config.degree_bits));
        black_box(println!(
            "Proving Keccak Circuit with config: {keccak_config:#?}"
        ));
        let (pk, gate_config, break_points) = black_box(
            match keygen(&keccak_config, &params, &input_type) {
                Ok(result) => result,
                Err(gate_config) => {
                    println!("Proving Keccak Circuit with gate config: {gate_config:#?}");
                    println!("Error: Keccak gate config is too wide. Skipping benchmark");
                    continue;
                }
            },
        );
        black_box(println!(
            "Proving Keccak Circuit with gate config: {gate_config:#?}"
        ));
        group.bench_with_input(
            black_box(BenchmarkId::new("keccak", keccak_config)),
            &keccak_config,
            move |bencher, keccak_config| {
                bencher.iter(|| {
                    black_box({
                        // Circuit instantiation
                        let circuit = KeccakCircuit::<Fr, G1Affine>::prover(
                            keccak_config,
                            &gate_config,
                            break_points.clone(),
                            &inputs,
                        );
                        let instances = circuit.instances();
                        // Proof generation
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
                            &params,
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
