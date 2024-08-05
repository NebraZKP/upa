use crate::{
    batch_verify::common::{
        native::json::{load_proof_and_inputs, load_vk},
        types::{Proof, PublicInputs, VerificationKey},
    },
    CircuitWithLimbsConfig, EccPrimeField,
};
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::{GateThreadBuilder, RangeWithInstanceCircuitBuilder},
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine, G1},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::KZGCommitmentScheme,
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
            TranscriptWriterBuffer,
        },
    },
    utils::fs::gen_srs,
    AssignedValue,
};
use rand_core::OsRng;
use serde::de::DeserializeOwned;
use std::{
    env,
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

mod commitment_point;
mod hashing;
mod keccak;
mod universal_batch_verifier;
mod universal_outer;
mod utils;

pub(crate) const VK_FILE: &str = "src/tests/data/vk.json";
// TODO: For now this VK is invalid, I just copied `delta` into the commitment fields
pub(crate) const VK_WITH_COMMITMENT_FILE: &str =
    "src/tests/data/vk_commitment.json";
const PROOF1_FILE: &str = "src/tests/data/proof1.json";
const PROOF2_FILE: &str = "src/tests/data/proof2.json";
const PROOF3_FILE: &str = "src/tests/data/proof3.json";
/// A file with a JSON array of 2 sample proof and input pairs.
/// A file with a JSON array of 8 sample proof and input pairs.
const PROOF_BATCH_1_8_FILE: &str = "src/tests/data/proof_batch_1_8.json";

const NUM_LIMBS: usize = 3;
const LIMB_BITS: usize = 88;

pub(crate) fn encode_g1(f: i32) -> G1Affine {
    G1Affine::from(G1::generator() * Fr::from(f as u64))
}

/// Test helper that returns `num_proofs` application circuit proofs, public inputs,
/// and verification key from file. Currently this draws from 3 distinct sample proofs
/// and copies them as needed to produce `num_proofs` many proofs.
#[allow(dead_code)] // Used in fixed BV circuit, no longer supported
pub(crate) fn sample_proofs_inputs_vk(
    num_proofs: usize,
) -> (Vec<(Proof, PublicInputs)>, VerificationKey) {
    // Read the vk
    let vk = load_vk(VK_FILE);

    // Read the proofs
    let proofs_and_inputs = [PROOF1_FILE, PROOF2_FILE, PROOF3_FILE]
        .iter()
        .map(|e| load_proof_and_inputs(e))
        .cycle()
        .take(num_proofs)
        .collect();

    (proofs_and_inputs, vk)
}

/// The build_circuit function for circuits with instances.
pub trait BuildCircuitFn<C: DeserializeOwned + Debug, R> = Fn(
    &mut GateThreadBuilder<Fr>,
    &CircuitWithLimbsConfig,
    &C,
    &mut Vec<AssignedValue<Fr>>,
) -> R;

/// Test key, witness generation and proof generation of a circuit, based on
/// the configurations in `path`.  The file `path` must contain one or more
/// lines of JSON specifying a `BasicConfig`, with any extra attributes
/// required by the test-specific object type `C`.  The function
/// `build_circuit` is used to contruct a circuit using the `BasicConfig` and
/// `C` objects read from `path`.  The `build_circuit` function can optionally
/// return a type R (R = () for functions that do not return anything). The
/// returned value for each invocation (i.e. for each line in the config file)
/// is returned from this function.
#[allow(dead_code)] // Used in fixed BV circuit, no longer supported
fn run_circuit_test<
    C: DeserializeOwned + Debug,
    R,
    BC: BuildCircuitFn<C, R>,
>(
    path: impl AsRef<Path>,
    build_circuit: BC,
) -> Vec<R> {
    let mut out = Vec::<R>::new();

    let params_file = File::open(&path).unwrap_or_else(|e| {
        let path = path.as_ref().to_str().unwrap();
        panic!("Path {path} does not exist: {e:?}")
    });
    let params_reader = BufReader::new(params_file);
    for line in params_reader.lines() {
        let (basic_config, test_config) =
            CircuitWithLimbsConfig::with_child_type::<C>(
                line.as_ref().unwrap().as_str(),
            );

        std::env::set_var("LOOKUP_BITS", basic_config.lookup_bits.to_string());

        // let rng = OsRng;
        let k = basic_config.degree_bits;
        let kzg_params = gen_srs(k);

        // Keygen
        let mut builder = GateThreadBuilder::<Fr>::keygen();

        let mut instance = Vec::new();
        build_circuit(&mut builder, &basic_config, &test_config, &mut instance);

        let computed_params = builder.config(k as usize, Some(20));
        println!("Computed config (keygen): {computed_params:?}");
        let circuit =
            RangeWithInstanceCircuitBuilder::keygen(builder, instance);

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&kzg_params, &circuit).unwrap();
        end_timer!(vk_time);
        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&kzg_params, vk, &circuit).unwrap();
        end_timer!(pk_time);

        let break_points = circuit.circuit.0.break_points.take();
        drop(circuit);

        // Create proof
        let proof_time = start_timer!(|| "Proving time");
        let mut builder = GateThreadBuilder::<Fr>::prover();

        let mut instance = Vec::new();
        out.push(build_circuit(
            &mut builder,
            &basic_config,
            &test_config,
            &mut instance,
        ));

        let circuit = RangeWithInstanceCircuitBuilder::prover(
            builder,
            instance,
            break_points,
        );
        let instance_vals = circuit.instance();
        let mut transcript =
            Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(
            &kzg_params,
            &pk,
            &[circuit],
            &[&[&instance_vals]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();
        end_timer!(proof_time);

        // Verify proof
        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = kzg_params.verifier_params();
        let strategy = SingleStrategy::new(&kzg_params);
        let mut transcript =
            Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            verifier_params,
            pk.get_vk(),
            strategy,
            &[&[&instance_vals]],
            &mut transcript,
        )
        .unwrap();
        end_timer!(verify_time);
    }

    out
}

/// Run `MockProver` on a circuit from a config located at `path`.  Operation
/// is exactly the same as run_circuit_test, except that `MockProver` is used.
/// This often gives more informative error messages.
#[allow(dead_code)] // Used in fixed BV circuit, no longer supported
pub fn run_circuit_mock_test<
    C: DeserializeOwned + Debug,
    R,
    BC: BuildCircuitFn<C, R>,
>(
    path: impl AsRef<Path>,
    build_circuit: BC,
) -> Vec<R> {
    let mut out = Vec::<R>::new();

    let params_file = File::open(&path).unwrap_or_else(|e| {
        let path = path.as_ref().to_str().unwrap();
        panic!("Path {path} does not exist: {e:?}")
    });
    let params_reader = BufReader::new(params_file);
    for line in params_reader.lines() {
        let (basic_config, test_config) =
            CircuitWithLimbsConfig::with_child_type::<C>(
                line.as_ref().unwrap().as_str(),
            );

        std::env::set_var("LOOKUP_BITS", basic_config.lookup_bits.to_string());

        let k = basic_config.degree_bits;

        let mut builder = GateThreadBuilder::<Fr>::mock();

        let mut instance = Vec::new();
        out.push(build_circuit(
            &mut builder,
            &basic_config,
            &test_config,
            &mut instance,
        ));

        let computed_params = builder.config(k as usize, Some(20));
        println!("Computed config (keygen): {computed_params:?}");
        let circuit = RangeWithInstanceCircuitBuilder::mock(builder, instance);
        let instance_vals = circuit.instance();

        MockProver::run(k, &circuit, vec![instance_vals])
            .unwrap()
            .assert_satisfied();
    }

    out
}

/// Run `MockProver` on a circuit from a config located at `path`.  Operation
/// is exactly the same as run_circuit_test, except that `MockProver` is used.
/// This often gives more informative error messages.
#[allow(dead_code)] // Used in fixed BV circuit, no longer supported
pub fn run_circuit_mock_test_failure<
    C: DeserializeOwned + Debug,
    R,
    BC: BuildCircuitFn<C, R>,
>(
    path: impl AsRef<Path>,
    build_circuit: BC,
) {
    let params_file = File::open(&path).unwrap_or_else(|e| {
        let path = path.as_ref().to_str().unwrap();
        panic!("Path {path} does not exist: {e:?}")
    });
    let params_reader = BufReader::new(params_file);
    for line in params_reader.lines() {
        let (basic_config, test_config) =
            CircuitWithLimbsConfig::with_child_type::<C>(
                line.as_ref().unwrap().as_str(),
            );

        std::env::set_var("LOOKUP_BITS", basic_config.lookup_bits.to_string());

        let k = basic_config.degree_bits;

        let mut builder = GateThreadBuilder::<Fr>::mock();

        let mut instance = Vec::new();
        build_circuit(&mut builder, &basic_config, &test_config, &mut instance);

        builder.config(k as usize, Some(20));
        let circuit = RangeWithInstanceCircuitBuilder::mock(builder, instance);
        let instance_vals = circuit.instance();

        let prover = MockProver::run(k, &circuit, vec![instance_vals]).unwrap();
        let res = prover.verify();
        match res {
            Ok(_) => {
                panic!("Expected circuit failure");
            }
            Err(_failures) => {
                // TODO: Determine how to allow the caller to specify a
                // specific failiure. (_failures is a vector of error codes,
                // so need to consider exactly what the caller should
                // provide).
            }
        }
    }
}

/// Removes specified environment variables
pub fn remove_env_variables(keys: Vec<String>) {
    for key in keys {
        env::remove_var(key);
    }
}
