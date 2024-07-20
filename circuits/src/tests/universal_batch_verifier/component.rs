use super::sample_test_config;
use crate::{
    batch_verify::{
        common::{
            chip::BatchVerifierChip,
            ecc::{
                get_assigned_value_g1point, get_assigned_value_g2point,
                EcPointPair,
            },
            native::compute_vk_poseidon_hash,
            types::VerificationKey,
        },
        universal::{
            chip::{AssignedPreparedProof, UniversalBatchVerifierChip},
            native::{
                self, compute_circuit_id, compute_pi_term_for_entry,
                update_batch,
            },
            types::{BatchEntries, UniversalBatchVerifierInputs},
        },
    },
    tests::{load_vk, VK_FILE, VK_WITH_COMMITMENT_FILE},
    CircuitWithLimbsConfig, EccPrimeField,
};
use halo2_base::{
    gates::builder::GateThreadBuilder,
    halo2_proofs::halo2curves::{
        bn256::{multi_miller_loop, Fq12, Fr, G1Affine, G2Affine, Gt},
        pairing::MillerLoopResult,
    },
    safe_types::RangeChip,
};
use halo2_ecc::{
    bn254::{Fp12Chip, FpChip, FqPoint},
    fields::{vector::FieldVector, FieldChip},
};
use itertools::Itertools;
use rand_core::OsRng;

/// Default degree for test configs
const DEFAULT_DEGREE: u32 = 14;

/// Returns `pair` as a pair of [`G1Affine`] and [`G2Affine`] points.
fn get_assigned_value_pair<F: EccPrimeField>(
    fp_chip: &FpChip<F>,
    pair: &EcPointPair<F>,
) -> (G1Affine, G2Affine) {
    let (g1_point, g2_point) = pair;
    (
        get_assigned_value_g1point(fp_chip, g1_point),
        get_assigned_value_g2point(fp_chip, g2_point),
    )
}

/// Returns the unassigned pairs from `assigned_prepared_proof`. Note the order is
/// chosen to match that of [`native`].
fn get_assigned_value_prepared_proof<F: EccPrimeField>(
    fp_chip: &FpChip<F>,
    assigned_prepared_proof: &AssignedPreparedProof<F>,
) -> Vec<(G1Affine, G2Affine)> {
    assigned_prepared_proof
        .iter()
        .map(|pair| get_assigned_value_pair(fp_chip, pair))
        .collect()
}

/// Returns `fq_point` as an [`Fq12`] point.
fn get_assigned_value_fqpoint<F: EccPrimeField>(
    fp_chip: &FpChip<F>,
    fq_point: &FqPoint<F>,
) -> Fq12 {
    let fp12_chip = Fp12Chip::new(fp_chip);
    fp12_chip.get_assigned_value(&FieldVector(
        fq_point
            .0
            .iter()
            .map(|point| point.as_ref().clone())
            .collect_vec(),
    ))
}

/// Checks that the UBV circuit outputs coincide one by one with the native implementation.
#[test]
fn component() {
    // Config and inputs setup
    let mut rng = OsRng;
    let config = sample_test_config(DEFAULT_DEGREE, &mut rng);
    let circuit_config =
        CircuitWithLimbsConfig::from_degree_bits(config.degree_bits);
    let inputs = UniversalBatchVerifierInputs::sample_mixed(&config, &mut rng);

    // Builder and chip setup
    let mut builder = GateThreadBuilder::<Fr>::mock();
    let range = RangeChip::<Fr>::default(config.lookup_bits);
    let fp_chip = FpChip::new(&range, config.limb_bits, config.num_limbs);
    let bv_chip = BatchVerifierChip::new(&fp_chip);
    let chip = UniversalBatchVerifierChip::new(&bv_chip);
    let assigned_inputs = chip.assign_batch_entries(
        builder.main(0),
        &BatchEntries::from_ubv_inputs_and_config(&inputs, &config),
    );

    // Check vk hash
    let mut vk_hashes = Vec::new();
    for (assigned_entry, native_entry) in
        assigned_inputs.0.iter().zip(inputs.0.iter())
    {
        let assigned_vk_hash =
            chip.compute_vk_hash(builder.main(0), assigned_entry);
        let vk_hash = compute_vk_poseidon_hash(
            &circuit_config,
            &native_entry.vk,
            config.max_num_public_inputs as usize,
        );
        assert_eq!(assigned_vk_hash.value(), &vk_hash, "vk hash mismatch");
        vk_hashes.push(assigned_vk_hash);
    }

    // Check challenge points
    let (native_r, native_t) = native::compute_challenge_points(
        // We update the batch here to include the hash of the
        // commitment point in the challenge computation.
        // We don't need to do it later because this function is called
        // internally by `native::get_pairs`
        update_batch(inputs.0.iter()),
        config.max_num_public_inputs as usize,
    );
    let circuit_challenges = chip.compute_challenge_points(
        builder.main(0),
        &vk_hashes,
        &assigned_inputs,
    );
    assert_eq!(
        &native_r,
        circuit_challenges.0.value(),
        "Challenge r mismatch"
    );
    assert_eq!(
        &native_t,
        circuit_challenges.1.value(),
        "Challenge t mismatch"
    );

    // Check pairs
    let native_pairs =
        native::get_pairs(inputs.0, config.max_num_public_inputs as usize);
    let circuit_pairs =
        chip.prepare_proofs(&mut builder, &assigned_inputs, circuit_challenges);
    assert_eq!(
        native_pairs,
        get_assigned_value_prepared_proof(chip.fp_chip(), &circuit_pairs),
        "Pair mismatch"
    );

    // Check pairing output
    let prepared_native_pairs = native_pairs
        .into_iter()
        .map(|(a, b)| (a, b.into()))
        .collect_vec();
    let native_pairing_out = multi_miller_loop(
        prepared_native_pairs
            .iter()
            .map(|(a, b)| (a, b))
            .collect::<Vec<_>>()
            .as_slice(),
    )
    .final_exponentiation();

    // TODO: needless cloning
    let circuit_pairs = circuit_pairs.iter().cloned().collect_vec();

    let circuit_pairing_out = chip
        .bv_chip()
        .multi_pairing(builder.main(0), &circuit_pairs);
    let circuit_pairing_out_value =
        get_assigned_value_fqpoint(&fp_chip, &circuit_pairing_out);
    assert_eq!(
        format!("Gt({circuit_pairing_out_value:?})"),
        format!("{native_pairing_out:?}"),
        "Pairing output mismatch"
    );
    assert_eq!(
        native_pairing_out,
        Gt::identity(),
        "Pairing output must be the identity"
    );
}

// Compute the circuitId of the example application VK, and output it, with
// its decomposition, as a test vector for the contract tests.
fn circuit_id_test_vector<F>(compute_circuit_id: F, vk_file: &str)
where
    F: FnOnce(&VerificationKey) -> [u8; 32],
{
    let vk = load_vk(vk_file);
    let circuit_id = compute_circuit_id(&vk);
    let hex = hex::encode(circuit_id);
    println!("circuit_id: 0x{hex}: {vk_file})");
}

/// Runs [`vk_hash_test_vector`] for UPA v1.0.0.
#[ignore = "tests nothing"]
#[test]
fn circuit_id_test_vector_universal() {
    println!("VK without commitment:");
    circuit_id_test_vector(compute_circuit_id, VK_FILE);
    println!("VK with commitment:");
    circuit_id_test_vector(compute_circuit_id, VK_WITH_COMMITMENT_FILE);
}

#[test]
fn compute_pi_pairs() {
    let mut rng = OsRng;
    let mut config = sample_test_config(DEFAULT_DEGREE, &mut rng);
    config.inner_batch_size = 1;

    // Builder and chip setup
    let mut builder = GateThreadBuilder::<Fr>::mock();
    let ctx = builder.main(0);
    let range = RangeChip::<Fr>::default(config.lookup_bits);
    let fp_chip = FpChip::new(&range, config.limb_bits, config.num_limbs);
    let bv_chip = BatchVerifierChip::new(&fp_chip);
    let chip = UniversalBatchVerifierChip::new(&bv_chip);

    // Sample inputs
    let ubv_inputs =
        UniversalBatchVerifierInputs::sample_mixed(&config, &mut rng);

    let updated_ubv_inputs = update_batch(ubv_inputs.0.iter());
    let pi_pairs = updated_ubv_inputs
        .iter()
        .map(|entry| (compute_pi_term_for_entry(entry), entry.vk.gamma));

    let assigned_batch_entries = chip.assign_batch_entries(
        ctx,
        &BatchEntries::from_ubv_inputs_and_config(&ubv_inputs, &config),
    );

    let assigned_pi_pairs =
        chip.compute_pi_pairs(&mut builder, &assigned_batch_entries);

    // Check
    for (idx, (pair, assigned_pair)) in
        pi_pairs.zip(assigned_pi_pairs.iter()).enumerate()
    {
        let g1 = get_assigned_value_g1point(&fp_chip, &assigned_pair.0);
        let g2 = get_assigned_value_g2point(&fp_chip, &assigned_pair.1);
        let g1_native: G1Affine = pair.0.into();

        assert_eq!(g1_native, g1, "g1 mismatch at {idx:?}");
        assert_eq!(pair.1, g2, "g2 mismatch at {idx:?}");
    }
}
