use crate::{
    batch_verify::universal::types::{
        UPA_V1_0_0_CHALLENGE_DOMAIN_TAG_STRING,
        UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING,
        UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING_WITH_COMMITMENT,
    },
    utils::hashing::{
        brute_force_poseidon, compute_domain_tag, var_len_poseidon,
        FieldElementRepresentation, InCircuitHash, InCircuitPartialHash,
        PoseidonHasher, POSEIDON_R,
    },
    EccPrimeField,
};
use halo2_base::{
    gates::builder::GateThreadBuilder,
    halo2_proofs::halo2curves::bn256::Fr,
    safe_types::{RangeChip, RangeInstructions},
    AssignedValue, Context,
};
use itertools::Itertools;
use rand::Rng;
use rand_core::{OsRng, RngCore};

/// Lookup bits
const LOOKUP_BITS: usize = 16;

/// Test Domain tag
const DOMAIN_TAG: &str = "test";

/// Prints the domain tags currently used in UPA, which are
/// the keccak digests of simple strings realized as field elements.
#[ignore = "does nothing"]
#[test]
fn domain_tags() {
    fn print_domain_tag(domain_tag_str: &str) {
        println!(
            "DOMAIN TAG: 0x{} (preimage: {})",
            hex::encode(compute_domain_tag(domain_tag_str)),
            domain_tag_str
        );
    }

    print_domain_tag(UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING);
    print_domain_tag(UPA_V1_0_0_CIRCUITID_DOMAIN_TAG_STRING_WITH_COMMITMENT);
    print_domain_tag(UPA_V1_0_0_CHALLENGE_DOMAIN_TAG_STRING);
}

/// Dummy Hashable.
///
/// This struct is intended to test the different cases of
/// [`var_len_poseidon`].
struct DummyHashable<F: EccPrimeField> {
    elements: Vec<AssignedValue<F>>,
    rate: usize,
    remainder: usize,
}

impl<F: EccPrimeField> DummyHashable<F> {
    fn sample_with_remainder<R>(
        ctx: &mut Context<F>,
        remainder: usize,
        rate: usize,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + ?Sized,
    {
        const MAX_NUM_CHUNKS: usize = 20;
        let num_chunks = rng.gen_range(0..MAX_NUM_CHUNKS);
        let elements = (0..num_chunks * rate + remainder)
            .into_iter()
            .map(|_| ctx.load_witness(F::random(&mut *rng)))
            .collect_vec();
        Self {
            elements,
            rate,
            remainder,
        }
    }
}

impl<F: EccPrimeField> InCircuitHash<F> for DummyHashable<F> {
    fn hash(&self, hasher: &mut PoseidonHasher<F>) {
        let slice = &self.elements[..];
        slice.hash(hasher);
    }
}

impl<F: EccPrimeField> FieldElementRepresentation<F> for DummyHashable<F> {
    fn representation(&self) -> Vec<AssignedValue<F>> {
        self.elements.clone()
    }

    fn num_elements(&self) -> usize {
        self.elements.len()
    }
}

impl<F: EccPrimeField> InCircuitPartialHash<F> for DummyHashable<F> {
    fn max_parts(&self) -> usize {
        self.num_elements() / self.rate + 1
    }
    fn partial_hash(&self, parts: usize, hasher: &mut PoseidonHasher<F>) {
        let slice = &self.elements[..self.rate * parts + self.remainder];
        slice.hash(hasher);
    }
    fn parts_to_num_elements(&self, parts: usize) -> usize {
        self.rate * parts + self.remainder
    }
}

/// Checks that a given `poseidon` implementation returns the expected
/// value on a struct which implements [`InCircuitPartialHash`].
fn check_poseidon_implementation<F, D, P, E, S, R>(
    poseidon: P,
    expect_poseidon: E,
    sampler: S,
    rng: &mut R,
) -> bool
where
    F: EccPrimeField,
    D: InCircuitPartialHash<F>,
    P: Fn(
        &mut Context<F>,
        Option<&str>,
        &RangeChip<F>,
        AssignedValue<F>,
        &D,
    ) -> AssignedValue<F>,
    E: Fn(&mut Context<F>, &str, &RangeChip<F>, usize, &D) -> F,
    S: Fn(&mut Context<F>, &mut R) -> D,
    R: RngCore + ?Sized,
{
    // initialize context and chip
    let mut builder = GateThreadBuilder::<F>::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::<F>::default(LOOKUP_BITS);
    // sample hashable
    let hashable = sampler(ctx, rng);
    // sample number of parts
    let num_parts = rng.gen_range(0..hashable.max_parts());
    let assigned_num_parts = ctx.load_witness(F::from(num_parts as u64));
    let expected_poseidon =
        expect_poseidon(ctx, DOMAIN_TAG, &chip, num_parts, &hashable);
    let poseidon_result =
        poseidon(ctx, Some(DOMAIN_TAG), &chip, assigned_num_parts, &hashable);
    poseidon_result.value() == &expected_poseidon
}

/// Specializes [`check_poseidon_implementation`] for a [`DummyHashable`] with all
/// possible remainder values.
fn check_poseidon_on_dummy<F, P, R>(poseidon: P, rng: &mut R) -> bool
where
    F: EccPrimeField,
    P: Fn(
        &mut Context<F>,
        Option<&str>,
        &RangeChip<F>,
        AssignedValue<F>,
        &DummyHashable<F>,
    ) -> AssignedValue<F>,
    R: RngCore + ?Sized,
{
    let mut result = true;
    for remainder in 0..POSEIDON_R {
        result &= check_poseidon_implementation::<F, DummyHashable<F>, _, _, _, _>(
            &poseidon,
            |ctx, domain_tag, chip, num_parts, assigned| {
                let mut hasher =
                    PoseidonHasher::new(ctx, &chip.gate, Some(domain_tag));
                let num_parts_assigned =
                    ctx.load_witness(F::from(num_parts as u64));
                hasher.absorb(&num_parts_assigned);
                assigned.partial_hash(num_parts, &mut hasher);
                *hasher.squeeze(ctx).value()
            },
            |ctx, rng| {
                DummyHashable::sample_with_remainder(
                    ctx, remainder, POSEIDON_R, rng,
                )
            },
            rng,
        )
    }
    result
}

/// Runs [`check_poseidon_implementation`] for [`var_len_poseidon`] on an
/// [`DummyHashable`].
#[test]
fn check_var_len_poseidon_on_dummy() {
    let mut rng = OsRng;
    assert!(
        check_poseidon_on_dummy::<Fr, _, _>(&var_len_poseidon, &mut rng),
        "Var len Poseidon error"
    );
}

/// Runs [`check_poseidon_implementation`] for [`brute_force_poseidon`] on an
/// [`DummyHashable`].
#[test]
fn check_brute_force_poseidon_on_dummy() {
    let mut rng = OsRng;
    assert!(
        check_poseidon_on_dummy::<Fr, _, _>(
            |ctx, domain_tag, range, num_parts, assigned| brute_force_poseidon(
                ctx,
                domain_tag,
                range.gate(),
                num_parts,
                assigned
            ),
            &mut rng
        ),
        "Brute force Poseidon error"
    );
}
