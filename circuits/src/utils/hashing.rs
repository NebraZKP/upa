use super::bitmask::ith_bit_bitmask;
use crate::{CircuitWithLimbsConfig, EccPrimeField};
use core::marker::PhantomData;
use ethers_core::utils::keccak256;
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fq,
    utils::{decompose_biguint, fe_to_biguint, CurveAffineExt},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::EcPoint,
    fields::{fp::Reduced, vector::FieldVector, FieldExtConstructor},
};
use itertools::Itertools;
use poseidon::PoseidonChip;

// TODO: Sanity check the reasoning below:

// In poseidon-solidity:
//
//   https://socket.dev/npm/package/poseidon-solidity,
//
// the most gas-efficient value of t (per element) seems to be t=3 (=> r = 2).
// Other constants are the output from `generate_parameters_grain.sage`.
//
// Other refs:
//   https://eprint.iacr.org/2019/458.pdf
//   https://github.com/iden3/circomlibjs/blob/main/src/poseidon_reference.js
//   https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage
//
// Sponge version
//   https://github.com/axiom-crypto/halo2/blob/axiom/dev/primitives/poseidon/src/poseidon.rs

/// Poseidon State size
pub(crate) const POSEIDON_T: usize = 3;
/// Poseidon Rate
pub(crate) const POSEIDON_R: usize = 2;
/// Poseidon Full rounds
pub(crate) const POSEIDON_R_F: usize = 8;
/// Poseidon Partial rounds
pub(crate) const POSEIDON_R_P: usize = 57;

pub fn digest_to_field_element<F: EccPrimeField>(digest: &[u8; 32]) -> F {
    let mut bytes_64 = [0u8; 64];
    bytes_64[..32].copy_from_slice(digest);
    F::from_bytes_wide(&bytes_64)
}

/// Compute bytes to derive a domain tag, as the keccak of the given string.
pub fn compute_domain_tag(domain_tag_str: &str) -> [u8; 32] {
    assert!(!domain_tag_str.is_empty());
    keccak256(domain_tag_str)
}

/// Compute and assign a domain tag (see `domain_tag`).
pub fn assigned_domain_tag<F: EccPrimeField>(
    ctx: &mut Context<F>,
    domain_tag_str: &str,
) -> AssignedValue<F> {
    ctx.load_constant(digest_to_field_element(&compute_domain_tag(
        domain_tag_str,
    )))
}

/// An in-circuit poseidon sponge, which can absorb instances of InCircuitHash
/// and then squeeze Fr values.
pub struct PoseidonHasher<'a, F: EccPrimeField> {
    pub gate_chip: &'a GateChip<F>,
    pub poseidon: PoseidonChip<F, POSEIDON_T, POSEIDON_R>,
}

impl<'a, F: EccPrimeField> PoseidonHasher<'a, F> {
    pub fn new(
        ctx: &mut Context<F>,
        gate_chip: &'a GateChip<F>,
        domain_tag: Option<&'a str>,
    ) -> Self {
        let domain_tag = domain_tag
            .map(|domain_tag_str| assigned_domain_tag(ctx, domain_tag_str));
        Self::new_with_domain_tag(ctx, gate_chip, domain_tag)
    }

    pub fn new_with_domain_tag(
        ctx: &mut Context<F>,
        gate_chip: &'a GateChip<F>,
        domain_tag: Option<AssignedValue<F>>,
    ) -> Self {
        let mut hasher = PoseidonHasher {
            gate_chip,
            poseidon: PoseidonChip::<F, POSEIDON_T, POSEIDON_R>::new(
                ctx,
                POSEIDON_R_F,
                POSEIDON_R_P,
            )
            .unwrap(),
        };
        if let Some(domain_tag) = domain_tag {
            hasher.absorb(&domain_tag);
        }
        hasher
    }

    pub fn new_with_state(
        init_state: [AssignedValue<F>; POSEIDON_T],
        gate_chip: &'a GateChip<F>,
    ) -> Self {
        PoseidonHasher {
            gate_chip,
            poseidon:
                PoseidonChip::<F, POSEIDON_T, POSEIDON_R>::new_with_state(
                    POSEIDON_R_F,
                    POSEIDON_R_P,
                    init_state,
                )
                .unwrap(),
        }
    }

    pub fn absorb<T: InCircuitHash<F>>(&mut self, assigned: &T) {
        assigned.hash(self);
    }

    pub fn squeeze(&mut self, ctx: &mut Context<F>) -> AssignedValue<F> {
        self.poseidon.squeeze(ctx, self.gate_chip).unwrap()
    }

    pub fn partial_absorb<T: InCircuitPartialHash<F>>(
        &mut self,
        assigned: &T,
        parts: usize,
    ) {
        assigned.partial_hash(parts, self)
    }
}

/// Computes the poseidon hash of `assigned[..len]`.
pub fn brute_force_poseidon<F, T>(
    ctx: &mut Context<F>,
    domain_tag: Option<&str>,
    chip: &GateChip<F>,
    len: AssignedValue<F>,
    assigned: &T,
) -> AssignedValue<F>
where
    F: EccPrimeField,
    T: InCircuitPartialHash<F>,
{
    let max_parts = assigned.max_parts();
    let mut result = Vec::with_capacity(max_parts);
    let bitmask = ith_bit_bitmask(ctx, chip, len, max_parts as u64);
    for i in 0..max_parts {
        let mut hasher = PoseidonHasher::new(ctx, chip, domain_tag);
        hasher.absorb(&len);
        hasher.partial_absorb(assigned, i);
        result.push(hasher.squeeze(ctx));
    }
    chip.inner_product(ctx, result, bitmask.into_iter().map(|b| b.into()))
}

/// Computes the poseidon hash of `assigned[..num_parts]`.
pub fn var_len_poseidon<F, T>(
    ctx: &mut Context<F>,
    domain_tag: Option<&str>,
    range: &RangeChip<F>,
    num_parts: AssignedValue<F>,
    assigned: &T,
) -> AssignedValue<F>
where
    F: EccPrimeField,
    T: InCircuitPartialHash<F>,
{
    let max_parts = assigned.max_parts();
    range.check_less_than_safe(ctx, num_parts, max_parts as u64);
    var_len_poseidon_no_len_check(
        ctx,
        domain_tag,
        range.gate(),
        num_parts,
        assigned,
    )
}

/// Computes the poseidon hash of `assigned[..num_parts]`.
///
/// # Note
///
/// `num_parts` must be constrained to be smaller than `assigned.max_parts()`.
pub fn var_len_poseidon_no_len_check<F, T>(
    ctx: &mut Context<F>,
    domain_tag_str: Option<&str>,
    chip: &GateChip<F>,
    num_parts: AssignedValue<F>,
    assigned: &T,
) -> AssignedValue<F>
where
    F: EccPrimeField,
    T: InCircuitPartialHash<F>,
{
    let empty: &[AssignedValue<F>] = &[];
    var_len_poseidon_no_len_check_with_extra_terms(
        ctx,
        domain_tag_str,
        chip,
        num_parts,
        assigned,
        &empty,
    )
}

/// Computes the poseidon hash of `assigned[..num_parts] || extra_terms`.
///
/// # Note
///
/// `num_parts` must be constrained to be smaller than `assigned.max_parts()`.
pub fn var_len_poseidon_no_len_check_with_extra_terms<F, T, S>(
    ctx: &mut Context<F>,
    domain_tag_str: Option<&str>,
    chip: &GateChip<F>,
    num_parts: AssignedValue<F>,
    assigned: &T,
    extra_terms: &S,
) -> AssignedValue<F>
where
    F: EccPrimeField,
    T: InCircuitPartialHash<F>,
    S: FieldElementRepresentation<F>,
{
    let max_parts = assigned.max_parts();
    assert!(max_parts > 0, "Max parts can't be zero");
    // `PoseidonHasher` absorbs the field elements in `POSEIDON_R`-sized chunks.
    // For possible number of parts, we compute how many chunks `PoseidonHasher` would
    // be absorbing (more precisely, the corresponding chunk indices), as well as the
    // remainder, i.e., how many extra field elements are there which wouldn't fill a chunk.
    let number_of_elements = (0..max_parts)
        .map(|parts| {
            assigned.parts_to_num_elements(parts)
                + 1 // we hash the length
                + (domain_tag_str.is_some() as usize)
        })
        .collect_vec();
    let (chunk_indices, remainder_lens): (Vec<_>, Vec<_>) = number_of_elements
        .iter()
        .map(|num_elts| (num_elts / POSEIDON_R, num_elts % POSEIDON_R))
        .unzip();
    // Let's now check that all remainder lengths coincide. We only accept the case where they are
    // all the same. This function could be generalized to accept mixed cases, but that would involve
    // extra complexity (and extra constraints) which we don't need for the UBV circuit.
    let remainder_len = remainder_lens[0];
    assert!(
        remainder_lens.iter().all(|rem| rem == &remainder_len),
        "Variable length poseidon requires all remainders to be of the same length"
    );
    // We also check that the chunk indices form a strictly increasing sequence (in particular,
    // this ensures that there are no repeated values).
    assert!(
        chunk_indices.windows(2).all(|w| w[0] < w[1]),
        "Chunk indices must be strictly increasing"
    );
    // After the above check, we compute now the remainders, accounting for
    // the domain tag, if present.
    let mut assigned_representation = vec![];

    let domain_tag = domain_tag_str.map(|t| assigned_domain_tag(ctx, t));
    if let Some(assigned_domain_tag) = domain_tag {
        assigned_representation.push(assigned_domain_tag);
    }
    assigned_representation.push(num_parts);
    assigned_representation.extend(assigned.representation());

    let remainders = number_of_elements
        .iter()
        .map(|num_elts| {
            (num_elts - remainder_len..*num_elts)
                .into_iter()
                .map(|i| {
                    *assigned_representation.get(i).unwrap_or_else(|| {
                        panic!("Retrieving the {i}-th element is not allowed to fail")
                    })
                })
                .collect_vec()
        })
        .collect_vec();
    // Instantiate the hasher and absorb all elements.
    let mut hasher = PoseidonHasher::new_with_domain_tag(ctx, chip, domain_tag);
    hasher.absorb(&num_parts);
    hasher.absorb(assigned);
    // Retrieve all intermediate states (after the absorption of each chunk).
    let (intermediate_states, is_remainder_len_zero) =
        hasher.poseidon.intermediate_states(ctx, chip);
    // is_remainder_len_zero is true when there are no remainders after the final chunk.
    // Let's double check it's consistent with `remainder_len`.
    assert_eq!(
        is_remainder_len_zero,
        remainder_len == 0,
        "Inconsistent remainder values"
    );
    // Take only the states with the relevant chunk indexes. Note that these
    // indices are given by type T's implementation of `InCircuitPartialHash`,
    // so they don't need to be selected in-circuit: they are constant and don't
    // depend on `num_parts`.
    let intermediate_states = intermediate_states
        .into_iter()
        .enumerate()
        .filter(|(index, _)| chunk_indices.contains(index))
        .map(|(_, state)| state.to_vec())
        .collect_vec();
    // Compute the `num_parts`-th bit bitmask.
    let bitmask = ith_bit_bitmask(ctx, chip, num_parts, max_parts as u64);
    // Select the right intermediate state
    let state = select_with_bitmask(ctx, chip, &bitmask, intermediate_states);
    let state = state.try_into().expect("Conversion not allowed to fail");
    // Return the final value
    let mut second_hasher = PoseidonHasher::new_with_state(state, chip);
    let extra_terms = extra_terms.representation();
    match remainder_len + extra_terms.len() {
        // If we absorbed an exact multiple of `POSEIDON_R`, we need an extra
        // permutation before returning the state.
        0 => second_hasher.poseidon.permute_and_return_output(ctx, chip),
        // If not, we need to add the remainder.
        _ => {
            let mut remainder =
                select_with_bitmask(ctx, chip, &bitmask, remainders);
            remainder.extend(extra_terms);
            second_hasher.absorb(&&remainder[..]);
            second_hasher.squeeze(ctx)
        }
    }
}

/// Selects the right `elements` using `bitmask`.
///
/// # Note
///
/// The elements in `bitmask` must be constrained to be booleans.
fn select_with_bitmask<F: EccPrimeField>(
    ctx: &mut Context<F>,
    chip: &GateChip<F>,
    bitmask: &[AssignedValue<F>],
    elements: Vec<Vec<AssignedValue<F>>>,
) -> Vec<AssignedValue<F>> {
    assert_eq!(
        bitmask.len(),
        elements.len(),
        "Bitmask and elements length mismatch"
    );
    let inner_len = elements
        .first()
        .expect("elements must have at least one element")
        .len();
    assert!(
        elements
            .iter()
            .map(|element| element.len())
            .all(|length| length == inner_len),
        "All inner lists must have the same length"
    );
    let mut result = Vec::with_capacity(inner_len);
    for index in 0..inner_len {
        let elmts = elements.iter().map(|inner_vec| inner_vec[index]);
        let bits = bitmask.iter().map(|b| QuantumCell::<F>::from(*b));
        result.push(chip.inner_product(ctx, elmts, bits))
    }
    result
}

/// An object which can be absorbed by a PoseidonHasher
pub trait InCircuitHash<F: EccPrimeField> {
    fn hash(&self, hasher: &mut PoseidonHasher<F>);
}

/// Interface for types that can be represented as a vector of field elements
pub trait FieldElementRepresentation<F: EccPrimeField> {
    /// Returns the representation of `self` as assigned field elements.
    fn representation(&self) -> Vec<AssignedValue<F>>;

    /// Returns the total number of field elements in `self`.
    fn num_elements(&self) -> usize;
}

/// An object whose parts can be absorbed by a PoseidonHasher
pub trait InCircuitPartialHash<F: EccPrimeField>:
    InCircuitHash<F> + FieldElementRepresentation<F>
{
    /// Returns the maximum number of parts of `self`.
    ///
    /// # Note
    ///
    /// This function must depend on the type (and possibly a config parameter)
    /// and not on the object itself.
    fn max_parts(&self) -> usize;

    /// Absorbs the first `parts` of `self` into `hasher`.
    fn partial_hash(&self, parts: usize, hasher: &mut PoseidonHasher<F>);

    /// Returns the number of of field elements contained in `parts`.
    ///
    /// # Note
    ///
    /// This function must depend on the type (and possibly a config parameter)
    /// and not on the object itself.
    fn parts_to_num_elements(&self, parts: usize) -> usize;
}

/// (Trivial) InCircuitHash implementation for an assigned scalar field element.
impl<F: EccPrimeField> InCircuitHash<F> for AssignedValue<F> {
    fn hash(&self, hasher: &mut PoseidonHasher<F>) {
        hasher.poseidon.update(&[*self]);
    }
}

/// (Trivial) InCircuitHash implementation for assigned scalar field elements.
impl<F: EccPrimeField> InCircuitHash<F> for &[AssignedValue<F>] {
    fn hash(&self, hasher: &mut PoseidonHasher<F>) {
        hasher.poseidon.update(self);
    }
}

/// Absorb an in-circuit Fq element (FpChip::ReducedFieldPoint).  This must be
/// a Reduced<...> since that is the unique representation of the underlying
/// value.
impl<F: EccPrimeField, Fq> InCircuitHash<F> for Reduced<ProperCrtUint<F>, Fq> {
    fn hash(&self, hasher: &mut PoseidonHasher<F>) {
        hasher
            .poseidon
            .update(self.inner().as_ref().truncation.limbs.as_slice());
    }
}

/// Absorb an in-circuit element of an extension of Fq value.
impl<F: EccPrimeField, Fq> InCircuitHash<F>
    for FieldVector<Reduced<ProperCrtUint<F>, Fq>>
{
    fn hash(&self, hasher: &mut PoseidonHasher<F>) {
        for element in self.0.iter() {
            element.hash(hasher);
        }
    }
}

/// InCircuitHash implementation for EcPoint, allowing an EC point to be
/// directly absorbed into a sponge.
impl<F: EccPrimeField, FP: InCircuitHash<F>> InCircuitHash<F>
    for EcPoint<F, FP>
{
    fn hash(&self, hasher: &mut PoseidonHasher<F>) {
        self.x.hash(hasher);
        self.y.hash(hasher);
    }
}

impl<F: EccPrimeField> FieldElementRepresentation<F> for AssignedValue<F> {
    fn representation(&self) -> Vec<AssignedValue<F>> {
        vec![*self]
    }

    fn num_elements(&self) -> usize {
        1
    }
}

impl<F: EccPrimeField> FieldElementRepresentation<F> for &[AssignedValue<F>] {
    fn representation(&self) -> Vec<AssignedValue<F>> {
        self.to_vec()
    }

    fn num_elements(&self) -> usize {
        self.len()
    }
}

impl<F: EccPrimeField> FieldElementRepresentation<F> for ProperCrtUint<F> {
    fn representation(&self) -> Vec<AssignedValue<F>> {
        self.limbs().to_vec()
    }

    fn num_elements(&self) -> usize {
        self.limbs().len()
    }
}

impl<F: EccPrimeField> FieldElementRepresentation<F>
    for Reduced<ProperCrtUint<F>, Fq>
{
    fn representation(&self) -> Vec<AssignedValue<F>> {
        self.inner().representation()
    }

    fn num_elements(&self) -> usize {
        self.inner().num_elements()
    }
}

impl<F: EccPrimeField> FieldElementRepresentation<F>
    for FieldVector<Reduced<ProperCrtUint<F>, Fq>>
{
    fn representation(&self) -> Vec<AssignedValue<F>> {
        self.0
            .iter()
            .flat_map(|reduced| reduced.representation())
            .collect()
    }

    fn num_elements(&self) -> usize {
        self.0
            .get(0)
            .map_or(0, |elt| elt.num_elements() * self.0.len())
    }
}

impl<F, FieldPoint> FieldElementRepresentation<F> for EcPoint<F, FieldPoint>
where
    F: EccPrimeField,
    FieldPoint: FieldElementRepresentation<F>,
{
    fn representation(&self) -> Vec<AssignedValue<F>> {
        [self.x.representation(), self.y.representation()].concat()
    }

    fn num_elements(&self) -> usize {
        self.x.num_elements() + self.y.num_elements()
    }
}

/// A native implementation of the in-circuit hashing for non-native field
/// elements and curve points.  Wraps the native Poseidon sponge trivially, so
/// callers can access the underlying `self.hasher` in order to absorb native
/// field elements or other types, and to squeeze. We use the term "wrong
/// field" instead of non-native to avoid confusion between in-circuit and
/// native code.
pub struct WrongFieldHasher<'a, C1: CurveAffineExt, C2: CurveAffineExt>
where
    C1::ScalarExt: EccPrimeField,
{
    pub circuit_config: &'a CircuitWithLimbsConfig,
    pub hasher:
        poseidon_native::Poseidon<C1::ScalarExt, POSEIDON_T, POSEIDON_R>,
    _phantom: PhantomData<C2>,
}

impl<'a, C1: CurveAffineExt, C2: CurveAffineExt> WrongFieldHasher<'a, C1, C2>
where
    C1::ScalarExt: EccPrimeField,
    C1::Base: EccPrimeField,
{
    pub fn new(
        circuit_config: &'a CircuitWithLimbsConfig,
        domain_tag_str: Option<&str>,
    ) -> Self {
        let mut hasher = WrongFieldHasher {
            circuit_config,
            hasher: poseidon_native::Poseidon::new(POSEIDON_R_F, POSEIDON_R_P),
            _phantom: PhantomData,
        };
        if let Some(domain_tag_str) = domain_tag_str {
            let domain_tag: C1::ScalarExt =
                digest_to_field_element(&compute_domain_tag(domain_tag_str));
            hasher.hasher.update(&[domain_tag]);
        }

        hasher
    }

    pub fn absorb_fq(&mut self, fq: &C1::Base) {
        let fq_bi = fe_to_biguint(fq);
        let fq_limbs = decompose_biguint(
            &fq_bi,
            self.circuit_config.num_limbs,
            self.circuit_config.limb_bits,
        );

        self.hasher.update(&fq_limbs);
    }

    pub fn absorb_fqe<
        const DEGREE: usize,
        Fqe: FieldExtConstructor<C1::Base, DEGREE>,
    >(
        &mut self,
        fqe: &Fqe,
    ) {
        for fq in fqe.coeffs() {
            self.absorb_fq(&fq);
        }
    }

    pub fn absorb_g1(&mut self, g: &C1) {
        let coords = g.coordinates().expect("invalid coords");
        self.absorb_fq(coords.x());
        self.absorb_fq(coords.y());
    }

    pub fn absorb_g2<const DEGREE: usize>(&mut self, g: &C2)
    where
        C2::Base: FieldExtConstructor<C1::Base, DEGREE>,
    {
        let coords = g.coordinates().expect("invalid coords");
        self.absorb_fqe(coords.x());
        self.absorb_fqe(coords.y());
    }
}
