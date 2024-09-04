//! Keccak circuit chip
//!
//! Code derived from [axiom-eth](https://github.com/axiom-crypto/axiom-eth)
//! Licensed under the MIT License.

extern crate alloc;

use crate::{
    keccak::{
        multivar::KeccakMultiVarHasher, utils::bytes_to_keccak_padded_words,
        variable, KECCAK_OUTPUT_BYTES,
    },
    utils::bitmask::ith_bit_bitmask,
    EccPrimeField,
};
use alloc::collections::BTreeMap;
use core::{cmp::max, mem};
use ethers_core::utils::keccak256;
use halo2_base::{
    gates::{
        builder::{
            assign_threads_in, GateThreadBuilder, KeygenAssignments,
            MultiPhaseThreadBreakPoints,
        },
        flex_gate::FlexGateConfig,
        GateInstructions, RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        circuit::{self, Region},
        plonk::{Advice, Column},
    },
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;
use rayon::prelude::*;
use std::collections::HashMap;
use tiny_keccak::{Hasher, HasherExt, Keccak};
use zkevm_keccak::{
    keccak_packed_multi::{
        get_num_keccak_f, get_num_rows_per_round, keccak_phase0_with_flags,
        KeccakRow,
    },
    util::{
        eth_types::Field, NUM_BYTES_PER_WORD, NUM_BYTES_TO_SQUEEZE, NUM_ROUNDS,
        NUM_WORDS_TO_ABSORB, NUM_WORDS_TO_SQUEEZE, RATE,
    },
    KeccakConfig,
};

/// Fixed length output cells
///
/// The key of the [`BTreeMap`] below is a pair consisting of
/// `(query_index, byte_index)`. The value is the
/// cell containing the output bytes.
///
/// The cells in the vector contain the input words, in order.
type FixedLenCells =
    (BTreeMap<(usize, usize), circuit::Cell>, Vec<circuit::Cell>);

/// Variable length output cells
///
/// The key of the [`BTreeMap`] below is a triple consisting of
/// `(query_index, chunk_index, byte_index)`. The value is the
/// cell containing the output bytes.
///
/// The cells in the vector contain the input words, in order.
type VarLenCells = (
    BTreeMap<(usize, usize, usize), circuit::Cell>,
    Vec<circuit::Cell>,
);

/// Keccak Row Data.
///
/// This type encodes the rows corresponding to a list of queries,
/// as well as the hashmaps with the relative positions of the output cells and
/// the input words.
type KeccakRowData<F> = Vec<(
    bool,
    Vec<KeccakRow<F>>,
    HashMap<(usize, usize), (usize, usize)>,
    HashMap<usize, usize>,
)>;

/// Keccak fixed length query
#[derive(Clone, Debug)]
pub struct KeccakFixedLenQuery<F: Field> {
    /// Input bytes
    input_bytes: Vec<u8>,
    /// Assigned input bytes
    input_bytes_assigned: Vec<AssignedValue<F>>,
    /// Input words
    input_words_assigned: Vec<AssignedValue<F>>,
    /// Output bytes
    #[allow(dead_code)]
    // This output byte representation can be handy for testing and debugging.
    output_bytes: [u8; NUM_BYTES_TO_SQUEEZE],
    /// Assigned output bytes
    output_bytes_assigned: Vec<AssignedValue<F>>,
}

impl<F: Field> KeccakFixedLenQuery<F> {
    /// Returns the output bytes.
    pub fn output_bytes_assigned(&self) -> &[AssignedValue<F>] {
        &self.output_bytes_assigned
    }
}

/// Keccak variable length query
#[derive(Clone, Debug)]
pub struct KeccakVarLenQuery<F: Field> {
    /// Number of bytes
    num_bytes: usize,
    /// Input bytes
    input_bytes: Vec<u8>,
    /// Assigned input bytes
    input_bytes_assigned: Vec<AssignedValue<F>>,
    /// Input words
    input_words_assigned: Vec<AssignedValue<F>>,
    /// Output bytes
    #[allow(dead_code)]
    // This output byte representation can be handy for testing and debugging.
    output_bytes: [u8; NUM_BYTES_TO_SQUEEZE],
    /// Assigned output bytes.
    ///
    /// These are the actual output bytes of the keccak query. We compute them from `output_bytes_vec`
    /// via scalar product by the chunk bitmask (see [`keccak_var_len`](KeccakChip::keccak_var_len)).
    output_bytes_assigned: Vec<AssignedValue<F>>,
    /// Output bytes vector
    ///
    /// The `i`-th inner vector in output_vec corresponds to the output bytes of keccak'ing, without padding,
    /// the first `i` chunks, where each chunk is [`RATE`] bytes.
    /// These will then be copy-constrained 1-to-1 to the cells coming from the
    /// the [`assign_keccak_cells`](KeccakChip::assign_keccak_cells) function.
    output_bytes_vec: Vec<Vec<AssignedValue<F>>>,
}

impl<F: Field> KeccakVarLenQuery<F> {
    /// Returns the 32 output bytes of the query.
    pub fn output_bytes_assigned(&self) -> &[AssignedValue<F>] {
        &self.output_bytes_assigned
    }

    /// Returns the maximum length of `self`, in bytes.
    pub fn max_len(&self) -> usize {
        self.input_bytes_assigned.len()
    }

    /// Returns the number of bytes of `self` used to compute the keccak hash.
    pub fn num_bytes(&self) -> usize {
        self.num_bytes
    }
}

/// Keccak Chip.
///
/// # Note
///
/// [`KeccakChip`] plays the role both of the chip and something like a `KeccakThreadBuilder` in that it keeps a
/// list of the keccak queries that need to be linked with the external zkEVM keccak chip.
#[derive(Clone, Debug)]
pub struct KeccakChip<F: Field> {
    pub(crate) num_rows_per_round: usize,
    /// Fixed length queries
    fixed_len_queries: Vec<KeccakFixedLenQuery<F>>,
    /// Variable length queries
    var_len_queries: Vec<KeccakVarLenQuery<F>>,
}

impl<F: Field> Default for KeccakChip<F> {
    fn default() -> Self {
        Self::new(get_num_rows_per_round())
    }
}

impl<F: Field> KeccakChip<F> {
    /// Creates an empty [`KeccakChip`] with `num_rows_per_round`.
    pub fn new(num_rows_per_round: usize) -> Self {
        Self {
            num_rows_per_round,
            fixed_len_queries: vec![],
            var_len_queries: vec![],
        }
    }

    /// Returns the fixed length queries.
    pub fn fixed_len_queries(&self) -> &[KeccakFixedLenQuery<F>] {
        &self.fixed_len_queries
    }

    /// Returns the variable length queries.
    pub fn var_len_queries(&self) -> &[KeccakVarLenQuery<F>] {
        &self.var_len_queries
    }

    /// Returns the total number of Keccak-f permutations needed to
    /// compute all this chip's queries.
    pub(super) fn total_keccak_perms(&self) -> usize {
        self.fixed_len_queries
            .iter()
            .map(|q| q.input_bytes_assigned.len())
            .chain(
                self.var_len_queries
                    .iter()
                    .map(|q| q.input_bytes_assigned.len()),
            )
            .map(get_num_keccak_f)
            .sum()
    }

    /// Takes a byte vector of known fixed length and computes the keccak digest of `input_assigned`.
    /// - Updates `self` with `(output_assigned, output_bytes)`, where `output_bytes` is provided just for convenience.
    /// - This function only computes witnesses for output bytes.
    ///
    /// # Specification
    ///
    /// This function performs **Steps 1-3 of Fixed-Length Query**
    /// in the variable length keccak spec.
    pub fn keccak_fixed_len(
        &mut self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        input_bytes_assigned: Vec<AssignedValue<F>>,
    ) {
        // Step 1
        // Convert bytes to words (in circuit), required by Keccak rows
        let input_words_assigned =
            bytes_to_keccak_padded_words(ctx, range, &input_bytes_assigned);

        // Step 2
        // Get input bytes as values, natively compute the correct output bytes and create cells with this assignment.
        // These will later be constrained to the correct cells from the Keccak computation.
        let input_bytes = get_assigned_bytes_values(&input_bytes_assigned[..]);
        let output_bytes = keccak256(&input_bytes);
        // Step 3
        let output_bytes_assigned = ctx.assign_witnesses(
            output_bytes
                .iter()
                .map(|b| range.gate.get_field_element(*b as u64)),
        );
        // Update the chip. Later we will copy-constrain `input_words_assigned` and
        // `output_bytes_assigned` to the corresponding keccak cells, effectively
        // enforcing that `keccak(input_bytes_assigned) = output_bytes_assigned`.
        self.fixed_len_queries.push(KeccakFixedLenQuery {
            input_bytes,
            input_bytes_assigned,
            input_words_assigned,
            output_bytes,
            output_bytes_assigned,
        });
    }

    /// Computes the keccak digest of `input_bytes_assigned[..len]`.
    /// - Updates `self` with `(output_assigned, output_bytes)`, where `output_bytes` is provided just for convenience.
    /// - This function only computes witnesses for output bytes.
    ///
    /// Note that the length of `input_bytes_assigned` determines the max input length for
    /// the query, and must therefore be the same length at keygen and proving time (i.e. padded
    /// if necessary). This padding doesn't get constrained in the function.
    /// The `len` assigned value determines the number of bytes to be input into the
    /// keccak algorithm for a particular instance.
    ///
    /// Constrains `min_len <= len <= bytes.len()`.
    ///
    /// # Specification
    ///
    /// This function performs **Steps 1-7 of Variable-Length Query**
    /// in the variable length keccak spec.
    pub fn keccak_var_len(
        &mut self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        input_bytes_assigned: Vec<AssignedValue<F>>,
        byte_len: AssignedValue<F>,
    ) {
        // Step 1: constrain len to be `<= max_len`
        let max_len = input_bytes_assigned.len();
        range.check_less_than_safe(ctx, byte_len, (max_len + 1) as u64);
        // Step 2: compute input words. These input words have the correct Keccak padding
        // based on `byte_len`, i.e., the first `byte_len` bytes are derived from
        // `input_bytes_assigned` and then the remaining chunks are filled according to the
        // keccak padding algorithm.
        let input_words = variable::var_bytes_to_keccak_padded_words(
            ctx,
            range,
            input_bytes_assigned.clone(),
            byte_len,
        );
        // Step 3: Correct input bytes in query (out-of-circuit)
        let input_byte_values = variable::bytes_from_words(&input_words);
        // Steps 4 + 5: Compute and assign cells for all intermediate keccak output bytes
        // `bytes_len`` will be used to select the correct set of these intermediate output
        // bytes. Later, each intermediate output will be constrained to the output of keccak
        // permutations for each chunk.
        let keccak_outputs_assigned = self
            .compute_intermediate_keccak_output_bytes_assigned(
                ctx,
                range,
                &input_byte_values,
            );
        // Step 6: Select right intermediate keccak output corresponding to the chunk of interest.
        let output_assigned = self.select_true_outputs(
            ctx,
            range,
            &keccak_outputs_assigned,
            byte_len,
            max_len,
            input_byte_values.len(),
        );
        // Compute true output bytes (out of circuit)
        let byte_len_val = byte_len.value().get_lower_32() as usize;
        let output_bytes = keccak256(&input_byte_values[..byte_len_val]);
        // Step 7: This is the input to the keccak function. In order to prevent
        // double-padding, we need to unpad the input bytes
        let unpadded_input_byte_values =
            variable::remove_padded_bytes(&input_byte_values).to_vec();
        // Sanity check the result of selecting against the expected value `output_bytes`.
        // This only checks - it does not create any constraints.
        self.assert_var_len_keccak_correctness(
            &output_bytes,
            &output_assigned,
            input_byte_values.len(),
            unpadded_input_byte_values.len(),
            byte_len_val,
            max_len,
        );
        // Schedule the keccak calculation that constrains the intermediate keccak
        // output bytes `keccak_outputs_assigned` to be the output from the keccak permutations.
        self.var_len_queries.push(KeccakVarLenQuery {
            num_bytes: byte_len_val,
            input_bytes: unpadded_input_byte_values,
            input_bytes_assigned,
            input_words_assigned: input_words,
            output_bytes,
            output_bytes_assigned: output_assigned,
            output_bytes_vec: keccak_outputs_assigned,
        });
    }

    /// Compute digest of a fixed length input and multiple variable length inputs.
    /// Fixed inputs must already be constrained to byte values. Variable length
    /// inputs must be flattened limb decompositions of vectors of Fq elements,
    /// each encoded as `NUM_LIMBS` F elements.
    ///
    /// # Note:
    ///
    /// Circuit will not be satisfiable if the total
    /// meaningful input length in bytes (fixed length plus non-padding
    /// bytes of each var input) is not a multiple of 8. A multiple of
    /// 32 bytes will be extracted from the variable inputs, so the requirement
    /// is that the fixed input length be a multiple of 8 bytes.
    pub fn multi_var_query(
        &mut self,
        ctx: &mut Context<F>,
        range_chip: &RangeChip<F>,
        fixed_input: Vec<AssignedValue<F>>,
        // The padded variable length inputs
        var_inputs: Vec<Vec<AssignedValue<F>>>,
        // The number of non-native limbs to absorb from each var length input
        var_input_lengths: Vec<AssignedValue<F>>,
    ) -> Vec<AssignedValue<F>> {
        assert_eq!(
            fixed_input.len() % 8,
            0,
            "Fixed input length must be a multiple of 8 bytes"
        );
        let mut hasher = KeccakMultiVarHasher::new();
        hasher.absorb_fixed(&fixed_input);
        for (input, len) in var_inputs.iter().zip_eq(&var_input_lengths) {
            hasher.absorb_var(input, *len);
        }

        hasher.finalize(ctx, range_chip, self)
    }

    /// Computes the output bytes from each keccak round (i.e. the output after processing each chunk of padded input data).
    /// The correct set of output bytes must be selected depending on the query length.
    /// For now, these values are just assigned to cells.  These cells will later be copy-constrained
    /// to the output bytes of [`assign_keccak_cells`](Self::assign_keccak_cells).
    ///
    /// # Specification
    ///
    /// This function performs **Steps 4+5 of Variable-Length Query**
    /// in the variable length keccak spec.
    fn compute_intermediate_keccak_output_bytes_assigned(
        &self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        input_bytes: &[u8],
    ) -> Vec<Vec<AssignedValue<F>>> {
        let max_input_bytes_length_after_padding = input_bytes.len();
        let max_number_of_chunks = max_input_bytes_length_after_padding / RATE;
        let mut keccak_outputs_assigned =
            Vec::with_capacity(max_number_of_chunks);
        for idx in 0..max_number_of_chunks {
            let output_bytes =
                keccak256_no_padding(&input_bytes[..(idx + 1) * RATE]);
            let output_assigned = ctx.assign_witnesses(
                output_bytes
                    .iter()
                    .map(|b| range.gate().get_field_element(*b as u64)),
            );
            keccak_outputs_assigned.push(output_assigned);
        }
        keccak_outputs_assigned
    }

    /// Selects the right output from `keccak_outputs_assigned`, with the selection based
    /// on how many [`RATE`]-len chunks `byte_len` covers.
    ///
    /// # Specification
    ///
    /// This function performs **Step 6 of Variable-Length Query**
    /// in the variable length keccak spec.
    fn select_true_outputs(
        &self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak_outputs_assigned: &[Vec<AssignedValue<F>>],
        byte_len: AssignedValue<F>,
        max_len: usize,
        max_input_bytes_length_after_padding: usize,
    ) -> Vec<AssignedValue<F>> {
        // Compute chunk bitmask. This bitmask has `max_number_of_chunks` bits
        // with a 1 in the `last_chunk_index`-th position (starting the index from 0)
        // and zeroes everywhere else. `last_chunk_index` is derived from `byte_len`
        // by computing how many RATE-len chunks `byte_len` fills.
        let max_number_of_chunks = max_input_bytes_length_after_padding / RATE;
        let last_chunk_index = variable::byte_len_to_last_chunk_index(
            ctx, range, byte_len, max_len,
        );
        let bitmask = ith_bit_bitmask(
            ctx,
            &range.gate,
            last_chunk_index,
            max_number_of_chunks as u64,
        );
        // Select the right one
        let mut output_assigned = Vec::with_capacity(KECCAK_OUTPUT_BYTES);
        for byte_idx in 0..KECCAK_OUTPUT_BYTES {
            let bytes = keccak_outputs_assigned
                .iter()
                .map(|output_assigned| output_assigned[byte_idx].into());
            let bits = bitmask.iter().map(|b| QuantumCell::<F>::from(*b));
            let output_byte = range.gate().inner_product(ctx, bits, bytes);
            output_assigned.push(output_byte);
        }
        output_assigned
    }

    /// Checks that the chip has executed [`keccak_var_len`](Self::keccak_var_len)
    /// correctly. This function should be called before updating the chip inner state.
    fn assert_var_len_keccak_correctness(
        &self,
        output_bytes: &[u8],
        output_assigned: &[AssignedValue<F>],
        max_input_bytes_length_after_padding: usize,
        unpadded_input_bytes_length: usize,
        byte_len_val: usize,
        max_len: usize,
    ) {
        assert!(max_len < max_input_bytes_length_after_padding);
        assert!(max_len >= byte_len_val);
        assert_eq!(byte_len_val % NUM_BYTES_PER_WORD, 0);
        assert_eq!(max_input_bytes_length_after_padding % RATE, 0);
        assert_eq!(
            output_bytes.to_vec(),
            get_assigned_bytes_values(output_assigned)
        );
        assert_eq!(
            unpadded_input_bytes_length,
            max((max_len / RATE) * RATE, byte_len_val)
        );
    }

    /// Produces [`KeccakRowData`] from the queries in `self`. Keccak Row Data consist of the keccak rows
    /// together with two hashmaps with the positions of the output bytes and the input words in
    /// those rows, respectively.
    ///
    /// # Specification
    ///
    /// This function performs **Step 4 of Fixed-Length Query** or **Step 8 of Variable-Length Query**
    /// in the variable length keccak spec.
    fn produce_keccak_row_data(&self, is_fixed: bool) -> KeccakRowData<F> {
        let queries = match is_fixed {
            true => self
                .fixed_len_queries
                .par_iter()
                .map(|query| &query.input_bytes)
                .collect(),
            false => self
                .var_len_queries
                .par_iter()
                .map(|query| &query.input_bytes)
                .collect::<Vec<_>>(),
        };
        queries
            .into_par_iter()
            .map(|input_bytes| {
                let num_keccak_f = get_num_keccak_f(input_bytes.len());
                let mut _unused = Vec::with_capacity(num_keccak_f);
                let mut rows = Vec::with_capacity(
                    num_keccak_f * (NUM_ROUNDS + 1) * self.num_rows_per_round,
                );
                let mut output_bytes_positions = HashMap::new();
                let mut input_words_positions = HashMap::new();
                keccak_phase0_with_flags(
                    &mut rows,
                    &mut _unused,
                    &mut output_bytes_positions,
                    &mut input_words_positions,
                    input_bytes,
                );
                (
                    is_fixed,
                    rows,
                    output_bytes_positions,
                    input_words_positions,
                )
            })
            .collect::<Vec<_>>()
    }

    /// Assigns cells in `region` for the keccak queries in `self`. Returns a [`BTreeMap`]
    /// with the cells where the Keccak output bytes are assigned, and a vector with
    /// the cells where the input words are assigned, for both the fixed length and variable length
    /// keccak queries.
    pub fn assign_keccak_cells(
        &self,
        region: &mut Region<F>,
        zkevm_keccak: &KeccakConfig<F>,
    ) -> (FixedLenCells, VarLenCells) {
        let mut num_rows_used = 0;
        // Dummy first rows so that the initial data is absorbed
        // The initial data doesn't really matter, `is_final` just needs to be disabled.
        for (idx, row) in KeccakRow::dummy_rows(self.num_rows_per_round)
            .iter()
            .enumerate()
        {
            zkevm_keccak.set_row(region, idx, row);
        }
        num_rows_used += self.num_rows_per_round;
        // Generate witnesses for the fixed length queries first since there's no issue of selection
        let keccak_row_data_fixed = self.produce_keccak_row_data(true);
        let keccak_row_data_var = self.produce_keccak_row_data(false);
        // Write the keccak rows in the region and expose the public outputs
        let mut fixed_output_bytes_cells = BTreeMap::new();
        let mut fixed_input_words_cells = Vec::new();
        let mut var_output_bytes_cells = BTreeMap::new();
        let mut var_input_words_cells = Vec::new();
        for (
            query_idx,
            (is_fixed, rows, output_bytes_positions, input_words_positions),
        ) in keccak_row_data_fixed
            .into_iter()
            .chain(keccak_row_data_var.into_iter())
            .enumerate()
        {
            let number_of_rows = rows.len();
            assert_eq!(
                number_of_rows % ((NUM_ROUNDS + 1) * self.num_rows_per_round),
                0
            );
            let number_of_chunks =
                number_of_rows / ((NUM_ROUNDS + 1) * self.num_rows_per_round);
            for (row_index, row) in rows.into_iter().enumerate() {
                // Compute chunk index from the round index
                let chunk_idx =
                    row_index / ((NUM_ROUNDS + 1) * self.num_rows_per_round);
                let is_last_chunk = chunk_idx == number_of_chunks - 1;
                // If an index is flagged, it means it is the relative position of an output byte
                // in a query, so we have to add its cell location to `output_bytes_cells`.
                if let Some((col_index, byte_index)) =
                    output_bytes_positions.get(&(chunk_idx, row_index))
                {
                    assert!(
                        byte_index < &(8 * NUM_WORDS_TO_SQUEEZE),
                        "Byte index out of range"
                    );
                    if is_fixed {
                        if is_last_chunk {
                            // Returns the assigned cell at the flagged index
                            let new_assigned_values = zkevm_keccak
                                .set_row_with_flags(
                                    region,
                                    num_rows_used,
                                    &row,
                                    &[*col_index],
                                );
                            // Insert the assigned cell into the BTreeMap with the cells we want to expose
                            fixed_output_bytes_cells.insert(
                                (query_idx, *byte_index),
                                new_assigned_values[0].clone(),
                            );
                        } else {
                            zkevm_keccak.set_row(region, num_rows_used, &row);
                        }
                    } else {
                        // Returns the assigned cell at the flagged index
                        let new_assigned_values = zkevm_keccak
                            .set_row_with_flags(
                                region,
                                num_rows_used,
                                &row,
                                &[*col_index],
                            );

                        // Insert the assigned cell into the BTreeMap. The key consists of
                        // query index, chunk index and byte index.
                        var_output_bytes_cells.insert(
                            (query_idx, chunk_idx, *byte_index),
                            new_assigned_values[0].clone(),
                        );
                    }
                }
                // If an index is flagged, it means it is the relative position of an input word
                // in a query, so we have to add its cell location to `fixed_input_words_cells`
                // or `var_input_words_cells`.
                else if let Some(col_index) =
                    input_words_positions.get(&row_index)
                {
                    let new_assigned_words = zkevm_keccak.set_row_with_flags(
                        region,
                        num_rows_used,
                        &row,
                        &[*col_index],
                    );
                    if is_fixed {
                        fixed_input_words_cells
                            .push(new_assigned_words[0].clone());
                    } else {
                        var_input_words_cells
                            .push(new_assigned_words[0].clone())
                    }
                } else {
                    zkevm_keccak.set_row(region, num_rows_used, &row);
                }
                num_rows_used += 1;
            }
        }
        // Deref the flagged cells and return the results
        (
            (
                fixed_output_bytes_cells
                    .into_iter()
                    .map(|(index, acell)| (index, *acell.cell()))
                    .collect(),
                fixed_input_words_cells
                    .into_iter()
                    .map(|acell| *acell.cell())
                    .collect(),
            ),
            (
                var_output_bytes_cells
                    .into_iter()
                    .map(|(index, acell)| (index, *acell.cell()))
                    .collect(),
                var_input_words_cells
                    .into_iter()
                    .map(|acell| *acell.cell())
                    .collect(),
            ),
        )
    }

    /// Returns the cells in `assignments` which contain the output byte vectors in `self`.
    fn extract_var_output_byte_vecs<'a>(
        &'a self,
        assignments: &'a KeygenAssignments<F>,
    ) -> impl 'a + IntoIterator<Item = circuit::Cell> {
        self.var_len_queries.iter().flat_map(|query| {
            query
                .output_bytes_vec
                .iter()
                .flatten()
                .map(|assigned_value| {
                    assigned_cell_from_assigned_value(
                        assigned_value,
                        assignments,
                    )
                })
        })
    }

    /// Returns the cells in `assignments` which contain the variable length queries
    /// input words in `self`.
    fn extract_var_input_words<'a>(
        &'a self,
        assignments: &'a KeygenAssignments<F>,
    ) -> impl 'a + IntoIterator<Item = circuit::Cell> {
        self.var_len_queries
            .iter()
            .flat_map(|query| &query.input_words_assigned)
            .map(|word| assigned_cell_from_assigned_value(word, assignments))
    }

    /// Returns the cells in `assignments` which contain the fixed length queries
    /// output bytes in `self`.
    fn extract_fixed_output_bytes<'a>(
        &'a self,
        assignments: &'a KeygenAssignments<F>,
    ) -> impl 'a + IntoIterator<Item = circuit::Cell> {
        self.fixed_len_queries
            .iter()
            .flat_map(|query| &query.output_bytes_assigned)
            .map(|byte| assigned_cell_from_assigned_value(byte, assignments))
    }

    /// Returns the cells in `assignments` which contain the fixed length queries
    /// input words in `self`.
    fn extract_fixed_input_words<'a>(
        &'a self,
        assignments: &'a KeygenAssignments<F>,
    ) -> impl 'a + IntoIterator<Item = circuit::Cell> {
        self.fixed_len_queries
            .iter()
            .flat_map(|query| &query.input_words_assigned)
            .map(|word| assigned_cell_from_assigned_value(word, assignments))
    }

    /// Constrains the context cells in `assignments` related to the variable length queries
    /// in `self` to be equal to the cells in `var_len_cells`.
    ///
    /// # Specification
    ///
    /// This function performs **Step 9 of Variable-Length Queries**
    /// in the variable length keccak spec.
    pub fn constrain_var_queries(
        &self,
        region: &mut Region<F>,
        assignments: &KeygenAssignments<F>,
        var_len_cells: &VarLenCells,
    ) {
        let (var_keccak_bytes_out, var_input_words) = var_len_cells;
        // The cells below are ordered by (see the `VarLenCells` type):
        // 1) query index
        // 2) chunk index
        // 3) byte index
        for (chip_cell, keccak_cell) in self
            .extract_var_output_byte_vecs(assignments)
            .into_iter()
            .zip_eq(var_keccak_bytes_out.values())
        {
            region.constrain_equal(&chip_cell, keccak_cell);
        }
        for (chip_cell, keccak_cell) in self
            .extract_var_input_words(assignments)
            .into_iter()
            .zip_eq(var_input_words.iter())
        {
            region.constrain_equal(&chip_cell, keccak_cell);
        }
    }

    /// Constrains the context cells in `assignments` related to the fixed length queries
    /// in `self` to be equal to the cells in `fixed_len_cells`.
    ///
    /// # Specification
    ///
    /// This function performs **Step 5 of Fixed-Length Query**
    /// in the variable length keccak spec.
    pub fn constrain_fixed_queries(
        &self,
        region: &mut Region<F>,
        assignments: &KeygenAssignments<F>,
        fixed_len_cells: &FixedLenCells,
    ) {
        let (fixed_keccak_bytes_out, fixed_input_words) = fixed_len_cells;
        // The cells below are ordered by (see the `FixedLenCells` type):
        // 1) query index
        // 2) byte index
        // Note only the last chunk for each query is considered
        for (chip_cell, keccak_cell) in self
            .extract_fixed_output_bytes(assignments)
            .into_iter()
            .zip_eq(fixed_keccak_bytes_out.values())
        {
            region.constrain_equal(&chip_cell, keccak_cell);
        }
        for (chip_cell, keccak_cell) in self
            .extract_fixed_input_words(assignments)
            .into_iter()
            .zip_eq(fixed_input_words.iter())
        {
            region.constrain_equal(&chip_cell, keccak_cell);
        }
    }
}

/// Extracts the cell in `assignments` containing `assigned_value`. Panics if the
/// cell is not assigned.
pub(crate) fn assigned_cell_from_assigned_value<F: Field>(
    assigned_value: &AssignedValue<F>,
    assignments: &KeygenAssignments<F>,
) -> circuit::Cell {
    let context_cell = assigned_value.cell.expect("Context cell not assigned");
    assignments
        .assigned_advices
        .get(&(context_cell.context_id, context_cell.offset))
        .expect("Cell not assigned")
        .0
}

/// Assigns the constraints in `builder` to `region`.
///
/// # Note
///
/// This function should be part of `synthesize` in prover mode.
pub fn assign_prover<F: EccPrimeField>(
    region: &mut Region<F>,
    gate: &FlexGateConfig<F>,
    lookup_advice: &[Vec<Column<Advice>>],
    builder: &mut GateThreadBuilder<F>,
    break_points: &mut MultiPhaseThreadBreakPoints,
) {
    // we only operate in phase 0
    const FIRST_PHASE: usize = 0;
    let break_points_gate = mem::take(&mut break_points[FIRST_PHASE]);
    let threads = mem::take(&mut builder.threads[FIRST_PHASE]);
    assign_threads_in(
        FIRST_PHASE,
        threads,
        gate,
        &lookup_advice[FIRST_PHASE],
        region,
        break_points_gate,
    );
    log::info!("End of FirstPhase");
}

/// Converts field values to bytes. Each field element in `bytes_assigned` must have at most 8 non-zero bits,
/// otherwise it panics.
pub(crate) fn get_assigned_bytes_values<F: EccPrimeField>(
    bytes_assigned: &[AssignedValue<F>],
) -> Vec<u8> {
    bytes_assigned
        .iter()
        .map(|abyte| {
            abyte
                .value()
                .get_lower_32()
                .try_into()
                .expect("Number out of range")
        })
        .collect_vec()
}

/// Computes the number of rows per round
pub(crate) fn rows_per_round(max_rows: usize, num_keccak_f: usize) -> u32 {
    log::info!("Number of keccak_f permutations: {num_keccak_f}");
    let rows_per_round =
        max_rows / (num_keccak_f * (NUM_ROUNDS + 1) + 1 + NUM_WORDS_TO_ABSORB);
    log::info!("Optimal keccak rows per round: {rows_per_round}");
    rows_per_round as u32
}

/// Computes the keccak hash of `bytes`, skipping the padding step.
fn keccak256_no_padding(bytes: &[u8]) -> [u8; KECCAK_OUTPUT_BYTES] {
    let mut output = [0u8; KECCAK_OUTPUT_BYTES];

    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize_no_padding(&mut output);

    output
}
