use crate::{
    keccak::{
        chip::KeccakChip, utils::multi_coordinates_to_bytes, NUM_BYTES_FQ,
        NUM_LIMBS,
    },
    EccPrimeField,
};
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    AssignedValue, Context, QuantumCell,
};

/// Upper bound on the bit size of the row index and length values.
const MAX_BIT_SIZE: usize = 32;

/// Keccak hasher that can absorb one fixed-length input and multiple
/// variable-length inputs. The variable-length inputs are assumed to
/// be limb decompositions of Fq points, each encoded as 3 non-native
/// limbs containing 11, 11, and 10 bytes of data, respectively.
pub(crate) struct KeccakMultiVarHasher<F: EccPrimeField> {
    /// Fixed length input, assumed to be bytes
    fixed_input: Vec<AssignedValue<F>>,
    /// Padded variable length inputs, assumed to be limb decompositions of Fq
    /// elements.  Note that the circuit does not constrain these to have
    /// lengths that are a multiple of the number of limbs.  The expectation
    /// is that the user either configures the circuit such that this
    /// constraint is naturally satisfied, or includes an explicit constraint
    /// on the length.
    var_inputs: Vec<Vec<AssignedValue<F>>>,
    /// The length of each variable length input, measured in F elements.
    var_input_lengths: Vec<AssignedValue<F>>,
}

impl<F: EccPrimeField<Repr = [u8; 32]>> KeccakMultiVarHasher<F> {
    pub(crate) fn new() -> Self {
        Self {
            fixed_input: Vec::new(),
            var_inputs: Vec::new(),
            var_input_lengths: Vec::new(),
        }
    }

    /// Absorb an input whose length is known at keygen time.
    /// These must be absorbed prior to any variable-length
    /// inputs. The input must already be constrained to byte values.
    pub(crate) fn absorb_fixed(&mut self, input: &[AssignedValue<F>]) {
        assert_eq!(
            self.var_inputs.len(),
            0,
            "Cannot absorb fixed after absorbing var."
        );
        self.fixed_input.extend_from_slice(input);
    }

    /// Absorb an input whose length is not known at keygen time. The
    /// input has been padded to a length which is known at keygen time,
    /// but only `input[0..len]` will be absorbed.
    ///
    /// Note: `len` is measured in number of F elements, so it will be
    /// `NUM_LIMBS` times the number of Fq elements in the input.
    pub(crate) fn absorb_var(
        &mut self,
        input: &[AssignedValue<F>],
        len: AssignedValue<F>,
    ) {
        // Expect input to be a limb decomposition of Fq points
        assert_eq!(input.len() % NUM_LIMBS, 0);
        assert_eq!(len.value().get_lower_32() % NUM_LIMBS as u32, 0);

        // `input.len` at keygen determines the maximum lengths supported by
        // the circuit.  Since the in-circuit constraint on length is
        // implemented as `less_than` over 32 bits, the length AND the bound
        // must be 32 bit numbers.  Hence `BOUND = (1 << MAX_BIT_SIZE) - 1`,
        // and `length < BOUND`.
        assert!(input.len() < (1 << MAX_BIT_SIZE) - 1, "input too long");

        self.var_inputs.push(input.to_vec());
        self.var_input_lengths.push(len);
    }

    /// Return the keccak digest of all inputs absorbed thus far.
    pub(crate) fn finalize(
        self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        keccak_chip: &mut KeccakChip<F>,
    ) -> Vec<AssignedValue<F>> {
        assert_eq!(self.var_inputs.len(), self.var_input_lengths.len());
        // Prepare preimage
        let (preimage, len) = self.prepare_preimage(ctx, range);

        // KeccakChip computes digest
        if self.is_fixed() {
            keccak_chip.keccak_fixed_len(ctx, range, preimage);
            return keccak_chip
                .fixed_len_queries()
                .last()
                .expect("no queries")
                .output_bytes_assigned()
                .to_vec();
        } else {
            keccak_chip.keccak_var_len(ctx, range, preimage, len);
            return keccak_chip
                .var_len_queries()
                .last()
                .expect("no queries")
                .output_bytes_assigned()
                .to_vec();
        }
    }

    /// Returns the preimage and its unpadded length in bytes. The preimage is
    /// `[self.fixed_input || var_input_0 || ... || var_input_n || PADDING]`
    /// where `var_input_i` refers to the bytes of the Fq elements encoded by the
    /// limbs in `self.var_inputs[i][0..len_i]` (see [multi_coordinates_to_bytes]).
    fn prepare_preimage(
        &self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
    ) -> (Vec<AssignedValue<F>>, AssignedValue<F>) {
        // Allocate a vector to hold the variable length input section of the preimage
        let var_preimage_len: usize = self
            .var_inputs
            .iter()
            .map(|x| {
                assert_eq!(x.len() % NUM_LIMBS, 0);
                x.len()
            })
            .sum();
        let mut preimage_var = Vec::with_capacity(var_preimage_len);
        let zero = ctx.load_constant(F::zero());
        for _ in 0..var_preimage_len {
            preimage_var.push(zero);
        }

        // Fill the variable length input section of the preimage

        // Tracks meaningful length of the variable length section, measured
        // in limbs.
        let mut offset_limbs = ctx.load_constant(F::zero());
        // Tracks sum of padded lengths of variable length inputs. This
        // is the maximum position in the variable section where a nonzero
        // value may appear.
        let mut max_nonzero_position = 0;
        for (input, len) in self.var_inputs.iter().zip(&self.var_input_lengths)
        {
            max_nonzero_position += input.len();
            add_slice_at_offset(
                ctx,
                range,
                input,
                offset_limbs,
                *len,
                &mut preimage_var,
                max_nonzero_position,
            );
            offset_limbs = range.gate.add(ctx, offset_limbs, *len);
        }

        // `preimage_var` now holds the desired non-native limbs (where
        // `var_preimage_len` is the number of limbs). Form `preimage` as the
        // fixed-length input followed by the bytes in the non-native limbs.

        let mut preimage = Vec::with_capacity(
            self.fixed_input.len()
                + var_preimage_len / NUM_LIMBS * NUM_BYTES_FQ,
        );
        preimage.extend_from_slice(&self.fixed_input);
        let var_bytes = multi_coordinates_to_bytes(ctx, range, &preimage_var);
        assert_eq!(
            var_bytes.len(),
            var_preimage_len / NUM_LIMBS * NUM_BYTES_FQ
        );
        preimage.extend_from_slice(&var_bytes);

        // Given the length in limbs, compute the length of the variable part of the preimage in bytes.

        let limbs_per_fq = ctx.load_constant(F::from(NUM_LIMBS as u64));
        let var_input_fq_length =
            range.gate.div_unsafe(ctx, offset_limbs, limbs_per_fq);
        // Overly conservative constraint to ensure division didn't overflow.
        range.range_check(ctx, var_input_fq_length, MAX_BIT_SIZE);
        let bytes_per_fq = ctx.load_constant(F::from(NUM_BYTES_FQ as u64));
        let var_input_byte_length =
            range.gate.mul(ctx, var_input_fq_length, bytes_per_fq);

        // Return the preimage and the byte length of its non-padding section
        let fixed_inputs_len =
            ctx.load_constant(F::from(self.fixed_input.len() as u64));
        let preimage_length =
            range.gate.add(ctx, var_input_byte_length, fixed_inputs_len);
        (preimage, preimage_length)
    }

    fn is_fixed(&self) -> bool {
        self.var_inputs.is_empty()
    }
}

/// Add `source[0..len]` to `dest[offset..offset+len]` as vectors, with
/// both `offset` and `len` being witness variables. Will not add beyond
/// `max_nonzero_position` in `dest`.
///
/// Note: This measures length and offset in F elements, so `len` is
/// `NUM_LIMBS` times the number of Fq elements in the source.
fn add_slice_at_offset<F: EccPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    source: &[AssignedValue<F>],
    offset: AssignedValue<F>,
    len: AssignedValue<F>,
    dest: &mut [AssignedValue<F>],
    max_nonzero_position: usize,
) {
    // Require `len <= padded input length`
    let padded_input_len = source.len();
    let padded_input_len_plus_one =
        ctx.load_constant(F::from(padded_input_len as u64 + 1));
    range.range_check(ctx, len, MAX_BIT_SIZE);
    range.check_less_than(ctx, len, padded_input_len_plus_one, MAX_BIT_SIZE);

    // Inner product below requires conversion to Vec<QuantumCell>
    let source: Vec<QuantumCell<F>> =
        source.iter().map(|x| QuantumCell::from(*x)).collect();

    // Do dst[0..max_nonzero_position] += source * slice_adder
    // where slice_adder is a matrix with a diagonal of 1's of length `len`
    // starting in column with index `offset` and with dimensions
    // source.len() x max_nonzero_position.
    // For offset = 1, len = 2, source.len() = 3, max_nonzero_position = 4:
    //                 0 1 0 0
    //  slice-adder =  0 0 1 0
    //                 0 0 0 0
    // The net effect is to add source[0..2] to dst[1..3].

    for (j, dst) in dest.iter_mut().enumerate().take(max_nonzero_position) {
        let selector_column =
            slice_adder_column(ctx, range, padded_input_len, offset, len, j);
        assert_eq!(selector_column.len(), padded_input_len, "bad column");
        let ip = range
            .gate
            .inner_product(ctx, source.clone(), selector_column);
        *dst = range.gate.add(ctx, *dst, ip);
    }
}

/// Return jth column of slice-adder matrix
fn slice_adder_column<F: EccPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    padded_input_len: usize,
    offset: AssignedValue<F>,
    len: AssignedValue<F>,
    j: usize,
) -> Vec<QuantumCell<F>> {
    // The jth column of the slice-adder matrix has a 1 at index i
    // if i + offset = j and i < len. Otherwise all elements are zero.

    // Note i + offset = j is impossible if i > j. Since these indices
    // are circuit constants we can treat those elements of the column
    // as the constant zero.
    // Note that the index i is also less than `padded_input_len`
    let max_nonzero_index_plus_one = core::cmp::min(j + 1, padded_input_len);

    let mut column = Vec::with_capacity(padded_input_len);
    for i in 0..max_nonzero_index_plus_one {
        assert!(i < 1 << MAX_BIT_SIZE, "i too large");
        // Compute (i + offset == j) && (i < len) in circuit
        // and assign to column[i]
        let i_assigned = ctx.load_constant(F::from(i as u64));
        let j_assigned = ctx.load_constant(F::from(j as u64));
        let i_plus_offset = range.gate.add(ctx, i_assigned, offset);
        let j_equals_i_plus_offset =
            range.gate.is_equal(ctx, j_assigned, i_plus_offset);
        // We may use `range.is_less_than` because `i` is less than 2^MAX_BIT_SIZE
        // and `len` <= padded_input_len < 2^MAX_BIT_SIZE
        let i_less_than_len =
            range.is_less_than(ctx, i_assigned, len, MAX_BIT_SIZE);
        column.push(
            range
                .gate
                .and(ctx, j_equals_i_plus_offset, i_less_than_len)
                .into(),
        );
    }
    // Remaining elements are zero
    for _ in max_nonzero_index_plus_one..padded_input_len {
        column.push(ctx.load_constant(F::zero()).into());
    }
    column
}
