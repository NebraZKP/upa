# Variable length keccak circuit specification

## Overview

The Variable Length Keccak circuit is one of the three circuits which constitute the Universal Proof Aggregator (UPA), together with the Universal Batch Verifier circuit and the Universal Outer circuit.

The circuit's three main responsibilities are computing circuit IDs, proof IDs, and a curve-to-field hash function.

### Circuit IDs:
For each of $M$ application proofs with verifying key $`vk_i`$, the Keccak circuit computes a circuit ID by hashing the bytes of $`vk_i`$.
```math
\mathsf{C_{ID}}_i = \mathsf{keccak}(\mathsf{domain tag}, vk_i)
```
to create a 32-byte digest.  See [Circuit ID Computation](#circuit-id-computation) below for details of the domain tags.

### Proof IDs:
For each of $M$ application proofs with public inputs $P_i$ and circuit ID $`\mathsf{C_{ID}}_i`$ computed above, the Keccak circuit:
- Computes $`k_i = \mathsf{keccak}(\mathsf{C_{ID}}_i || P_i)`$ for all $i$.
- Returns the final digest $`k = \mathsf{keccak}(||_{i=1}^M k_i)`$ as a public output.

### Curve-to-Field Hash
Each of the $M$ application proofs above has also a $`\mathbb{G}_1`$ point $`m_i`$. For each $`m_i`$, the Keccak circuit
- Computes the 32-byte keccak digest of (the byte decomposition of) $`m_i`$
- Interprets the result as a 256-bit integer
- Returns the mod $`r`$ reduction of that integer

## Conventions and Terminology

- $`e: \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T`$ denotes the pairing over the BN254 elliptic curve
- $`g_1 \in \mathbb{G}_1$ and $g_2 \in \mathbb{G}_2`$ denote the respective generators.
- $`\mathbb{F}_r`$ denotes the scalar field of BN254

## Configuration

The variable length keccak circuit is determined by the following parameters:
- `limb_bits`: The bit size of limbs to represent an $F_p$ element.
- `num_limbs`: The number of limbs to represent an $F_p$ element.
- `inner_batch_size`: The number of Groth16 proofs to be verified in a batch.
- `outer_batch_size`: The number of batches.
- `num_public_inputs`: The maximum number of public inputs allowed in one application proof instance. We call this $L$.

## Inputs

The input consists of tuples of the form $`\{ (\ell_i, vk_i,n_i, \overline{P}_i, m_i) \}^M_{i=1}`$, where
- $`vk_i`$ is a padded Groth16 verifying key (for a circuit that accepts $\ell_i$ public inputs), represented as non-native limbs (see [Circuit ID Computation](#circuit-id-computation) ).
- $`n_i`$ is 1 if $`vk`$ belongs to a circuit that uses the optional extra commitment and is 0 otherwise.
- $`0 \leq \ell_i \leq L`$. We cast $\ell_i$ as an $\mathbb{F}_r$ element.
- $`\overline{P}_i \in \mathbb{F}_r^L`$. Only the first $\ell_i$ elements of $`\overline{P}_i`$ will be used to compute the Proof ID.
- $`m_i`$ is the decomposition of a $`\mathbb{G}_1`$ point into `2 * num_limbs` elements of $`\mathbb{F}_r`$
- $M$ is the product of `inner_batch_size` by `outer_batch_size`, i.e., the total number of application proofs that will be aggregated.

Note that the input of the keccak circuit consists of the instances of `outer_batch_size` universal batch verifier circuits.

### Notes
- In the implementation, a `KeccakCircuitInput` has an `is_fixed` boolean flag, which is a circuit synthesis parameter: if all inputs satisfy `is_fixed = true`, the compiled circuit is a fixed length keccak circuit. Here, because we are describing only variable length keccak, we always take this flag to be `false` and will omit it.
- The Keccak circuit does not check that the non-native limbs of $`vk_i`$ and $`m_i`$ do indeed represent valid $`\mathbb{G}_1`$ and $`\mathbb{G}_2`$ points. This is done by the UBV circuit, with the Outer circuit ensuring that the UBV and Keccak circuits process the same data.

## Circuit Description
We give the high-level description of the Keccak circuit, referring to components defined in the next section for detailed descriptions.

### Circuit ID Computation
The circuit ID corresponding to a given $`vk`$ is $`\mathsf{C_{ID}} = \mathsf{keccak}(\mathsf{domain tag},vk)`$.

#### Domain Tag
The domain tag is derived either from the string `UPA Groth16 circuit id` (if the circuit does not use the commitment to witness value) or else from the string `UPA Groth16 with commitment circuit id`. The string is interpreted as ASCII bytes and it's 32-byte Keccak digest is used as the corresponding domain tag.

#### Byte Representation
We encode $`vk`$ in bytes as $`\alpha || \beta || \gamma || \delta || \ell_s || s_0 || ... || s_{\ell_s-1}`$ if the circuit does not use the optional commitment to witness value. If it does use the optional commitment we append $`h_1 || h_2`$ to the above bytes.

Here $`\mathbb{G}_1`$ and $`\mathbb{G}_2`$ elements are represented as the big-endian bytes of their affine coordinate representations. The length $\ell_s$ of $`vk.s`$ is represented as 32 big-endian bytes.

The bytes of each $`vk_i`$ are extracted from the nonnative limb representation of $`vk_i`$, which is one of the circuit inputs. We decode the $`\mathbb{F}_q`$ coordinates of each $`\mathbb{G}_1`$ and $`\mathbb{G}_2`$ element of $`vk_i`$ by repeatedly applying the [Coordinate limbs to bytes](#coordinate-limbs-to-bytes) component below. The Keccak circuit does not check that these bytes encode valid curve points; this condition is enforced by the UBV circuit.

The length $\ell_{s,i}$ is computed from the circuit input $`\ell_i`$ as $`\ell_{s,i} = \ell_i + 1 + n_i`$.

#### Digest Computation
The computation of $`\mathsf{C_{ID}}`$ from the above byte representation requires that we hash a preimage formed from one fixed-length input and two variable-length inputs. This is performed by the [Multi-Variable-Length Query](#multi-variable-length-query) component specified below.

To use that component we break $`vk`$ into one fixed-length part and two variable-length parts as follows:
- Fixed input: $`vk.\alpha || vk.\beta || vk.\gamma || vk.\delta || \ell_s || vk.s[0] || vk.s[1]`$ (We may consider $`vk.s[1]`$ to be part of the fixed-length inputs because we require $`\ell \ge 1`$, so $`vk.s[1]`$ is never padding.)
- Variable-length input: $`vk.s[2] \, || \ldots || \, vk.s[\ell_s-1]`$ of length `num_limbs`$`*2 *(\ell_s - 2)`$ scalars.
- Variable length input: $`vk.h_1 || vk.h_2`$ if the circuit uses the commitment to witness value and empty otherwise. This input's length is either 0 or $`8*`$`num_limbs` scalars.

### Proof ID Computation
The proof ID of a proof with circuit ID  $`\mathsf{C_{ID}}`$ and public input vector $`(P_1, \ldots P_\ell)`$ is defined as $`\mathsf{keccak}(\mathsf{C_{ID}} || P_1 || \ldots || P_\ell )`$ (where we implicitly mean the 32-byte big-endian representation of each of those $`\mathbb{F}_r`$ elements).

The following steps compute the proof ID for $`i = 1, \dots, M`$ from the circuit ID  $`\mathsf{C_{ID}}_i`$, padded public input vector $`\overline{P}_i`$, and public input length $\ell_i$.

#### Step 1: Byte decomposition
Compute the big-endian byte decompositions of $`\mathsf{C_{ID}}_i`$ and $`\overline{P}_i`$ (see [Byte Decomposition](#byte-decomposition) component). Concatenate these bytes.

#### Step 2: Compute query byte length
Compute the length in bytes of the $i$-th keccak query from $\ell_i$ as follows: $$\ell^{\textrm{bytes}}_i = 32(\ell_i+1).$$ Here the +1 accounts for the $`\mathsf{C_{ID}}_i`$, which exists for every input, and 32 is because each field element has 32 bytes.

#### Step 3: Variable-Length Keccak Query
Compute the Keccak digest of the first $`\ell^{\textrm{bytes}}_i`$ bytes from Step 1 (see [Variable-Length Query](#variable-length-query) component). This is the $`i`$ 'th Proof ID, $`O_i`$.

### Final Digest Computation
The Proof IDs $`O_i, i=1,\ldots M`$ are concatenated and their Keccak digest is computed (see [Fixed-Length Query](#fixed-length-query) component). Denote this 32-byte digest $`\mathsf{O}`$. Encode it as 2 field elements:
- Let $`\mathsf{O}_1 = \mathsf{O}[16..32)$ and $\mathsf{O}_2 = \mathsf{O}[0..16)`$
- For $`j = 1,2`$, let
```math
F_j = \sum_{k=0}^{15} (O_j)_{15-k} 2^{8k} \in \mathbb{F}_r.
```
- Return $`F_1, F_2`$

### Curve-to-Field Hash
For $`i = 1, \dots, M`$, each $`m_i`$ is represented using `2 * num_limbs` elements of $`\mathbb{F}_r`$. The first `num_limbs` represent its $`x`$ coordinate, the remaining `num_limbs` its $`y`$ coordinate (using the affine representation of $`\mathbb{G}_1`$ points).

The curve-to-field hash computation is
- Extract the bytes $`[b_0, \ldots b_{31}]`$ representing the $x$-coordinate of $`m_i`$ from the first `num_limbs` limbs of $`m_i`$ (see [Coordinate Limbs to Bytes](#coordinate-limbs-to-bytes) component below). Extract the bytes $`[b_{32}, \ldots b_{63}]`$ representing the $y$-coordinate of $`m_i`$ from the remaining `num_limbs` limbs of $`m_i`$
- Let $`[d_0, \ldots d_{31}] = \mathsf{keccak}([b_0, \ldots b_{63}])`$ (see [Fixed Length Query](#fixed-length-query) component below).
- Apply the component [Compose into Field Element](#compose-into-field-element) and return this value $`\textsf{comm}_i`$.

## Instance
The instance consists of:
```math
\{ \ell_i, vk_i, n_i, \textsf{comm}_i, m_i, \overline{P}_i \}_{i=1}^M \cup \{F_1, F_2\}
```
where $`vk_i`$ denotes a limb decomposition of a padded verifying key and $`m_i`$ denotes a limb decomposition of a $`\mathbb{G}_1`$ point.

## Statement

The statement regarding proof IDs is
```math
\begin{aligned} \mathsf{keccak}\left( \bigg|\bigg|_{i=1}^M \mathsf{keccak} \left( \mathsf{C_{ID}}_i || \overline{P}_i[0..\ell_i] \right) \right) = F_1 || F_2  \\  \end{aligned}
```
where $`\mathsf{C_{ID}}_i`$ is computed as defined [above](#circuit-id-computation) and
byte conversions of $`\overline{P}_i[0..\ell_i]`$, $F_1$ and $F_2$ are implicit.

The statement regarding curve-to-field hashes is, for each $`i = 1, \ldots M`$, $`\textsf{comm}_i`$ is the result of applying the curve-to-hash function to 64 bytes extracted from the limbs $`m_{i,j}`$, $`j=1, \ldots `$ `2 * num_limbs`.

Note: These 64 bytes are in fact the big endian byte representation of the $`x`$ and $`y`$ coordinates of a $`\mathbb{G}_1`$ point, but the Keccak circuit does not check that they represent a valid curve point. This is, however, enforced in the UBV circuit, and the Outer circuit copy-constrains these inputs between the UBV and Keccak circuits.

## Components

### Keccak phase 0: The grey box
We take the function `keccak_phase0_with_flags` as a grey box. Its signature is
```rust=
pub fn keccak_phase0_with_flags<F: Field>(
    rows: &mut Vec<KeccakRow<F>>,
    squeeze_digests: &mut Vec<[F; NUM_WORDS_TO_SQUEEZE]>,
    intermediate_digest_locations: &mut HashMap<(usize, usize), (usize, usize)>,
    input_word_locations: &mut HashMap<usize, usize>,
    bytes: &[u8],
)
```

At a high level, this function generates the trace of computing the Keccak digest of `bytes`, storing this trace row-by-row in `rows`. It flags certain locations in this trace, those containing "input words" and "intermediate digests" (defined below).

The input `bytes` are native bytes (not yet assigned in circuit). They are first processed out of circuit as follows:
- Convert `bytes` to bits and pad them to the next chunk length (which is 136 bytes or 1088 bits) with 10..01, using as many zeroes as needed. In terms of bytes, it pads with $`[1, 0, \dots, 0, 128]`$.
- Break resulting bits into chunks of size 1088 bits, packing each chunk's bits into 17 64-bit words.

Then, in circuit (meaning that the trace of the following operations is recorded in `rows` and constrained appropriately):
- Initialize Keccak state (all zeroes)
- For each chunk of 17 words, 24 rounds occur. In each round,
    - Assign and absorb next word into state (XOR) (After all 17 words are absorbed, do nothing). This is an "input word", so we record its location in the trace in `input_word_locations` (key: row, value: column)
    - Perform the Keccak $`\theta, \rho, \pi, \chi, \iota`$ transformations
- After 24 rounds, the trace contains an "intermediate digest". Record the locations of these 32 bytes in `intermediate_digest_locations` (key: (chunk index, row), value: (column index, index of byte within digest))
- The intermediate digest that occurs after the final chunk has been absorbed is the Keccak digest of `bytes`.

We emphasize that the rows defined by this computation trace define a Keccak `Region` that is separate from the `Region` where `Context` values are assigned in the overall Halo2 witness. This explains the need to record the `input_word_locations` and `intermediate_digest_locations`; they allow us to later impose the copy constraints that relate assigned quantities in a `Context` to assigned quantities in this Keccak-specific `Region`.

The assumption regarding this grey box is: The rows produced by `keccak_phase0_with_flags` are the witness to a Halo2 statement that constrains the cells holding input words and intermediate digests as described above. Our implementation of the function starts from an [audited Keccak circuit](https://github.com/axiom-crypto/halo2-lib/tree/2cd4548650cd7c2bf45414fae67651ea7d93c4bd/hashes/zkevm-keccak), assumed to produce constraints that indeed enforce the Keccak digest computation. We modify it as follows:
- Identifying and storing the locations of input words and intermediate digests
- Removing a `KeccakTable` from the prior circuit's config. This table was used by the previous circuit to produce RLC/RLP constraints and removing it does not affect witness generation for computing individual Keccak digests.

We do not change the output `rows` in any way. Therefore, assuming a thorough audit of the prior Keccak circuit, `keccak_phase0_with_flags` may be audited by confirming that the stored cell locations are indeed as described above.

### Fixed-Length Query
The grey box above may be used as follows to compute the Keccak digest of a buffer whose length is known at keygen time. (All steps are in circuit unless otherwise noted.)

- Input: `input_assigned`, a vector of values assigned in a `Context` and previously range-constrained to be bytes.
- Step 1: Component [Bytes to Keccak Padded Words](#bytes-to-keccak-padded-words) decomposes `input_assigned` to bits, performs Keccak padding to a multiple of 1088 bits, packs into 64-bit words, `input_words_assigned`.
- Step 2: (Out of Circuit) Extract native byte values `input_bytes` from `input_assigned` and compute their Keccak digest `output_bytes`.
- Step 3: Assign `output_bytes` in a `Context`, yielding `output_bytes_assigned`. (No need to impose range constraints as these will be copy-constrained to cells in the Keccak `Region` that are already constrained to byte values.)
- Step 4: Component `keccak_phase0_with_flags` generates the trace of computing the Keccak digest of `input_bytes`, returning `input_words_locations` and `intermediate_digest_locations`. Because this is a fixed-length query, the `output_bytes_positions` are the locations of the bytes of the final intermediate digest.
- Step 5: Copy-constrain the `input_words_assigned` in the `Context` to the cells of the Keccak `Region` located at `input_words_locations`. Copy-constrain the `output_bytes_assigned` in the `Context` to the cells of the Keccak `Region` located at `output_bytes_positions`.

The net effect of the above steps is that the `Context` cells `output_bytes_assigned` have been constrained to contain the Keccak digest of the `Context` cells `input_assigned`.

(Implementation Note: Steps 1-3 occur in the `KeccakChip` function `keccak_fixed_len`. Step 4 occurs in the `KeccakChip` function `produce_keccak_row_data`. Step 5 occurs in the `KeccakChip` function `constrain_fixed_queries`.)

### Variable-Length Query
When the input buffer length is not known at keygen time, it is instead specified as a witness value. We refer to this as a "variable-length Keccak query." The difficulty with variable-length input is that this circuit cannot dynamically choose the number of chunks to absorb; it must perform a fixed number of absorb-and-permute operations.

Our variable-length Keccak query therefore takes `input_bytes_assigned` of a *fixed* `max_length` (a maximum length set at keygen time) and an assigned witness value `byte_len` and produces the Keccak digest of `input_bytes_assigned[0..byte_len]`.

The same grey box `keccak_phase0_with_flags` may be used to compute the digest of this buffer in circuit, but the logic is subtler. The objective is to provide inputs to the grey box in such a way that one of the intermediate digests will contain the desired keccak digest. The correct intermediate digest occurs at index `chunk_index` $`=\lfloor`$ `byte_len`/136 $`\rfloor`$ because:
- Keccak padding will round `byte_len` up to the *next* multiple of 136 bytes (Here 136 bytes = 1088 bits is the size of a 17-word chunk.)
- Therefore `chunk_length` = $`\lfloor`$ `byte_len`/136 $`\rfloor +1`$ chunks will be absorbed before the Keccak digest occurs
- The *index* where the Keccak digest occurs is therefore $`\lfloor`$ `byte_len`/136 $`\rfloor`$ (due to 0-indexing)

We ensure that `keccak_phase0_with_flags` computes the correct output at `chunk_index` by ensuring that the first `chunk_length` chunks it absorbs match what would be absorbed by a native Keccak hasher given `input_bytes_assigned[0..byte_len]`. In particular, the `chunk_length`th chunk it absorbs must contain the Keccak padding of `input_bytes_assigned[0..byte_len]`. In general, `keccak_phase0_with_flags` will not perform this padding correctly because it performs Keccak padding only at the end of the input buffer it receives. We therefore must engineer the input to `keccak_phase0_with_flags` to have Keccak padding in the correct positions.

Overall, variable-length queries are computed as follows (All steps are in circuit unless otherwise noted):

- Input: `input_bytes_assigned`, a vector of values assigned in a `Context` and previously range-constrained to be bytes, as well as `byte_len`, also assigned in a `Context`.
- Step 1: Constrain the `byte_len` to be less than or equal to the `max_len`.
- Step 2: The component [Var Bytes to Keccak Padded Words](#var-bytes-to-keccak-padded-words) computes the appropriate `input_words`.
- Step 3: (Out of circuit) Extract the assigned values in `input_words` and unpack these 64-bit words to bytes, obtaining native bytes `input_byte_values`.
- Step 4: (Out of circuit) Compute all the intermediate digests that will appear in the trace of the Keccak computation. (See component [Compute Intermediate Keccak Digests](#compute-intermediate-keccak-digests-out-of-circuit))
- Step 5: Assign the bytes of these intermediate digests as `keccak_outputs_assigned`. (No need to impose range constraints as these will be copy-constrained to cells in the Keccak `Region` that are already constrained to byte values.)
- Step 6: Select the elements `output_assigned` of `keccak_outputs_assigned` that correspond to the digest of `input_bytes_assigned[0..byte_len]`. These are the bytes of the intermediate digest at index `chunk_index`. (See [Select true digest](#select-true-digest) below)
- Step 7: (Out of circuit) Remove the Keccak padding from `input_byte_values`. (Recall that `keccak_phase0_with_flags` begins by padding its inputs. This would result in double padding to `input_byte_values` if we did not perform this step. See [Unpad input bytes](#unpad-input-bytes-out-of-circuit) below)
- Step 8: Component `keccak_phase0_with_flags` generates the trace of computing the Keccak digest of `input_bytes`, returning `input_words_locations` and `intermediate_digest_locations`.
- Step 9: Copy-constrain the `input_words_assigned` in the `Context` to the cells of the Keccak `Region` located at `input_words_locations`. Copy-constrain the `keccak_outputs_assigned` in the `Context` to the cells of the Keccak `Region` located at `intermediate_digest_locations`. (Note that in this variable-length query we must copy-constrain all the intermediate Keccak outputs since we do not know *a priori* which will be used in a given instance of the circuit.)

The net effect of the above steps is that the `Context` cells `output_assigned` are constrained to equal the Keccak digest of `input_bytes_assigned[0..byte_len]`.

(Implementation Note: Steps 1-7 occur in the `KeccakChip` function `keccak_var_len`. Step 8 occurs in the `KeccakChip` function `produce_keccak_row_data`. Step 9 occurs in the `KeccakChip` function `constrain_var_queries`.)

### Bytes to Keccak padded words
(For fixed-length Keccak queries)
- Input: a vector of bytes $\vec{b}$ of length $l$
- Output: a vector of keccak padded words $\vec{w}$ of length $$l' = 17 \left\lceil \frac{l + 1}{136} \right\rceil,$$ where $`\lceil \cdot \rceil`$ denotes the ceiling function.
- Description:
    - Convert $\vec{b}$ to bits.
    - Pad them to chunk length (1088 bits) by adding the bit string 10..01.
    - Iterate over the 1088-bit chunks. For each chunk, pack each of the 17 groups of 64 bits into a word. In pseudocode, for each 64-bit group
        ```pseudocode
        acc = 0
        for bit in bits.rev():
            acc = 8*acc + bit
        w.push(acc)
        ```
        where `w` is the output vector $\vec{w}$. This is the in-circuit equivalent of the packing algorithm mentioned in [Keccak phase 0](#keccak-phase-0-the-grey-box).
    - Return $\vec{w}$.

### Var-Bytes to Keccak padded words
(For variable-length Keccak queries)
- Input: `byte_len` $`\ell^{\textrm{bytes}}`$ and `input_bytes` $`\{b_k\}_{k=1}^{L^{\textrm{bytes}}}`$ of `max_length` $`L^{\textrm{bytes}}`$. We assume `byte_len` has been constrained to be a multiple of 8 and `input_bytes` have been constrained to byte values.
- Output: A vector `input_words` of 64-bit words $`\{w_k\}_{k=1}^{L^{\textrm{words}}}`$.
- Description:
    - Compute word length $`\ell^{\textrm{words}}`$ from $`\ell^{\textrm{bytes}}`$
    $$\ell^{\textrm{words}} = \ell^{\textrm{bytes}}/8.$$
    Note $`\ell^{\textrm{bytes}}`$ is always a multiple of 8 because of how it was computed from $\ell$. We also do a range check $`\ell^{\textrm{bytes}} < 2^{16}`$ to make sure there hasn't been wrap-around.
    - Apply [Bytes to keccak padded words](#bytes-to-keccak-padded-words) to $`\{b_k\}_{k=1}^{L^{\textrm{bytes}}}`$, obtaining $`\{w'_k\}_{k=1}^{L^{\textrm{words}}}`$.
    - Compute the word [First $`\ell^{\textrm{words}}`$ bits bitmask](#first-bits-bitmask) $`\mathfrak{b}_{\textrm{words}}`$. This bitmask of length $`L^{\textrm{words}}`$ has ones in the first $`\ell^{\textrm{words}}`$ positions and zeroes everywhere else.
    - Compute the word [$`\ell^{\textrm{words}}`$-th bit bitmask](#th-bit-bitmask) $`\mathfrak{b}_{eq}`$. This bitmask of length $`L^{\textrm{words}}`$ has a 1 at the $`\ell^{\textrm{words}}`$-th position (indexing from 0) and zeroes everywhere else.
    - We denote by $`W_{\vec{b}}`$ the word resulting from packing (as in the last step of [Bytes to keccak padded words](#bytes-to-keccak-padded-words)) the bitstring $`\vec{b}`$. Assign the following constants, which are all the possible words that can be used to pad the words to chunk length, depending on the position within a chunk and whether it is the first padding word:
        - $`W_{00..00} \in \mathbb{F}_r`$
        - $`W_{00..01} \in \mathbb{F}_r`$
        - $`W_{10..00} \in \mathbb{F}_r`$
        - $`W_{10..01} \in \mathbb{F}_r`$
    - Now we iterate over the word indices, i.e., from 0 to $`L^{\textrm{words}} - 1`$. For each index $i$, we select the corresponding output word as follows:
        - Use the word position in the chunk (first, last or else) and the bitmask $`\mathfrak{b}_{eq}`$ at that index to select a filler word, which encodes the keccak padding algorithm at that position.
        - Use the bitmask $`\mathfrak{b}_{\textrm{words}}`$ to select either $`w'_i`$ or the filler word computed above.
    ```pseudocode
    for chunk_idx in 0..number_of_chunks:
        for word_idx in 0..17:
            idx = chunk_idx*17+word_idx
            # Compute filler_word (the padding to potentially be applied)
            # based on the word index within the chunk.
            if word_idx == 0:
                filler_word = W_{10..00}
            else if word_idx == 16:
                filler_word = select(W_{10..01}, W_{00..01}, b_{eq}(idx))
            else:
                filler_word = select(W_{10..00}, W_{00..00}, b_{eq}(idx))
            # Select final word
            w(idx) = select(w'(idx), filler_word, b_{words}(idx))
    ```
    - Return $`\{w_k\}_{k=1}^{L^{\textrm{words}}}`$. Note the first $`\ell^{\textrm{words}}`$ of $`\{w_k\}_k`$ coincide with the first $`\ell^{\textrm{words}}`$ of $`\{w'_k\}_k`$, and the last $`L^{\textrm{words}} - \ell^{\textrm{words}}`$ consist of keccak padded chunks.

### Compute intermediate keccak digests (out-of-circuit):
Let $`L^{\textrm{chunks}} = \hat{L}^{\textrm{bytes}}/136 = L^{\textrm{words}}/17`$ be the number of chunks.
For $`j = 1, \dots, L^{\textrm{chunks}}`$:
- Compute and assign the 32-byte vector
```math
O(j) = \mathsf{keccak}_{np}(b_{\textrm{input}}[..136 \cdot j]),
```
where $`\mathsf{keccak}_{np}`$ denotes the keccak algorithm but skipping the padding step. Note we're only generating the witness and $`O(j) \in \mathbb{F}_r^{32}`$ is unconstrained.

The output of this step is the matrix $`O = \{O_j\}_{j=1}^{L^{\textrm{chunks}}}`$.

### Select true digest
- Input: the matrix $O$ from the previous step and $`\ell^{\textrm{bytes}}`$.
- Output: true keccak digest: $`o \in \mathbb{F}_r^{32}`$.
- Description:
    - Compute `chunk_index` $`\ell^{\textrm{chunks}} = \ell^{\textrm{bytes}}/136`$ as integers, i.e., applying the Euclidean algorithm and discarding the remainder.
    - Compute the length $`L^{\textrm{chunks}}`$ [$`\ell^{\textrm{chunks}}`$-th bit bitmask](#th-bit-bitmask) $`\mathfrak{b}`$, which is one at the $`\ell^{\textrm{chunks}}`$-th position (indexing from 0) and zero everywhere else.
    - The result is the product $`o = O \cdot b`$, seeing $O$ as a $`32 \times L^{\textrm{chunks}}`$ matrix and $b$ as a $`L^{\textrm{chunks}}`$ vector.

### Unpad input bytes (out-of-circuit):
The component [Keccak Phase 0 with Flags](#keccak-phase-0-the-grey-box) always pads its input `bytes` to the next multiple of 136, according to the Keccak spec. Before calling `keccak_phase0_with_flags` in Step 8 of the variable-length Keccak query, we have already performed this padding in-circuit in Step 2 and extracted the resulting values in Step 3. To avoid double padding, we now remove the padding bytes that will be assigned by `keccak_phase0_with_flags`.

The removed byte string is of the form $(1, 0, 0, \dots, 0, 128)$ and it may:
- be a whole 136-byte chunk if $`\lfloor \ell^{\textrm{bytes}} / 136 \rfloor < \lfloor L^{\textrm{bytes}} / 136 \rfloor`$.
- consist of $`136*(\lfloor L^{\textrm{bytes}} / 136 \rfloor + 1) - \ell^{\textrm{bytes}}`$ bytes otherwise.


### First $\ell$ bits bitmask
- Input: a natural number $`N \in \mathbb{N}`$ and a length $`\ell \leq N`$. We consider $`\ell \in \mathbb{F}_r`$.
- A vector of bytes (aka bitmask): $`\mathfrak{b} = (b_0, \dots, b_{N-1})`$ such that:
    - $`b_k = 1`$ for $`k = 0, 1, \dots, \ell-1`$.
    - $`b_k = 0`$ for $`k = \ell, \ell+1, \dots, N-1`$.
- Description:
    - Initialize $`e = 1 \in \mathbb{F}_r`$.
    - Iterate over $`i \in \{0, 1, \dots, N \}`$.
    - For each $`i`$:
        - Let $`e = e - \textrm{is\_equal}(i, \ell)`$.
        - $`b_i = e`$

### $\ell$-th bit bitmask
- Input: a natural number $`N \in \mathbb{N}`$ and a length $`\ell \leq N`$. We consider $`\ell \in \mathbb{F}_r`$.
- A vector of bytes (aka bitmask): $`\mathfrak{b} = (b_0, \dots, b_{N-1})`$ such that:
    - $`b_k = 1`$ for $`k = \ell`$.
    - $`b_k = 0`$ for $`k \not= \ell`$.
- Description:
    - Iterate over $`i \in \{0, 1, \dots, N \}`$.
    - For each $i$:
        - Assign $`i \in \mathbb{F}_r`$ as a witness.
        - $`b_k = \textrm{is\_equal}(i, \ell)`$

### Byte Decomposition
An $`\mathbb{F}_r`$ point $f$ is decomposed into its unique big-endian byte representation as follows:
- Decompose $f$ into 32 bytes $`\{b_k\}_{k=0}^{31}`$ out of circuit (in big endian representation), and assign them as witnesses.
- Range check each byte $`0 \leq b_k < 2^8`$.
- Enforce (in constraint field $`\mathbb{F}_r`$)
```math
f = \sum_{k=0}^{31} b_{31-k} 2^{8k}.
```
This representation is unique provided that the above equality holds as integers (and not merely modulo $r$). To enforce this, we compute the numbers:
```math
f_1 = \sum_{k=0}^{15} b_{31-k} 2^{8k}, \quad f_2 = \sum_{k=0}^{15} b_{15-k} 2^{8k}
```
and assert that:
- $`f_2 < r_2`$, OR
- $`f_2 = r_2`$ AND $`f_1 \leq r_1`$

where
```math
r_1 = 0x000000000000000000000000000000002833e84879b9709143e1f593f0000000
```
and
```math
r_2 = 0x0000000000000000000000000000000030644e72e131a029b85045b68181585d
```
are the 16 least (respectively most) significant bytes of $r-1$. That is, $`r-1 = r_1 + r_2 * 2^{8*16}`$ as integers.

### Compose into Field Element
Takes 32 bytes $`[b_0, \ldots b_{31}]`$, interprets them as the big endian representation of an integer, and returns the mod $`r`$ value:
- Compute the powers $`2^0, 2^8, \ldots 2^{8*31}`$ as $`\mathbb{F}_r`$ elements
- Return
```math
\sum_{i=0}^{31} b_{i} *2^{8i}
```

### Coordinate Limbs to Bytes
Takes `num_limbs` $`\mathbb{F}_r`$ limbs and converts them to the big-endian byte representation of an $`\mathbb{F}_q`$ point. N.B. The limbs are in least-to-most significant order, but the bytes within a limb are most-to-least significant. We use a decomposition with
`num_limbs = 3`, `limb_bits = 88`. An $`\mathbb{F}_q`$ point whose big-endian bytes are $`[b_{0}, \ldots b_{31}]`$ is therefore represented in limbs with big-endian byte decompositions
```math
\begin{aligned} &[0, \ldots, 0, b_{21}, \ldots, b_{31}] \\ &[0, \ldots, 0, b_{10}, \ldots b_{20}] \\ & [0, \ldots 0, b_{0}, \ldots b_{9}] \end{aligned}
```
To arrive at the big-endian representation we therefore:
- Reverse the limb array (so that the limbs are now ordered most-to-least significant)
- Compute the big-endian byte decomposition of each limb (see [Byte Decomposition](#byte-decomposition) component).
- Concatenate and return the meaningful bytes from each limb. For a limb decomposition with `limb_bits = 88` and `num_limbs = 3`, these meaningful bytes are:
    - The last 10 bytes of the first limb
    - The last 11 bytes of the final two limbs

### Multi-Variable Length Query

This component computes the Keccak digest of a preimage obtained by concatenating a fixed-length input with one or more variable-length inputs:
```math
\mathsf{keccak}(\mathsf{fixed} || \mathsf{var}_0 || \ldots || \mathsf{var}_{N-1})
```
The variable-length inputs $`\mathsf{var}_k`$ are assumed to be byte representations of $`\mathbb{G}_1`$ and $`\mathbb{G}_2`$ points. The inputs are provided to the circuit as non-native limb decompositions $`\overline{\mathsf{var}}_k`$ padded to a constant length $`L_k`$ together with a witness value $`\ell_k`$ specifying the number of limbs encoding bytes that belong in the preimage. The bytes $`\mathsf{var}_k`$ to include in the preimage are extracted from the limbs $`\overline{\mathsf{var}}_k[0..\ell_k)`$ by taking 32 bytes from every three limbs as described in [Coordinate Limbs to Bytes](#coordinate-limbs-to-bytes).

The variable input lengths $`\ell_k`$ are witnesses to the circuit, so forming the preimage is a non-trivial circuit computation. The idea is to start with a vector $`\mathsf{preimage}_{\mathsf{var}}=[0, ... 0]`$ whose length is the sum of padded lengths $`L_k`$ and use constraints to add each slice $`\overline{\mathsf{var}}_k[0..\ell_k)`$ to the next open position in this vector.

This can be described using matrix multiplication. We repeatedly add to $`\mathsf{preimage}_{\mathsf{var}}`$ the result of multiplying the padded variable input vector $`\overline{\mathsf{var}}_k`$ by a certain "slice-adder" matrix $S_k$:
```math
\mathsf{preimage}_{\mathsf{var}} \mathrel{+}= \overline{\mathsf{var}}_k \cdot S_k
```

The slice-adder matrix $S_k$ is defined such that $`\overline{\mathsf{var}}_k \cdot S_k`$ consists of $`\overline{\mathsf{var}}_k[0..\ell_k)`$ preceded by some number of zeroes that offset the position where it will be added to $`\mathsf{preimage}_{\mathsf{var}}`$.

#### Example

The computation is best explained by an example. Take
- $`\overline{\mathsf{var}}_0 = [4, 5, 6, 0, 0, 0]`$ with unpadded length $`\ell_0 = 3`$ and padded length $`L_{0} =6`$.
- $`\overline{\mathsf{var}}_1 = [7, 8, 9]`$ with unpadded length $`\ell_1 = 3`$ and padded length $`L_{1} =3`$.

<!-- Then the preimage we wish to hash is $`[1, 2, 3, 4, 5, 6, 7, 8]`$. We compute it in-circuit as follows: -->
For these values we expect $`\mathsf{preimage}_{\mathsf{var}}=[4,5,6,7,8,9,0,0,0]`$. We compute it in-circuit as follows:
1. Initialize $`\mathsf{preimage}_{\mathsf{var}}= [0, 0, 0, 0, 0, 0, 0, 0, 0]`$ of length $`L_{0}+L_{1}`$.
2. Add to  $`\mathsf{preimage}_{\mathsf{var}}`$ the vector
```math
\overline{\mathsf{var}}_0 \cdot S_0 = \begin{pmatrix} 4 & 5 & 6 & 0 & 0 & 0 \end{pmatrix}
\begin{pmatrix}
1 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
0 & 1 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
0 & 0 & 1 & 0 & 0 & 0 & 0 & 0 & 0 \\
0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0
\end{pmatrix}
= \begin{pmatrix} 4 & 5 & 6 & 0 & 0 & 0 & 0 & 0 & 0 \end{pmatrix}
```
After this step $`\mathsf{preimage}_{\mathsf{var}}= [4, 5, 6, 0, 0, 0, 0, 0, 0]`$. Its unpadded length is currently $`\ell_0=3`$.

3. Add to $`\mathsf{preimage}_{\mathsf{var}}`$ the vector
```math
\overline{\mathsf{var}}_1 \cdot S_1 = \begin{pmatrix} 7 & 8 & 9  \end{pmatrix}
\begin{pmatrix}
0 & 0 & 0 & 1 & 0 & 0 & 0 & 0 & 0 \\
0 & 0 & 0 & 0 & 1 & 0 & 0 & 0 & 0 \\
0 & 0 & 0 & 0 & 0 & 1 & 0 & 0 & 0
\end{pmatrix}
= \begin{pmatrix} 0 & 0 & 0 & 7 & 8 & 9 & 0 & 0 & 0 \end{pmatrix}
```
After this step $`\mathsf{preimage}_{\mathsf{var}}= [4, 5, 6, 7, 8, 9, 0, 0, 0]`$. Its unpadded length is currently $`\ell_0 + \ell_1 = 6`$.

#### Slice-Adder Matrix
The slice-adder matrix $S_k$ has dimensions determined by circuit constants
- Number of rows = $`L_{k}`$: The padded length of $`\overline{\mathsf{var}}_k`$
- Number of columns = $`L_T := \sum_k L_{k}`$: The sum of padded lengths of all variable-length inputs

The entries of $S_k$ are determined by witness values
- $`\ell_k`$: The number of nonnative limbs that encode the input $`\mathsf{var}_k`$
- $`o_k`$: The offset within $`\mathsf{preimage}_{\mathsf{var}}`$ where we will add the limbs $`\overline{\mathsf{var}}_k[0..\ell_k)`$ .

The $`(i,j)`$ th element (indexing from 0) of the slice-adder matrix $S_k = S(L_{k}, L_T, \ell_k, o_k)$ is $$(S_k)_{i,j}=(j-i == o_k) \land (i < \ell_k)$$
This element can be computed in circuit from the constants $i, j$ and witness values $o_k, \ell_k$ using arithmetic, logic, and range gates.

#### Optimizations
To save some constraints, we observe that two regions of the slice-adder matrix must contain zeroes regardless of the witness values $o, \ell$.
- Below the main diagonal: Since $o \ge 0$, $(j-i == o) = 0$ whenever $i >j$. When computing column $j$ of the slice-adder matrix we therefore assign the constant value 0 whenever $i>j$.
- Columns past $`L_{0} + \ldots + L_{k}`$: If prior variable-length inputs had padded lengths $`L_{0}, \ldots L_{k-1}`$ then the current offset is at most $`L_{0} + \ldots + L_{k-1}`$. Since we also have $`\ell_k \le L_k`$, the operation $`\mathsf{preimage}_{\mathsf{var}} \mathrel{+}= \overline{\mathsf{var}}_k \cdot S_k`$ will not affect $`\mathsf{preimage}_{\mathsf{var}}`$ at any index at or beyond $`L_{0} + \ldots + L_{k}`$. In other words, such columns of $`S_k`$ are always 0. Our circuit truncates the matrix multiplication once it reaches that index.

#### Prepare Preimage
The following algorithm prepares the preimage from a fixed-length input $`\mathsf{fixed}`$ and variable-length inputs provided as padded vectors $`\overline{\mathsf{var}}_k`$ together with unpadded input lengths $`\ell_k`$.

1. Initialize $`\mathsf{preimage}_{\mathsf{var}}=[0, ..., 0]`$  with $`L_T`$ zeroes. Initialize the offset to zero: $`o = 0`$.
2. For each variable-length input $`\overline{\mathsf{var}}_k`$ with length $`\ell_k`$:

    a. Constrain $`\ell_k \le L_{k}`$

    b. For $`j \in [0, \ldots , L_{0} + \ldots + L_{k})`$:

    Compute $`j`$ th column of slice-adder matrix $`S_k`$ for offset $o$ and length $\ell_k$, as described above.

    Compute inner product of this column with $`\overline{\mathsf{var}}_k`$

    Add result to $`\mathsf{preimage}_{\mathsf{var}}[j]`$.

    c. Add $\ell_k$ to the offset $o$.

3. Initialize $`\mathsf{preimage} = \mathsf{fixed}`$ and fill in its variable input section by extending it with 32 bytes for every 3 limbs of $`\mathsf{preimage}_{\mathsf{var}}`$ (including padding) using [Coordinate Limbs to Bytes](#coordinate-limbs-to-bytes).
4. Compute $`\ell_{\mathsf{preimage}} = o/3 * 32 + \mathsf{fixed}.\mathsf{len}`$, the unpaddded preimage length in bytes. We ensure that the division $`o/3`$ does not overflow by constraining the result to be less than 32 bits, which is an overly-conservative condition.

The result is the preimage vector $`\mathsf{preimage}= (\mathsf{fixed} || \mathsf{var}_0 || \ldots || \mathsf{var}_{N-1})`$ padded to its maximum possible length (fixed input length + $`L_T/3*32`$) together with $`\ell_{\mathsf{preimage}}`$ specifying its unpadded length.

Finally $`\mathsf{preimage}`$ and $`\ell_{\mathsf{preimage}}`$ are passed to the [Variable-Length Query](#variable-length-query) component to compute the digest.

Note: The Variable-Length Query component requires that the unpadded length of the preimage be a multiple of 8 bytes, otherwise the circuit is not satisfiable.
