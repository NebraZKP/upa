# UPA Circuits

## Run tests

```console
$ cargo test -- --test-threads=1 [--show-output] [--include-ignored]
```

## Audit Scope

The following functions and types are in scope for the audit of UPA v1.0.0:

- `batch_verify`
  - `common`
    - `chip.rs`
      - `struct BatchVerifierChip`, lines 36-41
        - `fn assign_fq_reduced`, lines 55-62
        - `fn assign_fq2_reduced`, lines 64-73
        - `fn assign_g1_reduced`, lines 75-84
        - `fn assign_g2_reduced`, lines 86-95
        - `fn assign_verification_key`, lines 97-114
        - `fn assign_public_inputs`, lines 116-122
        - `fn assign_proof`, lines 124-136
        - `fn check_points_on_curve`, lines 145-166
        - `fn scalar_powers`, lines 169-187
        - `fn scale_pairs`, lines 190-211
        - `fn multi_pairing`, lines 213-229
        - `fn check_pairing_result`, lines 237-245
      - `struct AssignedVerificationKey`, lines 250-256
        - `fn hash`, lines 296-303
        - `fn representation`, lines 309-319
        - `fn num_elements`, lines 321-326
        - `fn max_parts`, lines 334-338
        - `fn partial_hash`, lines 340-348
        - `fn parts_to_num_elements`, lines 350-357
      - `struct AssignedProof`, lines 362-366
      - `struct AssignedPublicInputs`, line 370
    - `ecc.rs`
      - `types G1InputPoint, G2InputPoint`, lines 46-51
      - `fn g1_input_point_to_inner`, lines 54-58
      - `fn g2_input_point_to_inner`, lines 61-81
    - `types.rs`
      - `struct VerificationKey`, lines 11-20
        - `fn default_with_length`, lines 26-36
        - `fn gamma`, lines 39-41
        - `fn pad`, lines 44-49
      - `struct Proof`, lines 53-57
      - `struct PublicInputs`, line 71
        - `fn default_with_length`, lines 76-78
        - `fn pad`, lines 81-85
  - `universal`
    - `chip.rs`
      - `struct UniversalBatchVerifierChip`, lines 44-46
        - `fn check_padding`, lines 105-156
        - `fn assign_batch_entry`, lines 164-181
        - `fn assign_batch_entries`, lines 184-196
        - `fn compute_vk_hash`, lines 204-218
        - `fn compute_r`, lines 226-245
        - `fn verify`, lines 253-272
        - `fn verify_with_challenge`, lines 280-302
        - `fn prepare_proofs`, lines 310-341
        - `fn compute_pairs`, lines 349-393
        - `fn public_input_pair`, lines 401-469
      - `struct AssignedBatchEntry`, lines 274-283
      - `struct AssignedBatchEntries`, lines 487-489
        - `fn instance`, lines 518-525
      - `struct AssignedPreparedProof`, lines 530-539
        - `fn into_iter`, lines 554-561
    - `mod.rs`
      - `fn universal_batch_verify_circuit`, lines 73-98
      - `struct UniversalBatchVerifyCircuit`, lines 105-113
        - `fn create_builder_and_instance`, lines 125-144
        - `impl SafeCircuit` (not all is security-critical)
          - `fn keygen`, lines 178-200
          - `fn prover`, lines 202-261
        - `impl CircuitExt`:
          - `fn num_instance`, lines 370-372
          - `fn instances`, lines 374-382
    - `types.rs`
      - `struct UniversalBatchVerifierConfig`, lines 20-38
      - `struct BatchEntry`, lines 107-115
        - `fn from_ubv_input_and_config`, lines 119-139
        - `fn dummy`, lines 142-154
      - `struct BatchEntries`, line 175
        - `fn from_ubv_inputs_and_config`, lines 179-197
        - `fn dummy`, lines 200-207
      - `struct UniversalBatchVerifierInput`, lines 218-225
        - `fn dummy`, lines 243-249
      - `struct UniversalBatchVerifierInputs`, lines 268-270
        - `fn dummy`, lines 274-281
    - `utils.rs`
      - `fn dummy_ubv_snark`, lines 40-97
- `keccak`
  - `chip.rs`
    - `type FixedLenCells`, lines 54-55
    - `type VarLenCells`, lines 64-67
    - `type KeccakRowData`, lines 74-79
    - `struct KeccakFixedLenQuery`, lines 83-96
    - `struct KeccakVarLenQuery`, lines 107-132
    - `struct KeccakChip`, lines 158-164
      - `fn total_keccak_perms`, lines 194-205
      - `fn keccak_fixed_len`, lines 215-243
      - `fn keccak_var_len`, lines 261-330
      - `fn compute_intermediate_keccak_output_bytes_assigned`, lines 341-362
      - `fn select_true_outputs`, lines 371-405
      - `fn assert_var_len_keccak_correctness`, lines 409-430
      - `fn produce_keccak_row_data`, lines 435-473
      - `fn assign_keccak_cells`, lines 484-620
      - `fn extract_var_output_byte_vecs`, lines 623-639
      - `fn extract_var_input_words`, lines 643-651
      - `fn extract_fixed_output_bytes`, lines 655-663
      - `fn extract_fixed_input_words`, lines 667-675
      - `fn constrain_var_queries`, lines 684-709
      - `fn constrain_fixed_queries`, lines 718-743
    - `fn assigned_cell_from_assigned_value`, lines 748-758
    - `fn assign_prover`, lines 765-785
    - `fn get_assigned_bytes_values`, lines 789-802
    - `fn rows_per_round`, lines 805-811
    - `fn keccak_no_padding`, lines 814-822
  - `inputs.rs`
    - `struct KeccakFixedInput`, lines 15-29
    - `struct KeccakVarLenInput`, lines 55-66
    - `enum KeccakCircuitInputs`, lines 98-104
  - `mod.rs`
    - `struct KeccakConfig`, lines 72-84
    - `struct KeccakPaddedCircuitInput`, lines 154-175
      - `fn to_instance_values`, lines 184-192
      - `fn assign`, lines 198-208
      - `fn dummy`, lines 221-233
      - `fn is_well_constructed`, lines 270-278
      - `fn from_var_len_input`, lines 281-304
      - `fn from`, lines 311-318
    - `struct KeccakPaddedCircuitInputs`, lines 325-327
      - `fn from_var_len_inputs`, lines 333-348
      - `fn from_fixed_or_var_len_inputs`, lines 350-365
      - `fn dummy`, lines 379-385
      - `fn is_well_constructed`, lines 400-417
    - `struct AssignedKeccakInput`, lines 422-440
      - `fn flatten`, lines 454-458
      - `fn flatten_with_len`, lines 461-465
    - `struct AssignedKeccakInputs`, lines 476-478
      - `fn to_instance_values`, lines 500-506
    - `struct KeccakGateConfig`, lines 512-516
    - `struct KeccakCircuit`, lines 547-565
      - `fn var_input`, lines 579-598
      - `fn fixed_input`, lines 607-623
      - `fn new`, lines 630-712
      - `fn keccak_output_bytes`, lines 720-732
      - `fn config`, lines 735-767
      - `fn extract_public_inputs`, lines 861-872
      - `fn extract_public_output`, lines 875-881
      - `fn synthesize`, lines 901-987
      - `fn keygen`, lines 1015-1024
      - `fn prover`, lines 1026-1091
      - `fn compute_instance`, lines 1093-1164
      - `fn configure`, lines 1278-1284
      - `fn synthesize`, lines 1286-1316
      - `fn num_instance`, lines 1324-1326
      - `fn instances`, lines 1328-1336
    - `struct KeccakCircuitConfig`, lines 1223-1233
      - `fn configure`, lines 1236-1263
      - `fn configure`, lines 1278-1284
      - `fn synthesize`, lines 1286-1316
      - `fn num_instance`, lines 1324-1326
      - `fn instances`, lines 1328-1336
  - `utils.rs`
    - `fn byte_decomposition_powers`, lines 44-57
    - `fn byte_decomposition`, lines 61-92
    - `fn byte_decomposition_list`, lines 101-113
    - `fn compute_proof_id`, lines 117-137
    - `fn compute_final_digest`, lines 142-154
    - `fn digest_as_field_elements`, lines 165-178
    - `fn compose_into_field_elements`, lines 187-212
    - `fn into_bits`, lines 215-233
    - `fn padding`, lines 236-248
    - `fn pack`, lines 251-264
    - `fn bytes_to_keccak_padded_words`, lines 272-290
    - `fn keccak_inputs_from_ubv_instances`, lines 345-399
    - `fn compute_proof_ids_from_ubv_instance`, lines 403-445
    - `fn gen_keccak_snark`, lines 452-482
    - `fn gen_keccak_snark_with`, lines 489-513
  - `variable.rs`
    - Constants: lines 21,24,27
    - `fn first_i_bits_bitmask`, lines 35-48
    - `fn upa_input_len_to_word_len`, lines 65-76
    - `fn upa_input_len_to_byte_len`, lines 85-95
    - `fn byte_len_to_word_len`, lines 106-124
    - `fn byte_len_to_last_chunk_index`, lines 132-141
    - `fn var_bytes_to_keccak_padded_words`, lines 153-224
    - `fn bits_to_byte`, lines 227-229
    - `fn bytes_from_words`, lines 237-248
    - `fn constant_1_zeroes`, lines 251-255
    - `fn constant_1_zeroes_1`, lines 258-263
    - `fn constant_zeroes_1`, lines 266-270
    - `fn remove_padded_bytes`, lines 278-298
- `outer`
  - `mod.rs`
    - `trait OuterCircuit`, lines 51-145
    - `struct OuterInstanceInputs`, lines 181-187
      - `fn new`, lines 192-218
    - `struct OuterCircuitInputs`, lines 227-238
      - `fn new`, lines 260-275
      - `fn keygen_default`, lines 280-311
    - `struct OuterKeygenInputs`, lines 315-319
      - `fn new`, lines 324-344
    - `struct OuterCircuitWrapper`, lines 368-382
      - `fn configure`, lines 424-428
      - `fn synthesize`, lines 430-436
      - `fn num_instance`, lines 451-453
      - `fn instances`, lines 464-466
      - `fn keygen`, lines 505-522
      - `fn prover`, lines 524-540
    - `fn flex_gate_params_env_check`, lines 601-616
    - `fn lookup_bits_env_check`, lines 620-629
  - `universal.rs`
    - `struct UniversalOuterCircuit`, lines 21-24
    - `impl OuterCircuit for UniversalOuterCircuit`, lines 26-120
  - `utils.rs`
    - `fn gen_outer_evm_verifier`, lines 101-139
- `utils`
  - `bitmask.rs`
    - `fn ith_bit_bitmask`, lines 20-32
    - `fn first_i_bits_bitmask`, lines 43-56
  - `hashing.rs`
    - Poseidon constants: lines 37,39,41,43
    - `fn domain_tag_bytes`, lines 46-51
    - `fn domain_tag`, lines 55-57
    - `fn assigned_domain_tag`, lines 60-65
    - `struct PoseidonHasher`, lines 69-72
      - All functions, lines 75-143
    - `fn var_len_poseidon`, lines 169-189
    - `fn var_len_poseidon_no_len_check`, lines 196-295
    - `fn select_with_bitmask`, lines 302-324

The specs in `universal_batch_verifier.md`, `universal_outer.md`, and `var_len_keccak.md` are also in scope.

Any other files contain code that is out of scope, either because it pertains to the "fixed" (i.e. non-universal) versions of the circuits, is only for testing, or defines util functions for our prover tool.

Auditors may find the test code and the native functions in `batch_verify/common/native.rs`, `batch_verify/universal/native.rs` informative. However these are not in scope.
