use crate::{
    keccak::{
        chip::{assigned_cell_from_assigned_value, KeccakChip},
        multivar::KeccakMultiVarHasher,
        KeccakCircuit, KeccakCircuitConfig, DEFAULT_UNUSABLE_ROWS,
    },
    tests::remove_env_variables,
    EccPrimeField,
};
use core::{cell::RefCell, default::Default};
use ethers_core::utils::keccak256;
use halo2_base::{
    gates::{
        builder::{GateThreadBuilder, MultiPhaseThreadBreakPoints},
        range::RangeChip,
    },
    halo2_proofs::{
        circuit::{Cell, Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::{Fr, G1Affine},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    AssignedValue,
};
use itertools::Itertools;
use std::env::var;

// Define a KeccakHasher circuit for testing

pub struct KeccakTestCircuit {
    builder: RefCell<GateThreadBuilder<Fr>>,
    break_points: RefCell<MultiPhaseThreadBreakPoints>,
    keccak: KeccakChip<Fr>,
    digest: Vec<AssignedValue<Fr>>,
}

impl KeccakTestCircuit {
    pub fn new(
        mut builder: GateThreadBuilder<Fr>,
        degree_bits: usize,
        fixed_input: Vec<u8>,
        var_inputs: Vec<Vec<u8>>,
        var_input_lengths: Vec<usize>,
        expected_digest: [u8; 32],
    ) -> Self {
        let ctx = builder.main(0);
        let fixed_input: Vec<AssignedValue<Fr>> = fixed_input
            .iter()
            .map(|x| ctx.load_witness(Fr::from(*x as u64)))
            .collect();
        let var_inputs: Vec<Vec<AssignedValue<Fr>>> = var_inputs
            .iter()
            .map(|x| {
                x.iter()
                    .map(|y| ctx.load_witness(Fr::from(*y as u64)))
                    .collect()
            })
            .collect();
        let var_input_lengths: Vec<AssignedValue<Fr>> = var_input_lengths
            .iter()
            .map(|x| ctx.load_witness(Fr::from(*x as u64)))
            .collect();
        let expected_digest: Vec<AssignedValue<Fr>> = expected_digest
            .iter()
            .map(|x| ctx.load_witness(Fr::from(*x as u64)))
            .collect();

        let mut hasher = KeccakMultiVarHasher::new();
        hasher.absorb_fixed(&fixed_input);
        for (input, len) in var_inputs.iter().zip_eq(&var_input_lengths) {
            hasher.absorb_var(input, *len);
        }

        // Compute digest, constrain to expected
        const LOOKUP_BITS: usize = 8;
        let range_chip = RangeChip::default(LOOKUP_BITS);
        let mut keccak_chip = KeccakChip::default();
        let digest = hasher.finalize(ctx, &range_chip, &mut keccak_chip);
        digest
            .iter()
            .zip(expected_digest.iter())
            .for_each(|(a, b)| {
                ctx.constrain_equal(a, b);
            });

        // Configure
        KeccakCircuit::<Fr, G1Affine>::config(
            &builder,
            &mut keccak_chip,
            degree_bits as u32,
            Some(DEFAULT_UNUSABLE_ROWS),
            Some(degree_bits - 1),
        );
        Self {
            builder: RefCell::new(builder),
            break_points: RefCell::new(Default::default()),
            keccak: keccak_chip,
            digest,
        }
    }

    fn digest_values(&self) -> Vec<u8> {
        self.digest
            .iter()
            .map(|x| {
                let bytes = x.value().get_lower_32().to_le_bytes();
                assert_eq!(bytes[1], 0);
                assert_eq!(bytes[2], 0);
                assert_eq!(bytes[3], 0);
                bytes[0]
            })
            .collect()
    }

    /// Assign all builder and keccak cells, constrain their shared
    /// cells, and return the digest cells.
    fn synthesize(
        &self,
        config: &KeccakCircuitConfig<Fr>,
        layouter: &mut impl Layouter<Fr>,
    ) -> Vec<Cell> {
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");
        config
            .keccak
            .load_aux_tables(layouter)
            .expect("load keccak lookup tables");

        let mut digest = Vec::new();
        layouter
            .assign_region(
                || "Keccak Test Circuit",
                |mut region| {
                    let start = std::time::Instant::now();
                    let builder = self.builder.borrow();
                    // Builder cell assignments
                    let assignments = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &mut region,
                        Default::default(),
                    );
                    // Keccak cell assignments
                    let (fixed_len_cells, var_len_cells) = self
                        .keccak
                        .assign_keccak_cells(&mut region, &config.keccak);
                    // Constraints between builder and keccak cells
                    self.keccak.constrain_fixed_queries(
                        &mut region,
                        &assignments,
                        &fixed_len_cells,
                    );
                    self.keccak.constrain_var_queries(
                        &mut region,
                        &assignments,
                        &var_len_cells,
                    );
                    // return digest cells
                    digest.extend(self.digest.iter().map(|x| {
                        assigned_cell_from_assigned_value(x, &assignments)
                    }));
                    // Update break points
                    *self.break_points.borrow_mut() = assignments.break_points;
                    log::info!(
                        "keccak keygen constraint gen {:?}",
                        start.elapsed()
                    );
                    Ok(())
                },
            )
            .expect("synthesize");

        digest
    }
}

impl Circuit<Fr> for KeccakTestCircuit {
    type Config = KeccakCircuitConfig<Fr>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let params = serde_json::from_str(
            &var("KECCAK_GATE_CONFIG").expect("KECCAK_GATE_CONFIG not set"),
        )
        .expect("Deserialization error");
        KeccakCircuitConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // We later take the builder, so we need to save this value
        let witness_gen_only = self.builder.borrow().witness_gen_only();
        let assigned_digest = self.synthesize(&config, &mut layouter);
        if !witness_gen_only {
            // Expose digest
            let mut layouter = layouter.namespace(|| "expose");
            for (i, cell) in assigned_digest.iter().enumerate() {
                layouter.constrain_instance(*cell, config.instance, i);
            }
        }
        Ok(())
    }
}

fn test_keccak_mock(
    degree_bits: usize,
    fixed_input: Vec<u8>,
    var_inputs: Vec<Vec<u8>>,
    var_input_lengths: Vec<usize>,
    expected_digest: [u8; 32],
) {
    let circuit = KeccakTestCircuit::new(
        GateThreadBuilder::new(false),
        degree_bits,
        fixed_input,
        var_inputs,
        var_input_lengths,
        expected_digest,
    );
    let computed_digest: [u8; 32] = circuit.digest_values().try_into().unwrap();
    assert_eq!(expected_digest, computed_digest);
    let instance: Vec<Fr> = expected_digest
        .into_iter()
        .map(|x| Fr::from(x as u64))
        .collect();
    MockProver::<Fr>::run(degree_bits as u32, &circuit, vec![instance])
        .expect("prover run failure")
        .assert_satisfied();
    // The `KECCAK_DEGREE` env. variable can cause subsequent tests to fail
    remove_env_variables(vec![
        // String::from("FLEX_GATE_CONFIG_PARAMS"),
        // String::from("FLEX_GATE_NUM_COLS"),
        // String::from("KECCAK_GATE_CONFIG"),
        // String::from("KECCAK_LOOKUP_BITS"),
        // String::from("LAST_KECCAK_COLUMN"),
        // String::from("KECCAK_ADVICE_COLUMNS"),
        // String::from("UNUSABLE_ROWS"),
        // String::from("KECCAK_ROWS"),
        String::from("KECCAK_DEGREE"),
    ])
}

#[test]
fn test_fixed() {
    let degree_bits = 15;
    let fixed_input = vec![0x01, 0x02, 0x03];
    let var_inputs = vec![];
    let var_input_lengths = vec![];
    let expected_digest = keccak256(&fixed_input);
    println!("Expected Digest: {:?}", hex::encode(expected_digest));
    test_keccak_mock(
        degree_bits,
        fixed_input,
        var_inputs,
        var_input_lengths,
        expected_digest,
    );
}

// cargo test --package upa-circuits --lib -- keccak::multivar::tests::test_fixed_var --exact --show-output
#[test]
fn test_fixed_var() {
    let degree_bits = 15;

    let fixed_input = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let var_inputs = vec![vec![0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e]];
    let var_input_lengths = vec![3];
    let expected_preimage = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x09,
    ];
    let expected_digest = keccak256(expected_preimage);
    println!("Expected Digest: {:?}", hex::encode(expected_digest));
    test_keccak_mock(
        degree_bits,
        fixed_input,
        var_inputs,
        var_input_lengths,
        expected_digest,
    );
}

#[test]
fn test_fixed_var_var() {
    let degree_bits = 15;

    let fixed_input = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let var_inputs = vec![
        vec![0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e],
        vec![0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
    ];
    let var_input_lengths = vec![3, 6];
    let expected_preimage = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x09,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x13, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12,
    ];

    let expected_digest = keccak256(expected_preimage);
    println!("Expected Digest: {:?}", hex::encode(expected_digest));
    test_keccak_mock(
        degree_bits,
        fixed_input,
        var_inputs,
        var_input_lengths,
        expected_digest,
    );
}

#[test]
fn test_fixed_var_var_var() {
    let degree_bits = 15;

    let fixed_input = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let var_inputs = vec![
        vec![0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E],
        vec![0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
        vec![
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22,
            0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        ],
    ];
    let var_input_lengths = vec![3, 6, 6];
    let expected_preimage = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0A, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x09,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x13, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x1A, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x18, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1D, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1C, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x1B,
    ];

    let expected_digest = keccak256(expected_preimage);
    println!("Expected Digest: {:?}", hex::encode(expected_digest));
    test_keccak_mock(
        degree_bits,
        fixed_input,
        var_inputs,
        var_input_lengths,
        expected_digest,
    );
}
