use itertools::Itertools;
use upa_circuits::{
    keccak::{KeccakConfig, KECCAK_LOOKUP_BITS},
    outer::OuterConfig,
    utils::{
        benchmarks::{
            save_json, BV_CONFIG_FILE, KECCAK_CONFIG_FILE, OUTER_CONFIG_FILE,
            UBV_CONFIG_FILE, UNIVERSAL_OUTER_CONFIG_FILE,
        },
        file::load_json,
        upa_config::UpaConfig,
    },
    CircuitConfig, CircuitWithLimbsConfig,
};

/// Number of application public inputs. We choose four for convenience: there
/// are test files with valid Groth16 proofs for a circuit with 4 public
/// inputs.
const NUM_APP_PUBLIC_INPUTS: u32 = 16;

/// Optimal limb bits to perform non-native arithmetic
const LIMB_BITS: usize = 88;

/// Optimal number of limbs to perform non-native arithmetic
const NUM_LIMBS: usize = 3;

/// Generates outer config files that have a specified
/// total number of app proofs aggregated in each outer proof.
// cargo test --package upa-circuits --bench utils -- write_upa_configs_fixed_size --exact --nocapture
#[test]
fn write_upa_configs_fixed_size() {
    let bv_degree_range: Vec<u32> = vec![23];
    let keccak_degree_range: Vec<u32> = vec![19];
    let outer_degree_range: Vec<u32> = vec![24];
    let max_num_pub_input_range: Vec<u32> = vec![8, 16];

    // Desired total batch sizes
    let total_batch_size_range: Vec<u32> = vec![16, 20, 32, 40];
    // Vec of (inner, outer) batch size pairs with desired totals
    let mut batch_sizes = Vec::new();
    for total_batch_size in total_batch_size_range {
        for outer_batch_size in 2..5 {
            for inner_batch_size in 4..16 {
                if outer_batch_size * inner_batch_size == total_batch_size {
                    batch_sizes.push((inner_batch_size, outer_batch_size))
                }
            }
        }
    }
    println!("Chosen batch sizes (inner, outer): {batch_sizes:#?}");
    let mut configs = Vec::new();
    for outer_degree_bits in outer_degree_range.iter() {
        for keccak_degree_bits in keccak_degree_range.iter() {
            for bv_degree_bits in bv_degree_range.iter() {
                for (inner_batch_size, outer_batch_size) in batch_sizes.iter() {
                    for num_pub_in in max_num_pub_input_range.iter() {
                        configs.push(UpaConfig {
                            max_num_app_public_inputs: *num_pub_in,
                            inner_batch_size: *inner_batch_size,
                            outer_batch_size: *outer_batch_size,
                            bv_config: CircuitWithLimbsConfig::from_degree_bits(
                                *bv_degree_bits,
                            ),
                            keccak_config: CircuitConfig {
                                degree_bits: *keccak_degree_bits,
                                lookup_bits: KECCAK_LOOKUP_BITS,
                            },
                            outer_config:
                                CircuitWithLimbsConfig::from_degree_bits(
                                    *outer_degree_bits,
                                ),
                            output_submission_id: false,
                        });
                    }
                }
            }
        }
    }
    save_json(UNIVERSAL_OUTER_CONFIG_FILE, &configs)
}

/// Writes keccak configs specified by `degree_range`, `inner_batch_range` and `outer_batch_range`
/// to a file in the configs folder
#[test]
fn write_keccak_configs() {
    let degree_range: Vec<u32> = vec![19];
    let inner_batch_range: Vec<u32> = vec![8];
    let outer_batch_range: Vec<u32> = vec![4];
    let mut configs = Vec::new();
    for degree_bits in degree_range.iter() {
        for inner_batch_size in inner_batch_range.iter() {
            for outer_batch_size in outer_batch_range.iter() {
                // Use unchecked `UpaConfig` constructor. We will
                // only use the Keccak config.
                configs.push(UpaConfig {
                    max_num_app_public_inputs: NUM_APP_PUBLIC_INPUTS,
                    inner_batch_size: *inner_batch_size,
                    outer_batch_size: *outer_batch_size,
                    bv_config: CircuitWithLimbsConfig::from_degree_bits(1),
                    keccak_config: CircuitConfig {
                        degree_bits: *degree_bits,
                        lookup_bits: KECCAK_LOOKUP_BITS,
                    },
                    outer_config: CircuitWithLimbsConfig::from_degree_bits(1),
                    output_submission_id: false,
                });
            }
        }
    }
    save_json(KECCAK_CONFIG_FILE, &configs)
}

/// Writes (u)bv configs specified by `degree_range` and `batch_range`
/// to a file in the configs folder. If `is_universal` is `true`, writes a
/// UBV config.
fn write_bv_configs(is_universal: bool) {
    let degree_range: Vec<u32> = vec![23];
    let batch_range: Vec<u32> = vec![8];
    let mut configs = Vec::new();
    for degree_bits in degree_range.iter() {
        for batch_size in batch_range.iter() {
            // Use unchecked `UpaConfig` constructor. We will
            // only use the BV config.
            configs.push(UpaConfig {
                max_num_app_public_inputs: NUM_APP_PUBLIC_INPUTS,
                inner_batch_size: *batch_size,
                outer_batch_size: 0,
                bv_config: CircuitWithLimbsConfig::from_degree_bits(
                    *degree_bits,
                ),
                keccak_config: CircuitConfig {
                    degree_bits: 1,
                    lookup_bits: 0,
                },
                outer_config: CircuitWithLimbsConfig::from_degree_bits(1),
                output_submission_id: false,
            });
        }
    }
    if is_universal {
        save_json(UBV_CONFIG_FILE, &configs)
    } else {
        save_json(BV_CONFIG_FILE, &configs)
    }
}

/// Writes BV configs specified by `degree_range` and `batch_range`
/// to a file in the configs folder.
#[test]
fn write_nonuniversal_bv_configs() {
    write_bv_configs(false)
}

/// Writes UBV configs specified by `degree_range` and `batch_range`
/// to a file in the configs folder.
#[test]
fn write_universal_bv_configs() {
    write_bv_configs(true)
}

/// Writes keccak configs specified by `bv_degree_range`, `degree_range`, `inner_batch_range`
/// and `outer_batch_range` to a file in the configs folder
#[test]
fn write_outer_configs() {
    let bv_degree_range: Vec<u32> = vec![23];
    let degree_range: Vec<u32> = vec![24];
    let inner_batch_range: Vec<u32> = vec![8];
    let outer_batch_range: Vec<u32> = vec![4];
    let mut configs = Vec::new();
    for degree_bits in degree_range.iter() {
        for outer_batch_size in outer_batch_range.iter() {
            for bv_degree_bits in bv_degree_range.iter() {
                for batch_size in inner_batch_range.iter() {
                    // Use unchecked `UpaConfig` constructor. We will
                    // only use the Outer config.
                    configs.push(UpaConfig {
                        max_num_app_public_inputs: NUM_APP_PUBLIC_INPUTS,
                        inner_batch_size: *batch_size,
                        outer_batch_size: *outer_batch_size,
                        bv_config: CircuitWithLimbsConfig::from_degree_bits(
                            *bv_degree_bits,
                        ),
                        keccak_config: CircuitConfig {
                            degree_bits: 1,
                            lookup_bits: 0,
                        },
                        outer_config: CircuitWithLimbsConfig::from_degree_bits(
                            *degree_bits,
                        ),
                        output_submission_id: false,
                    });
                }
            }
        }
    }
    save_json(OUTER_CONFIG_FILE, &configs)
}

/// Generates outer config files that have a specified
/// total number of app proofs aggregated in each outer proof.
#[test]
fn write_outer_configs_fixed_size() {
    let bv_degree_range: Vec<u32> = vec![22, 23];
    let outer_degree_range: Vec<u32> = vec![23];
    let max_num_pub_input_range: Vec<u32> = vec![8, 16];

    // Desired total batch sizes
    let total_batch_size_range: Vec<u32> = vec![8, 16, 32];
    // Vec of (inner, outer) batch size pairs with desired totals
    let mut batch_sizes = Vec::new();
    for total_batch_size in total_batch_size_range {
        for outer_batch_size in 1..5 {
            for inner_batch_size in 4..64 {
                if outer_batch_size * inner_batch_size == total_batch_size {
                    batch_sizes.push((inner_batch_size, outer_batch_size))
                }
            }
        }
    }
    println!("Chosen batch sizes (inner, outer): {batch_sizes:#?}");
    let mut configs = Vec::new();
    for degree_bits in outer_degree_range.iter() {
        for bv_degree_bits in bv_degree_range.iter() {
            for (inner_batch_size, outer_batch_size) in batch_sizes.iter() {
                for num_pub_in in max_num_pub_input_range.iter() {
                    let bv_config = CircuitWithLimbsConfig {
                        degree_bits: *bv_degree_bits,
                        lookup_bits: *bv_degree_bits as usize - 1,
                        limb_bits: LIMB_BITS,
                        num_limbs: NUM_LIMBS,
                    };
                    let keccak_config = CircuitConfig {
                        degree_bits: *bv_degree_bits,
                        lookup_bits: KECCAK_LOOKUP_BITS,
                    };

                    configs.push(OuterConfig {
                        max_num_app_public_inputs: *num_pub_in,
                        inner_batch_size: *inner_batch_size,
                        outer_batch_size: *outer_batch_size,
                        bv_config,
                        keccak_config,
                        outer_config: CircuitWithLimbsConfig::from_degree_bits(
                            *degree_bits,
                        ),
                        output_submission_id: false,
                    });
                }
            }
        }
    }
    save_json(OUTER_CONFIG_FILE, &configs)
}

/// Generates outer config files that have a specified
/// total number of app proofs aggregated in each outer proof.
// cargo test --package upa-circuits --bench utils -- write_universal_outer_configs_fixed_size --exact --nocapture
#[test]
fn write_universal_outer_configs_fixed_size() {
    let bv_degree_range: Vec<u32> = vec![23];
    let outer_degree_range: Vec<u32> = vec![24];
    let max_num_pub_input_range: Vec<u32> = vec![16];

    // Desired total batch sizes
    let total_batch_size_range: Vec<u32> = vec![32];
    // Vec of (inner, outer) batch size pairs with desired totals
    let mut batch_sizes = Vec::new();
    for total_batch_size in total_batch_size_range {
        for outer_batch_size in 4..5 {
            for inner_batch_size in 8..9 {
                if outer_batch_size * inner_batch_size == total_batch_size {
                    batch_sizes.push((inner_batch_size, outer_batch_size))
                }
            }
        }
    }
    println!("Chosen batch sizes (inner, outer): {batch_sizes:#?}");
    let mut configs = Vec::new();
    for degree_bits in outer_degree_range.iter() {
        for bv_degree_bits in bv_degree_range.iter() {
            for (inner_batch_size, outer_batch_size) in batch_sizes.iter() {
                for num_pub_in in max_num_pub_input_range.iter() {
                    configs.push(UpaConfig {
                        max_num_app_public_inputs: *num_pub_in,
                        inner_batch_size: *inner_batch_size,
                        outer_batch_size: *outer_batch_size,
                        bv_config: CircuitWithLimbsConfig::from_degree_bits(
                            *bv_degree_bits,
                        ),
                        keccak_config: CircuitConfig {
                            degree_bits: 19,
                            lookup_bits: KECCAK_LOOKUP_BITS,
                        },
                        outer_config: CircuitWithLimbsConfig::from_degree_bits(
                            *degree_bits,
                        ),
                        output_submission_id: false,
                    });
                }
            }
        }
    }
    save_json(UNIVERSAL_OUTER_CONFIG_FILE, &configs)
}

/// Extracts Keccak configs from file of outer configs
#[test]
fn write_keccak_configs_from_outer_configs() {
    let outer_configs: Vec<OuterConfig> = load_json(OUTER_CONFIG_FILE);

    // Num app public inputs
    let num_pub_in_range: Vec<u32> = vec![10, 20];
    // Keccak circuit degree_bits to generate configs for
    let degree_range: Vec<u32> = vec![15, 16, 17, 18];
    // Extract all unique (inner, outer) batch size pairs
    let batch_sizes: Vec<(u32, u32)> = outer_configs
        .into_iter()
        .map(|config| (config.inner_batch_size, config.outer_batch_size))
        .unique()
        .collect();
    let mut configs = Vec::new();
    for num_pub_in in num_pub_in_range {
        for degree_bits in degree_range.iter() {
            for (inner_batch_size, outer_batch_size) in batch_sizes.iter() {
                configs.push(KeccakConfig {
                    degree_bits: *degree_bits,
                    num_app_public_inputs: num_pub_in,
                    inner_batch_size: *inner_batch_size,
                    outer_batch_size: *outer_batch_size,
                    lookup_bits: KECCAK_LOOKUP_BITS,
                })
            }
        }
    }
    save_json(KECCAK_CONFIG_FILE, &configs)
}
