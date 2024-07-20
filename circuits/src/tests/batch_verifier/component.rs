mod compute_r {
    use crate::{
        batch_verify::{
            common::{
                chip::{AssignedPublicInputs, BatchVerifierChip},
                native::json::load_proof_and_inputs,
                types::PublicInputs,
            },
            fixed::chip::FixedBatchVerifierChip,
        },
        tests::*,
    };
    use core::fmt::Debug;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::bn256::{Fq, Fr},
        },
        AssignedValue,
    };
    use halo2_ecc::fields::fp::FpChip;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct ComputeR {}

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        circuit_config: &CircuitWithLimbsConfig,
        _test_config: &ComputeR,
        instance: &mut Vec<AssignedValue<Fr>>,
    ) {
        let range = RangeChip::<Fr>::default(circuit_config.lookup_bits);
        let fp_chip = FpChip::<Fr, Fq>::new(
            &range,
            circuit_config.limb_bits,
            circuit_config.num_limbs,
        );
        let common_bv_chip = BatchVerifierChip::<_>::new(&fp_chip);
        let batch_verifier = FixedBatchVerifierChip::new(&common_bv_chip);

        let ctx = builder.main(0);

        let vk_hash = Fr::random(OsRng);
        let (proof1, _inputs1) = load_proof_and_inputs(PROOF1_FILE);
        let fake_pi = vec![
            PublicInputs(vec![Fr::from(1), Fr::from(1), Fr::from(1)]),
            PublicInputs(vec![Fr::from(1), Fr::from(1), Fr::from(2)]),
        ];
        let a_vk_hash = ctx.load_witness(vk_hash);
        let a_proof1 = batch_verifier.assign_proof(ctx, &proof1);
        let a_pi: Vec<AssignedPublicInputs<Fr>> = fake_pi
            .iter()
            .map(|pi| batch_verifier.assign_public_inputs(ctx, pi))
            .collect();

        // p_i_1 has inputs: [(1,1,1), (1,1,1)]
        let r_1_val = {
            let p_i_1 = vec![
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1.clone(), a_pi[0].clone()),
            ];
            let r_1 = batch_verifier.compute_r(ctx, &a_vk_hash, &p_i_1);
            instance.push(r_1);
            let r_1_val = *r_1.value();
            println!("r_1_val: {r_1_val:?}");
            r_1_val
        };

        // p_i_2 has inputs: [(1,1,1), (1,1,2)]
        let r_2_val = {
            let p_i_2 = vec![
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1.clone(), a_pi[1].clone()),
            ];
            let r_2 = batch_verifier.compute_r(ctx, &a_vk_hash, &p_i_2);
            instance.push(r_2);
            let r_2_val = *r_2.value();
            println!("r_2_val: {r_2_val:?}");
            r_2_val
        };
        assert_ne!(r_1_val, r_2_val);

        // p_i_3 has inputs (8 proofs, 3 inputs each): [
        //   (1,1,1), (1,1,1), (1,1,1), (1,1,1),
        //   (1,1,1), (1,1,1), (1,1,1), (1,1,2)
        // ]
        let r_3_val = {
            let p_i_3 = vec![
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1.clone(), a_pi[0].clone()),
                (a_proof1, a_pi[1].clone()),
            ];
            let r_3 = batch_verifier.compute_r(ctx, &a_vk_hash, &p_i_3);
            instance.push(r_3);
            let r_3_val = *r_3.value();
            println!("r_3_val: {r_3_val:?}");
            r_3_val
        };
        assert_ne!(r_2_val, r_3_val);
        assert_ne!(r_1_val, r_3_val);

        // Compare to natively computed values
        {
            use crate::batch_verify::fixed::native::compute_r;
            let r_1_native = compute_r(
                &vk_hash,
                &vec![(&proof1, &fake_pi[0]), (&proof1, &fake_pi[0])],
            );
            let r_2_native = compute_r(
                &vk_hash,
                &vec![(&proof1, &fake_pi[0]), (&proof1, &fake_pi[1])],
            );
            let r_3_native = compute_r(
                &vk_hash,
                &vec![
                    (&proof1, &fake_pi[0]),
                    (&proof1, &fake_pi[0]),
                    (&proof1, &fake_pi[0]),
                    (&proof1, &fake_pi[0]),
                    (&proof1, &fake_pi[0]),
                    (&proof1, &fake_pi[0]),
                    (&proof1, &fake_pi[0]),
                    (&proof1, &fake_pi[1]),
                ],
            );

            println!("r_1_native: {r_1_native:?}, r_1_val: {r_1_val:?}");
            println!("r_2_native: {r_2_native:?}, r_2_val: {r_2_val:?}");
            println!("r_3_native: {r_3_native:?}, r_3_val: {r_3_val:?}");

            assert_eq!(r_1_native, r_1_val, "r_1_val matches native version");
            assert_eq!(r_2_native, r_2_val, "r_2_val matches native version");
            assert_eq!(r_3_native, r_3_val, "r_3_val matches native version");
        }
    }

    const PATH: &str = "src/tests/configs/scalar_powers.config";

    #[test]
    fn test_mock() {
        run_circuit_mock_test(PATH, build_circuit);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        run_circuit_test(PATH, build_circuit);
    }
}

mod scalar_powers {
    use crate::{batch_verify::common::chip::BatchVerifierChip, tests::*};
    use core::fmt::Debug;
    use halo2_base::{
        gates::builder::GateThreadBuilder,
        halo2_proofs::halo2curves::bn256::Fr, AssignedValue,
    };

    #[derive(Debug, Deserialize)]
    /// A circuit to compute powers of `base` from `0` to `len - 1`.
    pub struct ScalarPowerCircuit {
        // degree: u32,
        /// To-Do: write `base` as a F element
        base: u64,
        len: usize,
    }

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        _circuit_config: &CircuitWithLimbsConfig,
        test_config: &ScalarPowerCircuit,
        _: &mut Vec<AssignedValue<Fr>>,
    ) {
        let ctx = builder.main(0);

        let base = ctx.load_witness(Fr::from(test_config.base));

        // Single value value edge-case
        {
            let powers = BatchVerifierChip::<_>::scalar_powers(ctx, base, 1);
            assert_eq!(powers.len(), 1);
            assert_eq!(powers[0].value(), &Fr::one());
        };

        // Longer example
        let result =
            BatchVerifierChip::<_>::scalar_powers(ctx, base, test_config.len);

        let answer = (0..test_config.len)
            .map(|i| Fr::from(test_config.base.pow(i as u32)));

        for (result, answer) in result.iter().zip(answer) {
            let answer = ctx.load_constant(answer);
            ctx.constrain_equal(result, &answer);
        }
    }

    const PATH: &str = "src/tests/configs/scalar_powers.config";

    #[test]
    fn mock_test() {
        run_circuit_mock_test(PATH, build_circuit);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        run_circuit_test(PATH, build_circuit);
    }
}

mod scale_pairs {
    use crate::{batch_verify::common::chip::BatchVerifierChip, tests::*};
    use core::fmt::Debug;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::bn256::{Fq, Fq2, Fr, G1Affine, G2Affine},
        },
        AssignedValue,
    };
    use halo2_ecc::{
        ecc::EccChip,
        fields::{fp::FpChip, fp2::Fp2Chip},
    };
    use rand_core::OsRng;

    #[derive(Debug, Deserialize)]
    /// A circuit to compute `(scalar_i * A_i, B_i)`
    pub struct ScalePairsCircuit {
        /// Number of pairs to scale
        len: usize,
    }

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        circuit_config: &CircuitWithLimbsConfig,
        test_config: &ScalePairsCircuit,
        _: &mut Vec<AssignedValue<Fr>>,
    ) {
        let range = RangeChip::<Fr>::default(circuit_config.lookup_bits);
        let fp_chip = FpChip::<_, Fq>::new(
            &range,
            circuit_config.limb_bits,
            circuit_config.num_limbs,
        );
        let batch_verifier = BatchVerifierChip::<_>::new(&fp_chip);
        let g1_chip = EccChip::new(&fp_chip);
        let fp2_chip = Fp2Chip::<Fr, FpChip<Fr, Fq>, Fq2>::new(&fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        let ctx = builder.main(0);

        // Sample points and scalars
        let (a, (b, r)): (Vec<_>, (Vec<_>, Vec<_>)) = (0..test_config.len)
            .map(|_| {
                (
                    G1Affine::random(OsRng),
                    (G2Affine::random(OsRng), Fr::random(OsRng)),
                )
            })
            .unzip();

        // Assign to circuit
        let (assigned_pairs, assigned_r): (Vec<_>, Vec<_>) = a
            .iter()
            .zip(b.iter())
            .zip(r.iter())
            .map(|((a, b), r)| {
                (
                    (
                        g1_chip.assign_point(ctx, *a),
                        g2_chip.assign_point(ctx, *b),
                    ),
                    ctx.load_witness(*r),
                )
            })
            .unzip();

        // Scale pairs
        let scaled_pairs =
            batch_verifier.scale_pairs(ctx, &assigned_r, &assigned_pairs);

        // Compute answers, assign to circuit
        let assigned_answers: Vec<_> = a
            .iter()
            .zip(b.iter())
            .zip(r.iter())
            .map(|((a, b), r)| {
                (
                    g1_chip.assign_point(ctx, G1Affine::from(a * r)),
                    g2_chip.assign_point(ctx, *b),
                )
            })
            .collect();

        // Constrain results
        let _ = scaled_pairs
            .iter()
            .zip(assigned_answers)
            .map(|((answer_a, answer_b), (computed_a, computed_b))| {
                g1_chip.assert_equal(ctx, answer_a.clone(), computed_a);
                g2_chip.assert_equal(ctx, answer_b.clone(), computed_b);
            })
            .collect::<Vec<_>>();
    }

    #[test]
    fn test_mock() {
        let path = "src/tests/configs/scale_pairs.config";
        run_circuit_mock_test(path, build_circuit);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        let path = "src/tests/configs/scale_pairs.config";
        run_circuit_test(path, build_circuit);
    }
}

mod fp_mul {
    use crate::tests::*;
    use core::fmt::Debug;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::bn256::{Fq, Fr},
        },
        AssignedValue,
    };
    use halo2_ecc::fields::{fp::FpChip, FieldChip};
    use rand_core::OsRng;

    #[derive(Debug, Deserialize)]
    /// Circuit for a single non-native multiplication
    pub struct FpMulCircuit {}

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        circuit_config: &CircuitWithLimbsConfig,
        _test_config: &FpMulCircuit,
        instance: &mut Vec<AssignedValue<Fr>>,
    ) {
        std::env::set_var(
            "LOOKUP_BITS",
            circuit_config.lookup_bits.to_string(),
        );

        // relation (_ab ; ab, a, b):  _ab = ab mod q, ab = a * b

        let ctx = builder.main(0);

        let a = Fq::random(OsRng);
        let b = Fq::random(OsRng);
        let range = RangeChip::<Fr>::default(circuit_config.lookup_bits);
        let fp_chip = FpChip::<_, Fq>::new(
            &range,
            circuit_config.limb_bits,
            circuit_config.num_limbs,
        );
        let assign_a = fp_chip.load_private(ctx, a);
        let assign_b = fp_chip.load_private(ctx, b);
        let ab = fp_chip.mul(ctx, assign_a, assign_b);
        instance.push(ab.as_ref().native);
    }

    const PATH: &str = "src/tests/configs/fp_mul.config";

    #[test]
    fn mock_test() {
        run_circuit_mock_test(PATH, build_circuit);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        run_circuit_test(PATH, build_circuit);
    }
}

mod multi_pairing {
    use crate::{
        batch_verify::{
            common::{
                chip::BatchVerifierChip,
                native::json::{load_proof_and_inputs, load_vk},
            },
            fixed::{
                chip::AssignedPreparedProof,
                native::{
                    compute_prepared_proof, get_pairing_pairs, pairing,
                    PreparedProof,
                },
            },
        },
        tests::*,
    };
    use core::fmt::Debug;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::halo2curves::{
            bn256::{Fq, Fq2, Fr, G1Affine, G2Affine},
            group::ff::Field,
        },
        AssignedValue, Context,
    };
    use halo2_ecc::{
        bn254::{Fp12Chip, FqPoint},
        ecc::{EcPoint, EccChip},
        fields::{fp::FpChip, fp2::Fp2Chip, vector::FieldVector, FieldChip},
    };
    use rand_core::OsRng;

    #[derive(Debug, Deserialize)]
    struct MultiPairing {
        pub num_random_pairs: usize,
    }

    fn do_build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        circuit_config: &CircuitWithLimbsConfig,
        prepared_proof: &PreparedProof,
    ) {
        let ctx = builder.main(0);

        // Setup the chip

        let range = RangeChip::<Fr>::default(circuit_config.lookup_bits);
        let fp_chip = FpChip::<Fr, Fq>::new(
            &range,
            circuit_config.limb_bits,
            circuit_config.num_limbs,
        );
        let batch_verifier = BatchVerifierChip::<_>::new(&fp_chip);
        let g1_chip = EccChip::new(&fp_chip);
        let fp2_chip = Fp2Chip::<Fr, FpChip<Fr, Fq>, Fq2>::new(&fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let fp12_chip = Fp12Chip::<Fr>::new(&fp_chip);

        // Natively compute the expected pairing result

        let expect = {
            let pairs_values = get_pairing_pairs(prepared_proof);
            println!("pairs_values = {pairs_values:?}");
            let pairing_out = pairing(&pairs_values);
            println!("expect pairing_out = {pairing_out:?}");

            pairing_out
        };

        // Load values into in-circuit object and execute in-circuit and
        // compare the answer

        #[allow(clippy::type_complexity)]
        fn assign_pair<'a>(
            ctx: &mut Context<Fr>,
            g1_chip: &EccChip<Fr, FpChip<Fr, Fq>>,
            g2_chip: &EccChip<Fr, Fp2Chip<Fr, FpChip<Fr, Fq>, Fq2>>,
            pair: &'a (G1Affine, G2Affine),
        ) -> (
            EcPoint<Fr, <FpChip<'a, Fr, Fq> as FieldChip<Fr>>::FieldPoint>,
            EcPoint<
                Fr,
                FieldVector<<FpChip<'a, Fr, Fq> as FieldChip<Fr>>::FieldPoint>,
            >,
        ) {
            (
                g1_chip.assign_point_unchecked(ctx, pair.0),
                g2_chip.assign_point_unchecked(ctx, pair.1),
            )
        }

        let prepared = AssignedPreparedProof::<Fr> {
            ab_pairs: prepared_proof
                .ab_pairs
                .iter()
                .map(|x| assign_pair(ctx, &g1_chip, &g2_chip, x))
                .collect(),
            rp: assign_pair(ctx, &g1_chip, &g2_chip, &prepared_proof.rp),
            pi: assign_pair(ctx, &g1_chip, &g2_chip, &prepared_proof.pi),
            zc: assign_pair(ctx, &g1_chip, &g2_chip, &prepared_proof.zc),
        };
        let prepared: Vec<_> = prepared.into();

        // Run the multi-miller loop

        let pairing_out: FqPoint<Fr> =
            batch_verifier.multi_pairing(ctx, &prepared);

        let pairing_out_unsafe: <Fp12Chip<Fr> as FieldChip<Fr>>::UnsafeFieldPoint =
            <Fp12Chip<Fr> as FieldChip<Fr>>::UnsafeFieldPoint::from(pairing_out);

        // Check values
        let actual = fp12_chip.get_assigned_value(&pairing_out_unsafe);

        println!("actual = {actual:?}");

        // Instead of assert!(Gt(actual) == expect);
        assert_eq!(format!("Gt({actual:?})"), format!("{expect:?}"));
    }

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        circuit_config: &CircuitWithLimbsConfig,
        config: &MultiPairing,
        _: &mut Vec<AssignedValue<Fr>>,
    ) {
        // Load native vk and proof

        if config.num_random_pairs == 0 {
            let vk = load_vk(VK_FILE);
            let (proof1, inputs1) = load_proof_and_inputs(PROOF1_FILE);
            let (proof2, inputs2) = load_proof_and_inputs(PROOF2_FILE);
            let (proof3, inputs3) = load_proof_and_inputs(PROOF3_FILE);
            let r = Fr::random(OsRng);

            // Compute everything natively

            let prepared_proof = compute_prepared_proof(
                &vk,
                &vec![
                    (&proof1, &inputs1),
                    (&proof2, &inputs2),
                    (&proof3, &inputs3),
                ],
                r,
            );

            do_build_circuit(builder, circuit_config, &prepared_proof);
        } else {
            let prepared_proof = PreparedProof {
                ab_pairs: (0..config.num_random_pairs)
                    .map(|_| (G1Affine::random(OsRng), G2Affine::random(OsRng)))
                    .collect(),
                rp: (encode_g1(3), encode_g2(5)),
                pi: (encode_g1(7), encode_g2(1)),
                zc: (encode_g1(11), encode_g2(13)),
            };

            do_build_circuit(builder, circuit_config, &prepared_proof);
        }
    }

    #[test]
    fn test_mock() {
        run_circuit_mock_test(
            "src/tests/configs/multi_pairing.config",
            build_circuit,
        );
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        run_circuit_test(
            "src/tests/configs/multi_pairing.config",
            build_circuit,
        );
    }
}

mod pairing_check {
    use crate::{batch_verify::common::chip::BatchVerifierChip, tests::*};
    use core::fmt::Debug;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::bn256::{Fq, Fq12, Fr},
        },
        AssignedValue,
    };
    use halo2_ecc::{
        bn254::Fp12Chip,
        fields::{fp::FpChip, FieldChip, FieldExtConstructor},
    };

    #[derive(Deserialize, Debug)]
    struct PairingCheck {}

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        circuit_config: &CircuitWithLimbsConfig,
        _test_config: &PairingCheck,
        _: &mut Vec<AssignedValue<Fr>>,
        output_value: Fq12,
    ) {
        let ctx = builder.main(0);

        // Setup the chip

        let range = RangeChip::<Fr>::default(circuit_config.lookup_bits);
        let fp_chip = FpChip::<Fr, Fq>::new(
            &range,
            circuit_config.limb_bits,
            circuit_config.num_limbs,
        );
        let batch_verifier = BatchVerifierChip::<_>::new(&fp_chip);

        // Test valid and invalid results.

        let fp12_chip = Fp12Chip::<Fr>::new(&fp_chip);
        let pairing_result = fp12_chip.load_private(ctx, output_value);
        batch_verifier.check_pairing_result(ctx, &pairing_result);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        // TODO: Adding type annotations to the closure fixes a compiler error
        // related to this issue:
        //
        //   https://github.com/rust-lang/rust/issues/37464
        run_circuit_test(
            "src/tests/configs/pairing_check.config",
            |ctx: &mut GateThreadBuilder<Fr>,
             circuit_config: &CircuitWithLimbsConfig,
             test_config: &PairingCheck,
             instance: &mut Vec<AssignedValue<Fr>>| {
                build_circuit(
                    ctx,
                    circuit_config,
                    test_config,
                    instance,
                    Fq12::one(),
                )
            },
        );
    }

    #[test]
    fn mock_test() {
        run_circuit_mock_test(
            "src/tests/configs/pairing_check.config",
            |ctx: &mut GateThreadBuilder<Fr>,
             circuit_config: &CircuitWithLimbsConfig,
             test_config: &PairingCheck,
             instance: &mut Vec<AssignedValue<Fr>>| {
                build_circuit(
                    ctx,
                    circuit_config,
                    test_config,
                    instance,
                    Fq12::one(),
                )
            },
        );
    }

    #[test]
    fn mock_failure_test() {
        // Ensure that non-zero outputs from the pairing are detected by the
        // circuit.  (This case is rather trivial, but for now it exercises the
        // run_circuit_mock_test_failure function).

        let f1 = Fq::one();
        let f0 = Fq::zero();
        let fp12_not_ones = vec![
            Fq12::new([f1 + f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f1, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f1, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f1, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f1, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f1, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f1, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f1, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f1, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f1, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f1]),
        ];

        for val in fp12_not_ones.iter() {
            run_circuit_mock_test_failure(
                "src/tests/configs/pairing_check.config",
                |ctx: &mut GateThreadBuilder<Fr>,
                 circuit_config: &CircuitWithLimbsConfig,
                 test_config: &PairingCheck,
                 instance: &mut Vec<AssignedValue<Fr>>| {
                    build_circuit(
                        ctx,
                        circuit_config,
                        test_config,
                        instance,
                        *val,
                    )
                },
            );
        }
    }
}

mod hashing {
    use crate::{
        tests::*,
        utils::hashing::{PoseidonHasher, WrongFieldHasher},
        CircuitWithLimbsConfig, EccPrimeField,
    };
    use core::fmt::Debug;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::halo2curves::bn256::{Fq, Fq2, Fr},
    };
    use halo2_ecc::fields::{fp::FpChip, fp2::Fp2Chip, FieldChip};
    use rand_core::OsRng;
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    struct HashCheck {}

    /// Basic test of the PoseidonHasher on Fp2 elements
    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        circuit_config: &CircuitWithLimbsConfig,
        fq2_val: Fq2,
    ) -> Fr {
        let ctx = builder.main(0);

        // Setup the chip

        let range = RangeChip::<Fr>::default(circuit_config.lookup_bits);
        let fp_chip = FpChip::<Fr, Fq>::new(
            &range,
            circuit_config.limb_bits,
            circuit_config.num_limbs,
        );
        let fp2_chip = Fp2Chip::<Fr, FpChip<Fr, Fq>, Fq2>::new(&fp_chip);
        let fq2 = fp2_chip.load_private_reduced(ctx, fq2_val);

        let mut hasher = PoseidonHasher::new(ctx, fp_chip.gate(), None);
        hasher.absorb(&fq2);
        let hash = hasher.squeeze(ctx);

        let hash_val = hash.value();
        println!("fq2_val: {fq2:?}");
        println!("hash: {hash_val:?}");

        // Run the same hash natively
        let native_hash_val: Fr = {
            let mut native_hasher = WrongFieldHasher::<G1Affine, G2Affine>::new(
                circuit_config,
                None,
            );
            native_hasher.absorb_fqe(&fq2_val);
            native_hasher.hasher.squeeze()
        };

        assert_eq!(
            &native_hash_val, hash_val,
            "in-circuit hash matches natively computed value"
        );

        *hash_val
    }

    /// Check our strategy for hashing non-native (extension) field elements,
    /// namely that all components of extension fields, and that all limbs of
    /// each component are entered into the sponge.  Compare the output of the
    /// in-circuit and native versions to ensure they are aligned, at least on
    /// this deterministic data set.
    #[test]
    fn test_hash_fq2_components_limbs_mock() {
        // Elements which introduce a change in every limb, to check
        // the hasher produces different results.
        let fq_repr: Vec<[u8; 32]> = vec![
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1,
            ],
        ];
        let fq_values: Vec<Fq> =
            fq_repr.iter().map(|a| Fq::from_repr(*a).unwrap()).collect();

        // Create values with every fr_value in each component.
        let values = fq_values
            .iter()
            .copied()
            .map(|x| Fq2 {
                c0: x,
                c1: fq_values[0],
            })
            .chain(fq_values.iter().copied().map(|y| Fq2 {
                c0: Fq::from(2), // ensure no repeats
                c1: y,
            }));

        // Hash each value
        let hashed_values: Vec<Fr> = values
            .flat_map(|v| {
                run_circuit_mock_test(
                    "src/tests/configs/hashing.config",
                    |ctx: &mut GateThreadBuilder<Fr>,
                     circuit_config: &CircuitWithLimbsConfig,
                     _test_config: &HashCheck,
                     _instance: &mut Vec<AssignedValue<Fr>>| {
                        build_circuit(ctx, circuit_config, v)
                    },
                )
            })
            .collect();

        // Ensure there are no repeats (indicating a limb/component that does not
        // contribute to the hash).
        for i in 0..hashed_values.len() {
            // Ensure that hashed_values[i] not in hashed_values[i+1 ...].
            assert!(!hashed_values[i + 1..].contains(&hashed_values[i]));
        }
    }

    /// Check agreement of the in-circuit and out-of-circuit implementations
    /// of non-native (extension) field element hashing.
    #[test]
    fn test_hash_fq2_mock() {
        // Sample some random values and make sure that the test passes for
        // all of them.

        run_circuit_mock_test(
            "src/tests/configs/hashing.config",
            |ctx: &mut GateThreadBuilder<Fr>,
             circuit_config: &CircuitWithLimbsConfig,
             _test_config: &HashCheck,
             _instance: &mut Vec<AssignedValue<Fr>>| {
                for _ in 0..5 {
                    let v = Fq2::random(OsRng);
                    build_circuit(ctx, circuit_config, v);
                }
            },
        );
    }
}

mod vk_hash {
    use crate::{
        batch_verify::{
            common::chip::BatchVerifierChip,
            fixed::{
                chip::FixedBatchVerifierChip, native::compute_vk_hash,
                types::UPA_V0_9_0_CIRCUITID_DOMAIN_TAG_STRING,
            },
        },
        tests::*,
        CircuitWithLimbsConfig,
    };
    use core::fmt::Debug;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::{
            arithmetic::CurveAffine,
            halo2curves::bn256::{Fq, Fq2, Fr},
        },
    };
    use halo2_ecc::fields::fp::FpChip;
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    struct HashCheck {}

    /// Simple circuit to compute a CircuitId (vk_hash).  Compares the result
    /// to the output of the native `compute_vk_hash` function.
    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        circuit_config: &CircuitWithLimbsConfig,
        _config: &HashCheck,
        instance: &mut Vec<AssignedValue<Fr>>,
    ) {
        let ctx = builder.main(0);
        let vk = load_vk(VK_FILE);

        // Compute vk_hash in circuit

        let range = RangeChip::<Fr>::default(circuit_config.lookup_bits);
        let fp_chip = FpChip::<Fr, Fq>::new(
            &range,
            circuit_config.limb_bits,
            circuit_config.num_limbs,
        );
        let common_bv_chip = BatchVerifierChip::<_>::new(&fp_chip);
        let batch_verifier = FixedBatchVerifierChip::new(&common_bv_chip);
        let a_vk = batch_verifier.assign_verification_key(ctx, &vk);
        let vk_hash = batch_verifier.compute_vk_hash(ctx, &a_vk);

        // Compute vk_hash natively

        let expect_vk_hash = compute_vk_hash(circuit_config, &vk);

        assert_eq!(
            &expect_vk_hash,
            vk_hash.value(),
            "in-circuit vk_hash matches natively computed one"
        );

        instance.push(vk_hash);
    }

    #[test]
    fn test_hash_vk_mock() {
        run_circuit_mock_test(
            "src/tests/configs/hashing.config",
            build_circuit,
        );
    }

    #[ignore = "takes too long"]
    #[test]
    fn test_hash_vk() {
        run_circuit_test("src/tests/configs/hashing.config", build_circuit);
    }

    #[test]
    fn decompose_fq_test_vector() {
        let vk = load_vk(VK_FILE);

        let fq: Fq = {
            let coords = <G1Affine as CurveAffine>::coordinates(&vk.alpha)
                .expect("invalid coords");
            *coords.x()
        };
        let fqe: Fq2 = {
            let coords = <G2Affine as CurveAffine>::coordinates(&vk.beta)
                .expect("invalid coords");
            *coords.x()
        };
        let g1: G1Affine = vk.alpha;
        let g2: G2Affine = vk.beta;

        {
            let fq_components = decompose_fq::<G1Affine>(&fq);
            println!("Fq: {fq:?}");
            println!("  components: {fq_components:?}");
        }

        {
            let fqe_components = decompose_fqe::<G1Affine, 2, Fq2>(&fqe);
            println!("Fqe: {fqe:?}");
            println!("  components: {fqe_components:?}");
        }

        {
            let g1_components = decompose_g1::<G1Affine>(&g1);
            println!("G1: {g1:?}");
            println!("  components: {g1_components:?}");
        }

        {
            let g2_components = decompose_g2::<G1Affine, 2, G2Affine>(&g2);
            println!("G2: {g2:?}");
            println!("  components: {g2_components:?}");
        }
    }
}
