use crate::{
    batch_verify::fixed::{
        types::BatchVerifyConfig, utils::dummy_batch_verify_snark,
    },
    keccak::inputs::KeccakCircuitInputs,
    outer::{OuterCircuit, OuterGateConfig},
    utils::upa_config::UpaConfig,
};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::{commitment::ParamsKZG, multiopen::ProverSHPLONK},
};
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, Snark};

pub struct FixedOuterCircuit {
    inner: AggregationCircuit,
    gate_config: OuterGateConfig,
}

impl OuterCircuit for FixedOuterCircuit {
    type Config = UpaConfig;

    type BatchVerifyConfig = BatchVerifyConfig;

    fn bv_config(config: &Self::Config) -> Self::BatchVerifyConfig {
        config.into()
    }

    fn keccak_config(config: &Self::Config) -> crate::keccak::KeccakConfig {
        config.into()
    }

    fn gate_config(&self) -> &OuterGateConfig {
        &self.gate_config
    }

    fn degree_bits(config: &Self::Config) -> usize {
        config.outer_config.degree_bits as usize
    }

    fn outer_batch_size(config: &Self::Config) -> usize {
        config.outer_batch_size as usize
    }

    fn dummy_bv_snark(
        bv_params: &ParamsKZG<Bn256>,
        bv_config: &Self::BatchVerifyConfig,
    ) -> Snark {
        dummy_batch_verify_snark::<ProverSHPLONK<Bn256>>(bv_params, bv_config)
    }

    fn keccak_inputs_from_bv_instances<'a>(
        _bv_config: &Self::BatchVerifyConfig,
        _bv_instances: impl ExactSizeIterator<Item = &'a [Fr]>,
    ) -> KeccakCircuitInputs<Fr> {
        unimplemented!("TODO: remove fixed outer circuit")
    }

    fn inner(&self) -> &AggregationCircuit {
        &self.inner
    }

    fn expose_final_digest_and_constrain(
        inner: &mut AggregationCircuit,
        config: &Self::Config,
    ) {
        let inner_batch_size = config.inner_batch_size as usize;
        let outer_batch_size = config.outer_batch_size as usize;
        let num_pub_ins = config.max_num_app_public_inputs as usize;

        let mut builder = inner.inner.circuit.0.builder.borrow_mut();
        let ctx = builder.main(0);
        let keccak_instances = inner
            .previous_instances
            .last()
            .expect("Keccak instance must exist");
        // The keccak instances repeat vk_hash for each application proof in each bv snark
        let num_keccak_inputs_per_bv_snark =
            inner_batch_size * (1 + num_pub_ins);
        assert_eq!(
            keccak_instances.len(),
            outer_batch_size * num_keccak_inputs_per_bv_snark + 2,
            "Unexpected Keccak input size"
        );

        for (bv_instance, keccak_chunk) in inner
            .previous_instances
            .iter()
            .take(outer_batch_size)
            .zip(keccak_instances.chunks(num_keccak_inputs_per_bv_snark))
        {
            // bv_instance:
            // vk_hash
            // app_1_pi_1 ... app_1_pi_k
            // ...
            // app_n_pi_1 ... app_n_pi_k

            // keccak_chunk:
            // vk_hash
            // app_1_pi_1 ... app_1_pi_k
            // vk_hash
            // app_2_pi_1 ... app_2_pi_k
            // ...
            // vk_hash
            // app_n_pi_1 ... app_n_pi_k

            for (app_idx, app_chunk) in
                keccak_chunk.chunks(1 + num_pub_ins).enumerate()
            {
                // Constrain vk_hash
                ctx.constrain_equal(&bv_instance[0], &app_chunk[0]);
                for idx in 0..num_pub_ins {
                    ctx.constrain_equal(
                        &bv_instance[(1 + app_idx * num_pub_ins) + idx],
                        &app_chunk[1 + idx],
                    );
                }
            }
        }

        // Expose keccak output digest
        inner.inner.assigned_instances.extend_from_slice(
            &keccak_instances
                [(outer_batch_size * num_keccak_inputs_per_bv_snark)..],
        );
    }

    fn from_inner(
        inner: AggregationCircuit,
        gate_config: OuterGateConfig,
    ) -> Self {
        Self { inner, gate_config }
    }
}
