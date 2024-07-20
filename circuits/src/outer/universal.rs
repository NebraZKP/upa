use crate::{
    batch_verify::universal::{
        types::UniversalBatchVerifierConfig, utils::dummy_ubv_snark,
    },
    keccak::{
        inputs::KeccakCircuitInputs,
        utils::{
            inputs_per_application_proof, keccak_inputs_from_ubv_instances,
        },
    },
    outer::{OuterCircuit, OuterGateConfig},
    utils::upa_config::UpaConfig,
};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::{commitment::ParamsKZG, multiopen::ProverSHPLONK},
};
use itertools::Itertools;
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, Snark};

/// `UniversalOuterCircuit` is responsible for recursively verifying
/// some number of proofs from the `UniversalBatchVerifyCircuit` and
/// an accompanying `KeccakCircuit` proof.
pub struct UniversalOuterCircuit {
    inner: AggregationCircuit,
    gate_config: OuterGateConfig,
}

impl OuterCircuit for UniversalOuterCircuit {
    type Config = UpaConfig;

    type BatchVerifyConfig = UniversalBatchVerifierConfig;

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
        dummy_ubv_snark::<ProverSHPLONK<Bn256>>(bv_params, bv_config)
    }

    fn keccak_inputs_from_bv_instances<'a>(
        bv_config: &Self::BatchVerifyConfig,
        bv_instances: impl ExactSizeIterator<Item = &'a [Fr]>,
    ) -> KeccakCircuitInputs<Fr> {
        KeccakCircuitInputs::VarLen(keccak_inputs_from_ubv_instances(
            bv_instances,
            bv_config.max_num_public_inputs as usize,
            bv_config.inner_batch_size as usize,
        ))
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
        let num_keccak_inputs_per_ubv_snark =
            inner_batch_size * inputs_per_application_proof(num_pub_ins);
        assert_eq!(
            keccak_instances.len(),
            outer_batch_size * num_keccak_inputs_per_ubv_snark + 2,
            "Unexpected Keccak input size"
        );

        for (ubv_instance, keccak_chunk) in inner
            .previous_instances
            .iter()
            .take(outer_batch_size)
            .zip(keccak_instances.chunks(num_keccak_inputs_per_ubv_snark))
        {
            for (ubv, keccak) in ubv_instance.iter().zip_eq(keccak_chunk) {
                ctx.constrain_equal(ubv, keccak)
            }
        }

        // Expose keccak output digest
        inner.inner.assigned_instances.extend_from_slice(
            &keccak_instances
                [(outer_batch_size * num_keccak_inputs_per_ubv_snark)..],
        );
    }

    fn from_inner(
        inner: AggregationCircuit,
        gate_config: OuterGateConfig,
    ) -> Self {
        Self { inner, gate_config }
    }
}
