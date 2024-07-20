//! Native functions common to all Batch Verify circuits
use crate::{
    batch_verify::common::types::VerificationKey,
    utils::{
        hashing::{compute_domain_tag, WrongFieldHasher},
        keccak_hasher::KeccakHasher,
    },
    CircuitWithLimbsConfig, EccPrimeField,
};
use halo2_base::utils::CurveAffineExt;
use halo2_ecc::fields::FieldExtConstructor;

// Keccak hash of VK, for CircuitID calculations in UBV
pub(crate) fn compute_vk_keccak_hash_with_domain_tag<
    C1,
    C2,
    const DEGREE: usize,
>(
    vk: &VerificationKey<C1, C2>,
    domain_tag_str: &str,
) -> [u8; 32]
where
    C1: CurveAffineExt,
    C2: CurveAffineExt,
    C1::ScalarExt: EccPrimeField,
    C1::Base: EccPrimeField,
    C2::Base: FieldExtConstructor<C1::Base, DEGREE>,
{
    assert!(vk.s.len() > 1, "VK must support >0 public inputs");

    // TODO: Do this outside this function and pass in the bytes
    let domain_tag = compute_domain_tag(domain_tag_str);

    let mut hasher = KeccakHasher::new();
    hasher.absorb_bytes(&domain_tag);
    hasher.absorb_g1(&vk.alpha);
    hasher.absorb_g2(&vk.beta);
    hasher.absorb_g2(&vk.gamma);
    hasher.absorb_g2(&vk.delta);
    hasher.absorb_f(&C1::Base::from(vk.s.len() as u64));
    for s in vk.s.iter() {
        hasher.absorb_g1(s);
    }

    // Absorb the commitment terms if present.
    if vk.has_commitment() {
        hasher.absorb_g2(&vk.h1[0]);
        hasher.absorb_g2(&vk.h2[0]);
    }

    hasher.finalize()
}

// Poseidon hash of the VK (without domain tag) for challenge calculations in
// UBV.
pub(crate) fn compute_vk_poseidon_hash<C1, C2, const DEGREE: usize>(
    circuit_config: &CircuitWithLimbsConfig,
    vk: &VerificationKey<C1, C2>,
    max_num_public_inputs: usize,
) -> C1::ScalarExt
where
    C1: CurveAffineExt,
    C2: CurveAffineExt,
    C1::ScalarExt: EccPrimeField,
    C1::Base: EccPrimeField,
    C2::Base: FieldExtConstructor<C1::Base, DEGREE>,
{
    let mut hasher = WrongFieldHasher::<C1, C2>::new(circuit_config, None);
    hasher.absorb_g1(&vk.alpha);
    hasher.absorb_g2(&vk.beta);
    hasher.absorb_g2(&vk.gamma);
    hasher.absorb_g2(&vk.delta);

    for s in vk.s.iter() {
        hasher.absorb_g1(s);
    }

    let g1_generator = C1::generator();
    for _ in vk.s.len()..max_num_public_inputs + 1 {
        hasher.absorb_g1(&g1_generator);
    }

    if vk.has_commitment() {
        hasher.absorb_g2(&vk.h1[0]);
        hasher.absorb_g2(&vk.h2[0]);
    } else {
        let g2_generator = C2::generator();
        hasher.absorb_g2(&g2_generator);
        hasher.absorb_g2(&g2_generator);
    }

    hasher.hasher.squeeze()
}

pub mod unsafe_proof_generation {
    //! Unsafe proof generation module.
    //!
    //! This module generates valid Groth16 proofs with their corresponding vk
    //! by computing both of them from the simulation trapdoor.
    use super::json::{
        field_element_from_str, field_element_to_str, JsonVerificationKey,
    };
    use crate::{
        batch_verify::common::types::{Proof, PublicInputs, VerificationKey},
        utils::commitment_point::{
            be_bytes_to_field_element, commitment_hash_bytes_from_g1_point,
        },
    };
    use halo2_base::halo2_proofs::{
        arithmetic::Field,
        halo2curves::bn256::{Fr, G1Affine, G2Affine},
    };
    use itertools::Itertools;
    use rand_core::RngCore;
    use serde::{Deserialize, Serialize};

    /// Unsafe Verification Key
    pub struct UnsafeVerificationKey {
        alpha: Fr,
        beta: Fr,
        gamma: Fr,
        delta: Fr,
        s: Vec<Fr>,
        /// Commitment proof-of-knowledge trapdoor
        sigma: Option<Fr>,
        vk: VerificationKey,
    }

    impl UnsafeVerificationKey {
        /// Builds a new [`UnsafeVerificationKey`] from its [`Fr`] constants.
        fn from_constants(
            alpha: Fr,
            beta: Fr,
            gamma: Fr,
            delta: Fr,
            s: Vec<Fr>,
            sigma: Option<Fr>,
        ) -> Self {
            let g1 = G1Affine::generator();
            let g2 = G2Affine::generator();
            let alpha_vk = g1 * alpha;
            let beta_vk = g2 * beta;
            let gamma_vk = g2 * gamma;
            let delta_vk = g2 * delta;
            let s_vk =
                s.iter().map(|elem| G1Affine::from(g1 * elem)).collect_vec();
            // Requirement is h2 = -1/sigma * h1
            let (h1, h2) = match sigma {
                Some(sigma) => (vec![(-g2 * sigma).into()], vec![g2]),
                _ => (vec![], vec![]),
            };
            Self {
                alpha,
                beta,
                gamma,
                delta,
                s,
                sigma,
                vk: VerificationKey {
                    alpha: alpha_vk.into(),
                    beta: beta_vk.into(),
                    gamma: gamma_vk.into(),
                    delta: delta_vk.into(),
                    s: s_vk,
                    h1,
                    h2,
                },
            }
        }

        /// Samples a new [`UnsafeVerificationKey`] to generate Groth16 proofs with
        /// `num_pub_inputs`. Pr
        pub fn sample<R>(
            num_pub_inputs: usize,
            has_commitment: bool,
            rng: &mut R,
        ) -> Self
        where
            R: RngCore + ?Sized,
        {
            let alpha = Fr::random(&mut *rng);
            let beta = Fr::random(&mut *rng);
            let gamma = Fr::random(&mut *rng);
            let delta = Fr::random(&mut *rng);
            let s = (0..num_pub_inputs + 1 + has_commitment as usize)
                .map(|_| Fr::random(&mut *rng))
                .collect_vec();
            let sigma = if has_commitment {
                Some(Fr::random(&mut *rng))
            } else {
                None
            };
            Self::from_constants(alpha, beta, gamma, delta, s, sigma)
        }

        /// Create a [`Proof`] and [`PublicInputs`] for this vk
        pub fn create_proof_and_inputs<R>(
            &self,
            rng: &mut R,
        ) -> (Proof, PublicInputs)
        where
            R: RngCore + ?Sized,
        {
            let has_commitment = self.sigma.is_some();
            let num_pub_inputs = self.s.len() - 1 - has_commitment as usize;
            let inputs = (0..num_pub_inputs)
                .map(|_| Fr::random(&mut *rng))
                .collect_vec();
            let proof = self.create_proof(&inputs, rng);
            (proof, PublicInputs(inputs))
        }

        /// Creates a [`Proof`] which will verify against `public_inputs`
        pub fn create_proof<R>(
            &self,
            public_inputs: &[Fr],
            rng: &mut R,
        ) -> Proof
        where
            R: RngCore + ?Sized,
        {
            let a = Fr::random(&mut *rng);
            let b = Fr::random(&mut *rng);
            let mut pi_term = self
                .s
                .iter()
                .skip(1)
                .zip(public_inputs.iter())
                .fold(self.s[0], |b, (s_i, pi_i)| b + s_i * pi_i);
            let g1 = G1Affine::generator();
            let g2 = G2Affine::generator();

            let (m_scalar, m_point, pok) = match self.sigma {
                Some(sigma) => {
                    // Commitment requires
                    //   M = m * G
                    // pok = m * (sigma * G)
                    let m = Fr::random(&mut *rng);
                    let result = (
                        m,
                        vec![(g1 * m).into()],
                        vec![(g1 * sigma * m).into()],
                    );
                    let last_pi: Fr = be_bytes_to_field_element(
                        &commitment_hash_bytes_from_g1_point(&result.1[0]),
                    );
                    pi_term +=
                        last_pi * self.s.last().expect("s cannot be empty");
                    result
                }
                _ => (Fr::zero(), vec![], vec![]),
            };

            let c = (a * b
                - self.alpha * self.beta
                - (pi_term + m_scalar) * self.gamma)
                * self.delta.invert().expect("Delta can't be zero");

            Proof {
                a: (g1 * a).into(),
                b: (g2 * b).into(),
                c: (g1 * c).into(),
                m: m_point,
                pok,
            }
        }

        /// Returns the [`VerificationKey`], consuming `self`
        pub fn into_vk(self) -> VerificationKey {
            self.vk
        }

        pub fn vk(&self) -> &VerificationKey {
            &self.vk
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct JsonUnsafeVerificationKey {
        pub alpha: String,
        pub beta: String,
        pub gamma: String,
        pub delta: String,
        pub s: Vec<String>,
        pub sigma: Option<String>,
        pub vk: JsonVerificationKey,
    }

    impl From<&JsonUnsafeVerificationKey> for UnsafeVerificationKey {
        fn from(json: &JsonUnsafeVerificationKey) -> Self {
            UnsafeVerificationKey::from_constants(
                field_element_from_str(&json.alpha),
                field_element_from_str(&json.beta),
                field_element_from_str(&json.gamma),
                field_element_from_str(&json.delta),
                json.s
                    .iter()
                    .map(|s| field_element_from_str(s.as_str()))
                    .collect(),
                json.sigma.as_ref().map(|str| field_element_from_str(str)),
            )
        }
    }

    impl From<&UnsafeVerificationKey> for JsonUnsafeVerificationKey {
        fn from(uvk: &UnsafeVerificationKey) -> Self {
            JsonUnsafeVerificationKey {
                alpha: field_element_to_str(&uvk.alpha),
                beta: field_element_to_str(&uvk.beta),
                gamma: field_element_to_str(&uvk.gamma),
                delta: field_element_to_str(&uvk.delta),
                s: uvk.s.iter().map(field_element_to_str).collect(),
                sigma: uvk.sigma.map(|sigma| field_element_to_str(&sigma)),
                vk: (&uvk.vk).into(),
            }
        }
    }

    /// Test helper that returns `num_proofs` application circuit proofs, public inputs,
    /// and verification keys.
    ///
    /// # Note
    ///
    /// We choose to keep this function outside the test module because we intend to
    /// use it for benchmarks on top of tests, and criterion doesn't allow
    /// imports under the `#[cfg(test)]` flag.
    pub fn sample_proofs_inputs_vk<R>(
        num_pub_inputs: usize,
        has_commitment: bool,
        num_proofs: usize,
        rng: &mut R,
    ) -> (Vec<(Proof, PublicInputs)>, VerificationKey)
    where
        R: RngCore + ?Sized,
    {
        let unsafe_vk =
            UnsafeVerificationKey::sample(num_pub_inputs, has_commitment, rng);
        let mut result = Vec::with_capacity(num_proofs);
        for _ in 0..num_proofs {
            let public_inputs = (0..num_pub_inputs)
                .into_iter()
                .map(|_| Fr::random(&mut *rng))
                .collect_vec();
            let proof = unsafe_vk.create_proof(&public_inputs, rng);
            result.push((proof, PublicInputs(public_inputs)));
        }
        (result, unsafe_vk.into_vk())
    }
}

/// JSON types for IO
pub mod json {
    use crate::{
        batch_verify::common::types::{Proof, PublicInputs, VerificationKey},
        utils::file::load_json,
        EccPrimeField,
    };
    use halo2_base::halo2_proofs::halo2curves::bn256::{
        Fq2, G1Affine, G2Affine,
    };
    use serde::{Deserialize, Serialize};

    /// Accepts a hex string, strips any leading 0x, and extends to be an even
    /// number of chars.  Converts to a [u8; 32] in reverse order, padded at the
    /// end.
    fn le_bytes32_from_hex(s: &str) -> Result<[u8; 32], String> {
        fn from_sanitized_hex(s: &str) -> Result<[u8; 32], String> {
            let hex_bytes =
                hex::decode(s).unwrap_or_else(|e| panic!("invalid hex: {e}"));
            let num_bytes = hex_bytes.len();
            let byte_offset = 32 - num_bytes;
            let mut bytes = [0u8; 32];
            bytes[byte_offset..].clone_from_slice(&hex_bytes);
            bytes.reverse();
            Ok(bytes)
        }

        // Remove the leading 0x
        let s = if let Some(stripped) = s.strip_prefix("0x") {
            stripped
        } else {
            s
        };

        if s.len() % 2 == 0 {
            from_sanitized_hex(s)
        } else {
            let mut new_s = String::with_capacity(s.len() + 1);
            new_s.push('0');
            new_s.push_str(s);
            assert!(new_s.len() % 2 == 0);
            from_sanitized_hex(&new_s)
        }
    }

    pub fn field_element_from_str<F>(s: &str) -> F
    where
        F: EccPrimeField<Repr = [u8; 32]>,
    {
        if s.starts_with("0x") {
            let bytes = le_bytes32_from_hex(s).unwrap_or_else(|e| {
                panic!("Failed to parse Fr hex string: {s}: {e}")
            });
            F::from_repr(bytes)
                .expect(&format!("Failed to convert bytes to F: {s}"))
        } else {
            F::from_str_vartime(s)
                .unwrap_or_else(|| panic!("Failed to parse Fr string: {s}"))
        }
    }

    pub fn field_element_to_str<F: EccPrimeField>(f: &F) -> String {
        format!("{f:?}")
    }

    pub fn g1_from_json(json: &[String; 2]) -> G1Affine {
        G1Affine {
            x: field_element_from_str(&json[0]),
            y: field_element_from_str(&json[1]),
        }
    }

    pub fn g1_to_json(g1: &G1Affine) -> [String; 2] {
        [field_element_to_str(&g1.x), field_element_to_str(&g1.y)]
    }

    pub fn fq2_from_json(json: &[String; 2]) -> Fq2 {
        Fq2 {
            c0: field_element_from_str(&json[0]),
            c1: field_element_from_str(&json[1]),
        }
    }

    pub fn fq2_to_json(fq2: &Fq2) -> [String; 2] {
        [field_element_to_str(&fq2.c0), field_element_to_str(&fq2.c1)]
    }

    pub fn g2_from_json(json: &[[String; 2]; 2]) -> G2Affine {
        G2Affine {
            x: fq2_from_json(&json[0]),
            y: fq2_from_json(&json[1]),
        }
    }

    pub fn g2_to_json(g2: &G2Affine) -> [[String; 2]; 2] {
        [fq2_to_json(&g2.x), fq2_to_json(&g2.y)]
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    pub struct JsonVerificationKey {
        pub alpha: [String; 2],
        pub beta: [[String; 2]; 2],
        pub gamma: [[String; 2]; 2],
        pub delta: [[String; 2]; 2],
        pub s: Vec<[String; 2]>,
        pub h1: Vec<[[String; 2]; 2]>,
        pub h2: Vec<[[String; 2]; 2]>,
    }

    impl From<&JsonVerificationKey> for VerificationKey {
        fn from(vk_json: &JsonVerificationKey) -> Self {
            if vk_json.h1.len() != vk_json.h2.len() {
                panic!("Invalid VK. Inconsistent h1, h2")
            }
            VerificationKey {
                alpha: g1_from_json(&vk_json.alpha),
                beta: g2_from_json(&vk_json.beta),
                gamma: g2_from_json(&vk_json.gamma),
                delta: g2_from_json(&vk_json.delta),
                s: vk_json.s.iter().map(g1_from_json).collect(),
                h1: vk_json.h1.iter().map(g2_from_json).collect(),
                h2: vk_json.h2.iter().map(g2_from_json).collect(),
            }
        }
    }

    impl From<&VerificationKey> for JsonVerificationKey {
        fn from(vk: &VerificationKey) -> Self {
            JsonVerificationKey {
                alpha: g1_to_json(&vk.alpha),
                beta: g2_to_json(&vk.beta),
                gamma: g2_to_json(&vk.gamma),
                delta: g2_to_json(&vk.delta),
                s: vk.s.iter().map(g1_to_json).collect(),
                h1: vk.h1.iter().map(g2_to_json).collect(),
                h2: vk.h2.iter().map(g2_to_json).collect(),
            }
        }
    }

    /// Matches the SDK `application.Proof` structure in the client SDK, which is
    /// the output from snarkjs.fullProve (i.e. using natural Fq2 component
    /// ordering).
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct JsonProof {
        pub pi_a: [String; 2],
        pub pi_b: [[String; 2]; 2],
        pub pi_c: [String; 2],
        pub m: Vec<[String; 2]>,
        pub pok: Vec<[String; 2]>,
    }

    impl From<&JsonProof> for Proof {
        fn from(json: &JsonProof) -> Self {
            assert_eq!(
                json.m.len(),
                json.pok.len(),
                "Bad data, proof.m proof.pok length mismatch"
            );
            assert!(
                json.m.len() < 2,
                "Multiple commitment points not supported."
            );
            Proof {
                a: g1_from_json(&json.pi_a),
                b: g2_from_json(&json.pi_b),
                c: g1_from_json(&json.pi_c),
                m: json.m.iter().map(g1_from_json).collect(),
                pok: json.pok.iter().map(g1_from_json).collect(),
            }
        }
    }

    impl From<&Proof> for JsonProof {
        fn from(proof: &Proof) -> Self {
            assert_eq!(
                proof.m.len(),
                proof.pok.len(),
                "Bad data, proof.m proof.pok length mismatch"
            );
            assert!(
                proof.m.len() < 2,
                "Multiple commitment points not supported."
            );
            JsonProof {
                pi_a: g1_to_json(&proof.a),
                pi_b: g2_to_json(&proof.b),
                pi_c: g1_to_json(&proof.c),
                m: proof.m.iter().map(g1_to_json).collect(),
                pok: proof.pok.iter().map(g1_to_json).collect(),
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct JsonPublicInputs(Vec<String>);

    impl From<&JsonPublicInputs> for PublicInputs {
        fn from(json: &JsonPublicInputs) -> Self {
            PublicInputs(
                json.0.iter().map(|s| field_element_from_str(s)).collect(),
            )
        }
    }

    impl From<&PublicInputs> for JsonPublicInputs {
        fn from(inputs: &PublicInputs) -> Self {
            JsonPublicInputs(
                inputs.0.iter().map(field_element_to_str).collect(),
            )
        }
    }

    pub fn load_vk(filename: &str) -> VerificationKey {
        let vk_json: JsonVerificationKey = load_json(filename);
        VerificationKey::from(&vk_json)
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct JsonProofAndInputs {
        pub proof: JsonProof,
        pub inputs: JsonPublicInputs,
    }

    // TODO: create the native version of ProofAndInputs and use this instead of
    // (Proof, PublicInputs).  Implement From<JsonProofAndInputs> for
    // ProofAndInputs.

    pub fn load_proof_and_inputs(filename: &str) -> (Proof, PublicInputs) {
        let proof_pi_json: JsonProofAndInputs = load_json(filename);
        (
            Proof::from(&proof_pi_json.proof),
            PublicInputs::from(&proof_pi_json.inputs),
        )
    }

    pub fn load_proof_and_inputs_batch(
        filename: &str,
    ) -> Vec<(Proof, PublicInputs)> {
        let proof_pi_json: Vec<JsonProofAndInputs> = load_json(filename);
        proof_pi_json
            .iter()
            .map(|proof_pi_json| {
                (
                    Proof::from(&proof_pi_json.proof),
                    PublicInputs::from(&proof_pi_json.inputs),
                )
            })
            .collect()
    }
}
