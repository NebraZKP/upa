extern crate alloc;

use crate::EccPrimeField;
use halo2_base::halo2_proofs::halo2curves::{
    bn256::{Fr, G1Affine, G2Affine},
    CurveAffineExt,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct VerificationKey<C1 = G1Affine, C2 = G2Affine>
where
    C1: CurveAffineExt,
    C2: CurveAffineExt,
{
    pub alpha: C1,
    pub beta: C2,
    pub gamma: C2,
    pub delta: C2,
    pub s: Vec<C1>,
}

impl<C1: CurveAffineExt, C2: CurveAffineExt> VerificationKey<C1, C2> {
    /// Create a dummy VK for some given number of public inputs. Existence of
    /// Pedersen commitment is specified by `has_commitment`. Length is
    /// arguably ambiguous, but this is named to match the PublicInputs
    /// method.
    pub fn default_with_length(
        num_public_inputs: usize,
        has_commitment: bool,
    ) -> Self {
        let g1 = C1::generator();
        let g2 = C2::generator();
        // Note, we need an extra s entry for the 0-th PI with value "1"
        VerificationKey {
            alpha: g1,
            beta: g2,
            gamma: g2,
            delta: g2,
            s: vec![g1; num_public_inputs + 1],
        }
    }

    /// Pads the public input points of `self` to `total_len` using the generator.
    /// Pads the Pedersen commitment key with default values, if not already present.
    pub fn pad(&mut self, total_len: usize) {
        assert!(total_len + 1 >= self.s.len(), "VK over total length");
        let padding = (self.s.len()..total_len + 1)
            .into_iter()
            .map(|_| C1::generator());
        self.s.extend(padding);
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

impl Proof {
    /// Return a dummy proof, with or without Pedersen commitment points.
    pub fn default_with_commitment(has_commitment: bool) -> Self {
        let g1 = G1Affine::generator();
        Proof {
            a: g1,
            b: G2Affine::generator(),
            c: g1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PublicInputs<F = Fr>(pub Vec<F>)
where
    F: EccPrimeField;

impl<F: EccPrimeField> PublicInputs<F> {
    pub fn default_with_length(num_public_inputs: usize) -> Self {
        PublicInputs(vec![F::zero(); num_public_inputs])
    }

    /// Pads `self` to `total_len` using zeros.
    pub fn pad(&mut self, total_len: usize) {
        assert!(total_len >= self.0.len(), "Too many public inputs");
        let padding = (self.0.len()..total_len).into_iter().map(|_| F::zero());
        self.0.extend(padding)
    }
}
