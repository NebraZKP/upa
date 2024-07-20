extern crate alloc;

use crate::{
    utils::commitment_point::commitment_hash_bytes_from_g1_point, EccPrimeField,
};
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
    /// Commitment key. Valid lengths are 0, 1.
    pub h1: Vec<C2>,
    /// Commitment key. Valid lengths are 0, 1.
    pub h2: Vec<C2>,
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
            h1: vec![g2; has_commitment as usize],
            h2: vec![g2; has_commitment as usize],
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
        assert_eq!(
            self.h1.len(),
            self.h2.len(),
            "Invalid VK. Inconsistent h1, h2"
        );
        if self.h1.is_empty() {
            self.h1.push(C2::generator());
            self.h2.push(C2::generator());
        }
    }

    /// Check consistency
    pub fn is_well_formed(&self) -> bool {
        let commitment_length = self.h1.len();
        (commitment_length == self.h2.len()) && (commitment_length < 2)
    }

    /// Checks if `self` has a commitment point
    pub fn has_commitment(&self) -> bool {
        assert!(self.is_well_formed());
        match self.h1.len() {
            0 => false,
            1 => true,
            num_commitments => unreachable!("A vk cannot have {num_commitments} after checking it is well-formed")
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
    /// Pedersen Commitment. Valid lengths are 0, 1.
    pub m: Vec<G1Affine>,
    /// Pedersen Commitment Proof of Knowledge. Valid lengths are 0, 1.
    pub pok: Vec<G1Affine>,
}

impl Proof {
    /// Return a dummy proof, with or without Pedersen commitment points.
    pub fn default_with_commitment(has_commitment: bool) -> Self {
        let g1 = G1Affine::generator();
        Proof {
            a: g1,
            b: G2Affine::generator(),
            c: g1,
            m: vec![g1; has_commitment as usize],
            pok: vec![g1; has_commitment as usize],
        }
    }

    /// Detects whether proof contains a non-trivial Pedersen commitment.
    /// If absent, inserts padding values for these commitments.
    /// Argument `has_commitment` is used to check for consistency with
    /// the corresponding VK.
    pub(crate) fn pad(&mut self, has_commitment: bool) {
        assert_eq!(
            self.m.len(),
            self.pok.len(),
            "Invalid proof. Inconsistent m, pok."
        );
        assert_eq!(
            self.m.len(),
            has_commitment as usize,
            "Invalid proof. Not consistent with VK."
        );
        if !has_commitment {
            self.m.push(G1Affine::generator());
            self.pok.push(-G1Affine::generator());
        }
    }

    /// Computes the commitment hash bytes from the commitment
    /// point in `self`, if any.
    pub fn compute_commitment_hash_bytes_from_commitment_point(
        &self,
    ) -> Option<[u8; 32]> {
        self.m.get(0).map(commitment_hash_bytes_from_g1_point)
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
