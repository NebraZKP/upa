use crate::EccPrimeField;
use halo2_base::utils::CurveAffineExt;
use halo2_ecc::fields::FieldExtConstructor;
use tiny_keccak::{Hasher, Keccak};

pub struct KeccakHasher(Keccak);

impl KeccakHasher {
    pub fn new() -> KeccakHasher {
        KeccakHasher(Keccak::v256())
    }

    pub fn absorb_bytes(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn absorb_f<F: EccPrimeField>(&mut self, f: &F) {
        let mut bytes = f.to_bytes_le();
        bytes.reverse();
        self.absorb_bytes(&bytes);
    }

    pub fn absorb_fqe<
        Fqe: FieldExtConstructor<F, DEGREE>,
        const DEGREE: usize,
        F: EccPrimeField,
    >(
        &mut self,
        fqe: &Fqe,
    ) {
        for f in fqe.coeffs() {
            self.absorb_f(&f);
        }
    }

    pub fn absorb_g1<C1: CurveAffineExt>(&mut self, g: &C1)
    where
        C1::Base: EccPrimeField,
    {
        let coords = g.coordinates().expect("invalid coords");
        self.absorb_f(coords.x());
        self.absorb_f(coords.y());
    }

    pub fn absorb_g2<
        C2: CurveAffineExt,
        const DEGREE: usize,
        F: EccPrimeField,
    >(
        &mut self,
        g: &C2,
    ) where
        C2::Base: FieldExtConstructor<F, DEGREE>,
    {
        let coords = g.coordinates().expect("invalid coords");
        self.absorb_fqe(coords.x());
        self.absorb_fqe(coords.y());
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut output = [0u8; 32];
        self.0.finalize(&mut output);
        output
    }
}

impl Default for KeccakHasher {
    fn default() -> Self {
        Self::new()
    }
}
