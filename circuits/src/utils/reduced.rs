use crate::EccPrimeField;
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::EcPoint,
    fields::{fp::Reduced, vector::FieldVector},
};

/// Conversion from a reduced (unique) represenation to a regular
/// representation.
pub trait FromReduced<R> {
    fn from_reduced(reduced: R) -> Self;
}

impl<F: EccPrimeField, Fp: Clone>
    FromReduced<&EcPoint<F, Reduced<ProperCrtUint<F>, Fp>>>
    for EcPoint<F, ProperCrtUint<F>>
{
    fn from_reduced(
        reduced: &EcPoint<F, Reduced<ProperCrtUint<F>, Fp>>,
    ) -> Self {
        EcPoint::new(reduced.x.inner().clone(), reduced.y.inner().clone())
    }
}

impl<F: EccPrimeField, Fp: Clone>
    FromReduced<&EcPoint<F, FieldVector<Reduced<ProperCrtUint<F>, Fp>>>>
    for EcPoint<F, FieldVector<ProperCrtUint<F>>>
{
    fn from_reduced(
        reduced: &EcPoint<F, FieldVector<Reduced<ProperCrtUint<F>, Fp>>>,
    ) -> Self {
        EcPoint::new(
            FieldVector::<ProperCrtUint<F>>::from(&reduced.x),
            FieldVector::<ProperCrtUint<F>>::from(&reduced.y),
        )
    }
}

impl<'a, R, T: FromReduced<&'a R>> FromReduced<&'a Vec<R>> for Vec<T> {
    fn from_reduced(reduced: &'a Vec<R>) -> Self {
        reduced.iter().map(T::from_reduced).collect()
    }
}
