//! This module provides definitions and implementations of in-circuit vector
//! operations.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;
use ark_std::ops::Index;

/// [`VectorMulGadget`] defines the multiplication (dot product) operation on
/// in-circuit vector variables.
pub trait VectorMulGadget<Other: ?Sized> {
    type Output;

    fn mul(&self, other: &Other) -> Result<Self::Output, SynthesisError>;
}

impl<F: PrimeField> VectorMulGadget<[FpVar<F>]> for [FpVar<F>] {
    type Output = FpVar<F>;

    fn mul(&self, other: &[FpVar<F>]) -> Result<Self::Output, SynthesisError> {
        if self.len() != other.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(self.iter().zip(other).map(|(a, b)| a * b).sum())
    }
}

impl<F: PrimeField, Other: Index<usize, Output = FpVar<F>>> VectorMulGadget<Other>
    for [(FpVar<F>, usize)]
{
    type Output = FpVar<F>;

    fn mul(&self, other: &Other) -> Result<Self::Output, SynthesisError> {
        Ok(self
            .iter()
            .map(|(value, index)| value * &other[*index])
            .sum())
    }
}
