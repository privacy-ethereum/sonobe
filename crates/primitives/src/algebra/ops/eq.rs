//! This module defines traits for enforcing custom, user-defined equivalence
//! relation between in-circuit variables, enabling flexible checks for equality
//! and congruence.

use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

/// [`EquivalenceGadget`] enforces two in-circuit variables are "equivalent".
///
/// This does not only allow us to ensure the equality of two variables of the
/// same type, but can also be used for guaranteeing variables of different
/// types represent the "same" (depending on the context) value.
pub trait EquivalenceGadget<Other: ?Sized> {
    /// [`EquivalenceGadget::enforce_equivalent`] enforces that `self` and
    /// `other` are equivalent.
    fn enforce_equivalent(&self, other: &Other) -> Result<(), SynthesisError>;
}

impl<F: PrimeField> EquivalenceGadget<FpVar<F>> for FpVar<F> {
    fn enforce_equivalent(&self, other: &FpVar<F>) -> Result<(), SynthesisError> {
        self.enforce_equal(other)
    }
}

impl<S: EquivalenceGadget<T>, T> EquivalenceGadget<[T]> for [S] {
    fn enforce_equivalent(&self, other: &[T]) -> Result<(), SynthesisError> {
        if self.len() != other.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        self.iter()
            .zip(other)
            .try_for_each(|(a, b)| a.enforce_equivalent(b))
    }
}
