use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

/// `EquivalenceGadget` enforces that two in-circuit variables are equivalent,
/// where the equivalence relation is parameterized by `M`:
/// - For `FpVar`, it is simply an equality relation, and `M` is unused.
/// - For `NonNativeUintVar`, we consider equivalence as a congruence relation,
///   in terms of modular arithmetic, so `M` specifies the modulus.
pub trait EquivalenceGadget<M> {
    fn enforce_equivalent(&self, other: &Self) -> Result<(), SynthesisError>;
}
impl<M, F: PrimeField> EquivalenceGadget<M> for FpVar<F> {
    fn enforce_equivalent(&self, other: &Self) -> Result<(), SynthesisError> {
        self.enforce_equal(other)
    }
}
impl<M, T: EquivalenceGadget<M>> EquivalenceGadget<M> for [T] {
    fn enforce_equivalent(&self, other: &Self) -> Result<(), SynthesisError> {
        self.iter()
            .zip(other)
            .try_for_each(|(a, b)| a.enforce_equivalent(b))
    }
}
