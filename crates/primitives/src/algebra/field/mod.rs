//! This module defines extension traits for field elements and their in-circuit
//! counterparts, along with some common implementations.

use ark_ff::{BigInteger, Fp, FpConfig, PrimeField};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{
    any::TypeId,
    mem::transmute_copy,
    ops::{Add, Mul},
};

use crate::{
    algebra::field::emulated::EmulatedFieldVar,
    circuits::{
        WitnessToPublic,
        linkage::{Canonical, Emulated, HasConstraintField, HasValue, HasVar},
    },
    traits::{Inputize, InputizeEmulated},
    transcripts::{Absorbable, AbsorbableVar},
};

pub mod emulated;

/// [`SonobeField`] trait is a wrapper around [`PrimeField`] that also includes
/// necessary bounds for the field to be used conveniently in folding schemes.
pub trait SonobeField:
    PrimeField<BasePrimeField = Self>
    + Absorbable
    + Inputize<Self>
    + HasVar<Canonical, Var: FieldVar<Self, Self> + WitnessToPublic>
    + HasVar<Emulated<Self>, Var = EmulatedFieldVar<Self, Self>>
{
    /// [`SonobeField::BITS_PER_LIMB`] defines the bit length of each limb when
    /// representing field elements as limbs in an emulated field variable.
    // TODO: either make it configurable, or compute an optimal value based on
    // the modulus size.
    const BITS_PER_LIMB: usize;
}

impl<P: FpConfig<N>, const N: usize> SonobeField for Fp<P, N> {
    const BITS_PER_LIMB: usize = 32;
}

impl<F: PrimeField> HasConstraintField for FpVar<F> {
    type ConstraintField = F;
}

impl<F: PrimeField> HasValue for FpVar<F> {
    type Value = F;
}

impl<P: FpConfig<N>, const N: usize> HasVar<Canonical> for Fp<P, N> {
    type Var = FpVar<Self>;
}

impl<P: FpConfig<N>, const N: usize, F: SonobeField> HasVar<Emulated<F>> for Fp<P, N> {
    type Var = EmulatedFieldVar<F, Self>;
}

impl<P: FpConfig<N>, const N: usize> Absorbable for Fp<P, N> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        if TypeId::of::<F>() == TypeId::of::<Self>() {
            // Safe because `F` and `Self` have the same type
            // TODO (@winderica): specialization when???
            dest.push(unsafe { transmute_copy::<Self, F>(self) });
        } else {
            let bits_per_limb = F::MODULUS_BIT_SIZE - 1;
            let num_limbs = Self::MODULUS_BIT_SIZE.div_ceil(bits_per_limb);

            let mut limbs = self
                .into_bigint()
                .to_bits_le()
                .chunks(bits_per_limb as usize)
                .map(|chunk| F::from(F::BigInt::from_bits_le(chunk)))
                .collect::<Vec<F>>();
            limbs.resize(num_limbs as usize, F::zero());

            dest.extend(&limbs)
        }
    }
}

impl<F: PrimeField> AbsorbableVar<F> for FpVar<F> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        dest.push(self.clone());
        Ok(())
    }
}

impl<P: FpConfig<N>, const N: usize> Inputize<Self> for Fp<P, N> {
    fn inputize(&self) -> Vec<Self> {
        vec![*self]
    }
}

impl<F: SonobeField, P: SonobeField> InputizeEmulated<F> for P {
    fn inputize_emulated(&self) -> Vec<F> {
        self.into_bigint()
            .to_bits_le()
            .chunks(F::BITS_PER_LIMB)
            .map(|chunk| F::from(F::BigInt::from_bits_le(chunk)))
            .collect()
    }
}

impl<F: PrimeField> WitnessToPublic for FpVar<F> {
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        // This line "converts" `x` from a witness to a public input.
        // Instead of directly modifying the constraint system, we allocate a
        // public input variable explicitly and enforce that its value is indeed
        // `x`.
        // While seemingly redundant, comparing `x` with itself is necessary
        // because:
        // - `.value()` allows an honest prover to extract public inputs without
        //   computing them outside the circuit.
        // - `.enforce_equal()` prevents a malicious prover from claiming public
        //   inputs that are not the honest `x` computed in-circuit.
        self.enforce_equal(&FpVar::new_input(self.cs(), || self.value())?)
    }
}

/// [`TwoStageFieldVar`] abstracts over field variables that support a
/// two-stage arithmetic model.
///
/// In this model, we consider two stages of in-circuit variables for field
/// elements when performing arithmetic operations:
/// 1. Before the operations, we have the standard field variable type, i.e.,
///    the implementor of this trait.
/// 2. During the operations, we use [`TwoStageFieldVar::Intermediate`] to hold
///    the intermediate results.
///    Therefore, the [`Add`] and [`Mul`] operations between two field variables
///    yield an intermediate variable.
pub trait TwoStageFieldVar:
    Clone
    + Add<Output = Self::Intermediate>
    + for<'a> Add<&'a Self, Output = Self::Intermediate>
    + Mul<Output = Self::Intermediate>
    + for<'a> Mul<&'a Self, Output = Self::Intermediate>
{
    /// The intermediate variable type used during arithmetic operations.
    ///
    /// We require this type to support conversions from and to the original
    /// field variable type.
    ///
    /// In addition, to allow chaining operations without excessive conversions,
    /// we require this type to support [`Add`] and [`Mul`] operations with both
    /// itself and the original field variable type.
    type Intermediate: Clone
        + From<Self>
        + TryInto<Self>
        + Add<Output = Self::Intermediate>
        + for<'a> Add<&'a Self::Intermediate, Output = Self::Intermediate>
        + Mul<Output = Self::Intermediate>
        + for<'a> Mul<&'a Self::Intermediate, Output = Self::Intermediate>
        + Add<Self, Output = Self::Intermediate>
        + for<'a> Add<&'a Self, Output = Self::Intermediate>
        + Mul<Self, Output = Self::Intermediate>
        + for<'a> Mul<&'a Self, Output = Self::Intermediate>;
}

// Operations over the canonical variable `FpVar` always yield another `FpVar`.
impl<F: PrimeField> TwoStageFieldVar for FpVar<F> {
    type Intermediate = Self;
}
