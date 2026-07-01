//! This module defines extension traits for field elements and their in-circuit
//! counterparts, along with some common implementations.

use ark_ff::{BigInteger, Field, Fp, Fp2, Fp2Config, FpConfig, PrimeField};
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
    ops::{Add, Mul, Sub},
};

#[cfg(feature = "evm")]
use crate::utils::evm::serialize::EVMSerialize;
use crate::{
    algebra::{Val, field::emulated::EmulatedFieldVar},
    circuits::{WitnessToPublic, inputize::Inputize},
    transcripts::{Absorbable, AbsorbableVar},
};

pub mod emulated;

/// [`SonobeField`] trait is a wrapper around [`PrimeField`] that also includes
/// necessary bounds for the field to be used conveniently in folding schemes.
pub trait SonobeField:
    PrimeField<BasePrimeField = Self>
    + Absorbable
    + Val<
        Var: FieldVar<Self, Self> + WitnessToPublic + Inputize<Self>,
        EmulatedVar<Self> = EmulatedFieldVar<Self, Self>,
    >
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

impl<P: FpConfig<N>, const N: usize> Val for Fp<P, N> {
    type PreferredConstraintField = Self;
    type Var = FpVar<Self>;

    type EmulatedVar<F: SonobeField> = EmulatedFieldVar<F, Self>;
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

impl<F: PrimeField> Inputize<F> for FpVar<F> {
    fn inputize(value: &Self::Value) -> Vec<F> {
        vec![*value]
    }
}

impl<Base: SonobeField, Target: SonobeField> Inputize<Base> for EmulatedFieldVar<Base, Target> {
    fn inputize(value: &Self::Value) -> Vec<Base> {
        // TODO: pack bits
        value
            .into_bigint()
            .to_bits_le()
            .chunks(Base::BITS_PER_LIMB)
            .map(Base::BigInt::from_bits_le)
            .map(Base::from)
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
        self.enforce_equal(&Self::new_input(self.cs(), || {
            Ok(self.value().unwrap_or_default())
        })?)
    }
}

impl<Base: SonobeField, Target: SonobeField> WitnessToPublic for EmulatedFieldVar<Base, Target> {
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        self.enforce_equal(&Self::new_input(self.cs(), || {
            Ok(self.value().unwrap_or_default())
        })?)
    }
}

#[cfg(feature = "evm")]
impl<P: FpConfig<N>, const N: usize> EVMSerialize for Fp<P, N> {
    fn to_calldata(&self) -> Vec<u8> {
        self.into_bigint().to_bytes_be()
    }
}

#[cfg(feature = "evm")]
impl<P: Fp2Config<Fp: EVMSerialize>> EVMSerialize for Fp2<P> {
    fn to_calldata(&self) -> Vec<u8> {
        [self.c1.to_calldata(), self.c0.to_calldata()].concat()
    }
}

/// [`TwoStageFieldVar`] abstracts over field variables that support a
/// two-stage arithmetic model.
///
/// In this model, we consider two stages of in-circuit variables for field
/// elements when performing field operations:
/// 1. Before the operations, we have the standard field variable type, i.e.,
///    the implementor of this trait.
/// 2. During the operations, we use [`TwoStageFieldVar::Intermediate`] to hold
///    the intermediate results.
///    Therefore, the field operations on two field variables yield a new
///    intermediate variable.
pub trait TwoStageFieldVar:
    Clone
    + Add<Output = Self::Intermediate>
    + for<'a> Add<&'a Self, Output = Self::Intermediate>
    + Sub<Output = Self::Intermediate>
    + for<'a> Sub<&'a Self, Output = Self::Intermediate>
    + Mul<Output = Self::Intermediate>
    + for<'a> Mul<&'a Self, Output = Self::Intermediate>
    + GR1CSVar<Self::ConstraintField, Value = Self::ValueField>
    + AllocVar<Self::Value, Self::ConstraintField>
{
    // TODO: seems that using GR1CSVar's Value breaks the compiler...
    type ValueField: Field;
    type ConstraintField: Field;

    /// The intermediate variable type used during field operations.
    ///
    /// We require this type to support conversions from and to the original
    /// field variable type.
    ///
    /// In addition, to allow chaining operations without excessive conversions,
    /// we require this type to support field operations with both itself and
    /// the original field variable type.
    type Intermediate: Clone
        + From<Self>
        + TryInto<Self>
        + Add<Output = Self::Intermediate>
        + for<'a> Add<&'a Self::Intermediate, Output = Self::Intermediate>
        + Sub<Output = Self::Intermediate>
        + for<'a> Sub<&'a Self::Intermediate, Output = Self::Intermediate>
        + Mul<Output = Self::Intermediate>
        + for<'a> Mul<&'a Self::Intermediate, Output = Self::Intermediate>
        + Add<Self, Output = Self::Intermediate>
        + for<'a> Add<&'a Self, Output = Self::Intermediate>
        + Sub<Self, Output = Self::Intermediate>
        + for<'a> Sub<&'a Self, Output = Self::Intermediate>
        + Mul<Self, Output = Self::Intermediate>
        + for<'a> Mul<&'a Self, Output = Self::Intermediate>;

    fn additive_identity() -> Self;
    fn multiplicative_identity() -> Self;
}

// Operations over the canonical variable `FpVar` always yield another `FpVar`.
impl<F: PrimeField> TwoStageFieldVar for FpVar<F> {
    type ValueField = F;
    type ConstraintField = F;
    type Intermediate = Self;

    fn additive_identity() -> Self {
        Self::zero()
    }

    fn multiplicative_identity() -> Self {
        Self::one()
    }
}
