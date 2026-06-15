//! This module defines extension traits for field elements and their in-circuit
//! counterparts, along with some common implementations.

use ark_ff::{
    BigInteger, Field, Fp, Fp2, Fp2Config, Fp3, Fp3Config, Fp4, Fp4Config, Fp6, Fp6Config, Fp12,
    Fp12Config, FpConfig, PrimeField, SmallFp, SmallFpConfig,
};
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

use crate::{
    algebra::{Val, field::emulated::EmulatedFieldVar},
    circuits::WitnessToPublic,
    traits::Inputize,
    transcripts::{Absorbable, AbsorbableVar, squeezable::Squeezable},
};

pub mod emulated;

/// [`SonobeField`] trait is a wrapper around [`PrimeField`] that also includes
/// necessary bounds for the field to be used conveniently in folding schemes.
pub trait SonobePrimeField:
    PrimeField
    + Absorbable
    + Squeezable<Self>
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

pub trait SonobeField:
    Field<BasePrimeField: SonobePrimeField> + Absorbable + Squeezable<Self::BasePrimeField>
{
}

impl<P: FpConfig<N>, const N: usize> SonobePrimeField for Fp<P, N> {
    const BITS_PER_LIMB: usize = 32;
}

impl<P: SmallFpConfig> SonobePrimeField for SmallFp<P> {
    const BITS_PER_LIMB: usize = 32;
}

impl<T: Field<BasePrimeField: SonobePrimeField> + Absorbable + Squeezable<Self::BasePrimeField>>
    SonobeField for T
{
}

impl<P: FpConfig<N>, const N: usize> Val for Fp<P, N> {
    type PreferredConstraintField = Self;
    type Var = FpVar<Self>;

    type EmulatedVar<F: SonobePrimeField> = EmulatedFieldVar<F, Self>;
}

impl<P: SmallFpConfig> Val for SmallFp<P> {
    type PreferredConstraintField = Self;
    type Var = FpVar<Self>;

    type EmulatedVar<F: SonobePrimeField> = EmulatedFieldVar<F, Self>;
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

impl<P: SmallFpConfig> Absorbable for SmallFp<P> {
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

impl<P: Fp2Config<Fp: Absorbable>> Absorbable for Fp2<P> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        for i in self.to_base_prime_field_elements() {
            i.absorb_into(dest);
        }
    }
}

impl<P: Fp3Config<Fp: Absorbable>> Absorbable for Fp3<P> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        for i in self.to_base_prime_field_elements() {
            i.absorb_into(dest);
        }
    }
}

impl<P: Fp4Config<Fp2Config: Fp2Config<Fp: Absorbable>>> Absorbable for Fp4<P> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        for i in self.to_base_prime_field_elements() {
            i.absorb_into(dest);
        }
    }
}

impl<P: Fp6Config<Fp2Config: Fp2Config<Fp: Absorbable>>> Absorbable for Fp6<P> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        for i in self.to_base_prime_field_elements() {
            i.absorb_into(dest);
        }
    }
}

impl<P: Fp12Config<Fp6Config: Fp6Config<Fp2Config: Fp2Config<Fp: Absorbable>>>> Absorbable
    for Fp12<P>
{
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        for i in self.to_base_prime_field_elements() {
            i.absorb_into(dest);
        }
    }
}

impl<P: SmallFpConfig> Squeezable<Self> for SmallFp<P> {
    fn size() -> usize {
        Self::extension_degree() as usize
    }

    fn squeeze_from(v: Vec<Self>) -> Self {
        Self::from_base_prime_field_elems(v).unwrap()
    }
}

impl<P: FpConfig<N>, const N: usize> Squeezable<Self> for Fp<P, N> {
    fn size() -> usize {
        Self::extension_degree() as usize
    }

    fn squeeze_from(v: Vec<Self>) -> Self {
        Self::from_base_prime_field_elems(v).unwrap()
    }
}

impl<P: Fp2Config> Squeezable<<Self as Field>::BasePrimeField> for Fp2<P> {
    fn size() -> usize {
        Self::extension_degree() as usize
    }

    fn squeeze_from(v: Vec<<Self as Field>::BasePrimeField>) -> Self {
        Self::from_base_prime_field_elems(v).unwrap()
    }
}

impl<P: Fp3Config> Squeezable<<Self as Field>::BasePrimeField> for Fp3<P> {
    fn size() -> usize {
        Self::extension_degree() as usize
    }

    fn squeeze_from(v: Vec<<Self as Field>::BasePrimeField>) -> Self {
        Self::from_base_prime_field_elems(v).unwrap()
    }
}

impl<P: Fp4Config> Squeezable<<Self as Field>::BasePrimeField> for Fp4<P> {
    fn size() -> usize {
        Self::extension_degree() as usize
    }

    fn squeeze_from(v: Vec<<Self as Field>::BasePrimeField>) -> Self {
        Self::from_base_prime_field_elems(v).unwrap()
    }
}

impl<P: Fp6Config> Squeezable<<Self as Field>::BasePrimeField> for Fp6<P> {
    fn size() -> usize {
        Self::extension_degree() as usize
    }

    fn squeeze_from(v: Vec<<Self as Field>::BasePrimeField>) -> Self {
        Self::from_base_prime_field_elems(v).unwrap()
    }
}

impl<P: Fp12Config> Squeezable<<Self as Field>::BasePrimeField> for Fp12<P> {
    fn size() -> usize {
        Self::extension_degree() as usize
    }

    fn squeeze_from(v: Vec<<Self as Field>::BasePrimeField>) -> Self {
        Self::from_base_prime_field_elems(v).unwrap()
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

impl<Base: SonobePrimeField, Target: SonobePrimeField> Inputize<Base>
    for EmulatedFieldVar<Base, Target>
{
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

impl<Base: SonobePrimeField, Target: SonobePrimeField> WitnessToPublic
    for EmulatedFieldVar<Base, Target>
{
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        self.enforce_equal(&Self::new_input(self.cs(), || {
            Ok(self.value().unwrap_or_default())
        })?)
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
