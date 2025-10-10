use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::{BigInteger, Field as ArkField, Fp, FpConfig, One, PrimeField, Zero};
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldVar},
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{
    any::TypeId,
    iter::Sum,
    mem::transmute_copy,
    ops::{Add, Mul},
};

pub type CF1<C> = <C as PrimeGroup>::ScalarField;
pub type CF2<C> = <<C as CurveGroup>::BaseField as ArkField>::BasePrimeField;

pub trait Dummy<Cfg> {
    fn dummy(cfg: Cfg) -> Self;
}

impl<T: Default + Clone> Dummy<usize> for Vec<T> {
    fn dummy(cfg: usize) -> Self {
        vec![Default::default(); cfg]
    }
}

impl<T: Default> Dummy<()> for T {
    fn dummy(_: ()) -> Self {
        Default::default()
    }
}

/// Converts a value `self` into a vector of field elements, ordered in the same
/// way as how a variable of type `Var` would be represented *natively* in the
/// circuit.
///
/// This is useful for the verifier to compute the public inputs.
pub trait Inputize<F> {
    fn inputize(&self) -> Vec<F>;
}

/// Converts a value `self` into a vector of field elements, ordered in the same
/// way as how a variable of type `Var` would be represented *non-natively* in
/// the circuit.
///
/// This is useful for the verifier to compute the public inputs.
///
/// Note that we require this trait because we need to distinguish between some
/// data types that are represented both natively and non-natively in-circuit
/// (e.g., field elements can have type `FpVar` and `NonNativeUintVar`).
pub trait InputizeNonNative<F> {
    fn inputize_nonnative(&self) -> Vec<F>;
}

impl<F, T: Inputize<F>> Inputize<F> for [T] {
    fn inputize(&self) -> Vec<F> {
        self.iter().flat_map(Inputize::<F>::inputize).collect()
    }
}

impl<F, T: InputizeNonNative<F>> InputizeNonNative<F> for [T] {
    fn inputize_nonnative(&self) -> Vec<F> {
        self.iter()
            .flat_map(InputizeNonNative::<F>::inputize_nonnative)
            .collect()
    }
}

impl<P: FpConfig<N>, const N: usize> Inputize<Self> for Fp<P, N> {
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `FpVar::new_input`.
    fn inputize(&self) -> Vec<Self> {
        vec![*self]
    }
}

impl<P: SWCurveConfig<BaseField: SonobeField>> Inputize<P::BaseField> for Projective<P> {
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `ProjectiveVar::new_input`.
    fn inputize(&self) -> Vec<P::BaseField> {
        let affine = self.into_affine();
        match affine.xy() {
            Some((x, y)) => vec![x, y, One::one()],
            None => vec![Zero::zero(), One::one(), Zero::zero()],
        }
    }
}

impl<F: SonobeField, P: SonobeField> InputizeNonNative<F> for P {
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `NonNativeUintVar::new_input`.
    fn inputize_nonnative(&self) -> Vec<F> {
        self.into_bigint()
            .to_bits_le()
            .chunks(F::BITS_PER_LIMB)
            .map(|chunk| F::from(F::BigInt::from_bits_le(chunk)))
            .collect()
    }
}

impl<P: SWCurveConfig<BaseField: SonobeField, ScalarField: SonobeField>>
    InputizeNonNative<P::ScalarField> for Projective<P>
{
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `NonNativeAffineVar::new_input`.
    fn inputize_nonnative(&self) -> Vec<P::ScalarField> {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();

        [x, y].inputize_nonnative()
    }
}

/// `Field` trait is a wrapper around `PrimeField` that also includes the
/// necessary bounds for the field to be used conveniently in folding schemes.
pub trait SonobeField:
    PrimeField<BasePrimeField = Self> + Absorbable<Self> + Inputize<Self>
{
    const BITS_PER_LIMB: usize;
    /// The in-circuit variable type for this field.
    type Var: FieldVar<Self, Self>;
}

impl<P: FpConfig<N>, const N: usize> SonobeField for Fp<P, N> {
    const BITS_PER_LIMB: usize = 55; // TODO: make this configurable
    type Var = FpVar<Self>;
}

/// `Curve` trait is a wrapper around `CurveGroup` that also includes the
/// necessary bounds for the curve to be used conveniently in folding schemes.
pub trait SonobeCurve:
    CurveGroup<ScalarField: SonobeField, BaseField: SonobeField>
    + Absorbable<Self::BaseField>
    + Inputize<Self::BaseField>
    + InputizeNonNative<Self::ScalarField>
{
    /// The in-circuit variable type for this curve.
    type Var: CurveVar<Self, Self::BaseField>;
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> SonobeCurve
    for Projective<P>
{
    type Var = ProjectiveVar<P, FpVar<P::BaseField>>;
}

pub trait Absorbable<F: PrimeField> {
    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    /// Append the list to `dest`
    fn absorb_into(&self, dest: &mut Vec<F>);

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    /// Return the list as `Vec`
    fn extract_absorbed(&self) -> Vec<F> {
        let mut result = Vec::new();
        self.absorb_into(&mut result);
        result
    }
}

impl<F: PrimeField, P: FpConfig<N>, const N: usize> Absorbable<F> for Fp<P, N> {
    fn absorb_into(&self, dest: &mut Vec<F>) {
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

impl<F: PrimeField, P: SWCurveConfig<BaseField: Absorbable<F>>> Absorbable<F> for Projective<P> {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();
        [x, y].absorb_into(dest);
    }
}

impl<F: PrimeField> Absorbable<F> for usize {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self as u64));
    }
}

impl<F: PrimeField, T: Absorbable<F>> Absorbable<F> for &T {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        <T as Absorbable<F>>::absorb_into(self, dest);
    }
}

impl<F: PrimeField, T: Absorbable<F>> Absorbable<F> for (T, T) {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest);
        self.1.absorb_into(dest);
    }
}

impl<F: PrimeField, T: Absorbable<F> + 'static> Absorbable<F> for [T] {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        if TypeId::of::<F>() == TypeId::of::<T>() {
            // Safe because `F` and `T` have the same type
            dest.extend(unsafe { transmute_copy::<&[T], &[F]>(&self) });
        } else {
            for t in self.iter() {
                t.absorb_into(dest);
            }
        }
    }
}

impl<F: PrimeField, T: Absorbable<F> + 'static, const N: usize> Absorbable<F> for [T; N] {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        <[T] as Absorbable<F>>::absorb_into(self, dest);
    }
}

impl<F: PrimeField, T: Absorbable<F> + 'static> Absorbable<F> for Vec<T> {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        <[T] as Absorbable<F>>::absorb_into(self, dest);
    }
}

// TODO: rework this
/// An interface for objects that can be absorbed by a `TranscriptVar` whose constraint field
/// is `F`.
///
/// Matches `AbsorbGadget` in `ark-crypto-primitives`.
pub trait AbsorbNonNativeGadget<F: PrimeField> {
    /// Converts the object into field elements that can be absorbed by a `TranscriptVar`.
    fn to_native_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError>;
}

impl<F: PrimeField, T: AbsorbNonNativeGadget<F>> AbsorbNonNativeGadget<F> for &T {
    fn to_native_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        T::to_native_sponge_field_elements(self)
    }
}

impl<F: PrimeField, T: AbsorbNonNativeGadget<F>> AbsorbNonNativeGadget<F> for [T] {
    fn to_native_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut result = Vec::new();
        for t in self.iter() {
            result.extend(t.to_native_sponge_field_elements()?);
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Null;

impl<F> Add<F> for Null {
    type Output = Null;

    fn add(self, _: F) -> Null {
        Null
    }
}

impl<F> Add<F> for &Null {
    type Output = Null;

    fn add(self, _: F) -> Null {
        Null
    }
}

impl<F> Mul<F> for Null {
    type Output = Self;

    fn mul(self, _: F) -> Null {
        Null
    }
}

impl<F> Mul<F> for &Null {
    type Output = Null;

    fn mul(self, _: F) -> Null {
        Null
    }
}

impl Sum for Null {
    fn sum<I: Iterator<Item = Self>>(_: I) -> Self {
        Null
    }
}

pub trait ScalarRLC<Coeff> {
    type Value;

    fn scalar_rlc(self, coeffs: &[Coeff]) -> Self::Value;
}

impl<I: Iterator + Sized, Coeff> ScalarRLC<Coeff> for I
where
    I::Item: Add<Output = I::Item> + Sum + for<'a> Mul<&'a Coeff, Output = I::Item>,
{
    type Value = I::Item;

    fn scalar_rlc(self, coeffs: &[Coeff]) -> Self::Value {
        self.zip(coeffs).map(|(v, c)| v * c).sum::<I::Item>()
    }
}

pub trait SliceRLC<Coeff> {
    type Value;

    fn slice_rlc(self, coeffs: &[Coeff]) -> Vec<Self::Value>;
}

impl<'a, T: 'a, I: Iterator<Item = &'a [T]>, Coeff> SliceRLC<Coeff> for I
where
    T: Add<Output = T> + Copy,
    for<'x> T: Mul<&'x Coeff, Output = T>,
{
    type Value = T;

    fn slice_rlc(self, coeffs: &[Coeff]) -> Vec<Self::Value> {
        let mut iter = self.zip(coeffs).map(|(v, c)| v.iter().map(|x| *x * c));
        let first = iter.next().unwrap();

        iter.fold(first.collect(), |acc, v| {
            acc.into_iter().zip(v).map(|(a, b)| a + b).collect()
        })
    }
}
