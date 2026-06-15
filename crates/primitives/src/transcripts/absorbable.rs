//! This module defines traits for converting values into a form absorbable by a
//! sponge or transcript.
//!
//! Implementations are provided for some primitive types as well as composite
//! types (references, tuples, slices, etc.).

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

// TODO (@winderica):
//
// Ideally this trait should be defined as follows, so that we can use it for
// absorbing values into bits/bytes/etc., in addition to field elements.
// (Although Arkworks' `Absorb` trait covers both bytes and field elements, it
// requires downstream types to support absorbing into both as well, even if the
// downstream type doesn't support/is unrelated to one absorbing target.)
//
// ```rs
// pub trait Absorbable<F> {
//     fn absorb_into(&self, dest: &mut Vec<F>);

//     fn to_absorbable(&self) -> Vec<F> {
//         let mut result = Vec::new();
//         self.absorb_into(&mut result);
//         result
//     }
// }
// ```
//
// But my attempt was unsuccessful. In our use case, `SonobeField` needs to be
// absorbed into prime fields that are unknown when making the definition. Due
// to the `F` type parameter in `Absorbable<F>`, I have three options:
// 1. Define `SonobeField` as `SonobeField<F>: Absorbable<F>`. This means that
//    I need to add `F` to everywhere `SonobeField` is used, making the codebase
//    much more verbose.
// 2. Remove the `Absorbable` bound from `SonobeField`, but instead manually add
//    `Absorbable<F>` to `T: SonobeField`'s bounds whenever we need `T` to be
//    absorbable. This also increases the verbosity a lot.
// 3. Wait for https://github.com/rust-lang/rust/issues/108185 to be resolved,
//    so I can define `SonobeField: for <F: PrimeField> Absorbable<F>`.
// Personally I think the best option is 3. File an issue or submit a PR if you
// have better solution :)
/// [`Absorbable`] is a trait for objects that can be absorbed into a sponge or
/// transcript.
pub trait Absorbable {
    /// [`Absorbable::absorb_into`] absorbs `self` into the given destination
    /// vector of field elements.
    ///
    /// The implementation should append the field elements representing `self`
    /// to `dest`.
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>);
}

impl Absorbable for usize {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self as u64));
    }
}

impl Absorbable for i8 {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self));
    }
}

impl<T: Absorbable> Absorbable for &T {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self).absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for (T, T) {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest);
        self.1.absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for [T] {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        for t in self.iter() {
            t.absorb_into(dest);
        }
    }
}

impl<T: Absorbable, const N: usize> Absorbable for [T; N] {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.as_ref().absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for Vec<T> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.as_slice().absorb_into(dest);
    }
}

/// [`AbsorbableVar`] is a trait for in-circuit variables that can be absorbed
/// into a sponge or transcript defined over constraint field `F`.
///
/// Matches [`Absorbable`].
pub trait AbsorbableVar<F: PrimeField> {
    /// [`AbsorbableVar::absorb_into`] absorbs `self` into the given
    /// destination vector of field element variables.
    ///
    /// The implementation should append the field element variables
    /// representing `self` to `dest`.
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError>;
}

impl<F: PrimeField, T: AbsorbableVar<F>> AbsorbableVar<F> for &T {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        (*self).absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableVar<F>> AbsorbableVar<F> for (T, T) {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)?;
        self.1.absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableVar<F>> AbsorbableVar<F> for [T] {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.iter().try_for_each(|t| t.absorb_into(dest))
    }
}

impl<F: PrimeField, T: AbsorbableVar<F>, const N: usize> AbsorbableVar<F> for [T; N] {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.as_ref().absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableVar<F>> AbsorbableVar<F> for Vec<T> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.as_slice().absorb_into(dest)
    }
}
