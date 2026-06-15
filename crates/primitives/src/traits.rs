//! This module defines helper traits used across Sonobe's crates.

use ark_ff::Field;
use ark_r1cs_std::GR1CSVar;

pub use crate::algebra::{
    field::{SonobePrimeField, SonobeField},
    group::{CF1, CF2, SonobeCurve},
};

/// [`Dummy`] provides a way to construct a placeholder ("dummy") value of a
/// given type, parameterized by some configuration `Cfg`.
///
/// This is useful when initializing data structures that require a value of a
/// certain shape before the real data is available, e.g., when setting up the
/// initial state of a folding scheme.
pub trait Dummy<Cfg> {
    /// [`Dummy::dummy`] constructs a dummy value of `Self` based on the given
    /// configuration `cfg`.
    fn dummy(cfg: Cfg) -> Self;
}

impl<T> Dummy<T> for () {
    fn dummy(_: T) -> Self {
        ()
    }
}

impl<T: Default + Clone> Dummy<usize> for Vec<T> {
    fn dummy(cfg: usize) -> Self {
        vec![Default::default(); cfg]
    }
}

impl<Cfg, T: Dummy<Cfg> + Copy, const N: usize> Dummy<Cfg> for [T; N] {
    fn dummy(cfg: Cfg) -> Self {
        [T::dummy(cfg); N]
    }
}

impl<Cfg: Copy, A: Dummy<Cfg>, B: Dummy<Cfg>> Dummy<Cfg> for (A, B) {
    fn dummy(cfg: Cfg) -> Self {
        (A::dummy(cfg), B::dummy(cfg))
    }
}

/// [`Inputize`] converts a value into a vector of field elements, ordered in
/// the same way as how the value's corresponding in-circuit variable would be
/// represented in the circuit when allocated as public input.
///
/// This is useful for the verifier to compute the public inputs.
pub trait Inputize<F: Field>: GR1CSVar<F> {
    /// [`Inputize::inputize`] outputs the underlying field elements of `self`
    /// as if it is allocated in the canonical way in-circuit.
    fn inputize(value: &Self::Value) -> Vec<F>;
}

impl<F: Field, T: Inputize<F>> Inputize<F> for [T] {
    fn inputize(value: &Self::Value) -> Vec<F> {
        value.iter().flat_map(T::inputize).collect()
    }
}

impl<F: Field, T: Inputize<F>, const N: usize> Inputize<F> for [T; N] {
    fn inputize(value: &Self::Value) -> Vec<F> {
        value.iter().flat_map(T::inputize).collect()
    }
}
