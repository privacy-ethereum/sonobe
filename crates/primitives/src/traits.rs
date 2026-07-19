//! This module defines helper traits used across Sonobe's crates.

pub use crate::algebra::{field::SonobeField, group::SonobeCurve};

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
/// represented in the canonical way in the circuit when allocated as public
/// input.
///
/// This is useful for the verifier to compute the public inputs.
pub trait Inputize<F> {
    /// [`Inputize::inputize`] outputs the underlying field elements of `self`
    /// as if it is allocated in the canonical way in-circuit.
    fn inputize(&self) -> Vec<F>;
}

impl<F, T: Inputize<F>> Inputize<F> for [T] {
    fn inputize(&self) -> Vec<F> {
        self.iter().flat_map(Inputize::<F>::inputize).collect()
    }
}

/// [`InputizeEmulated`] converts a value into a vector of field elements,
/// ordered in the same way as how the value's corresponding in-circuit variable
/// would be represented in the emulated way in the circuit when allocated as
/// public input.
///
/// This is useful for the verifier to compute the public inputs.
///
/// Note that we require this trait because we need to distinguish between some
/// data types that can be represented in both the canonical and emulated ways
/// in-circuit (e.g., field elements or elliptic curve points).
pub trait InputizeEmulated<F> {
    /// [`InputizeEmulated::inputize_emulated`] outputs the underlying field
    /// elements of `self` as if it is allocated in the emulated way in-circuit.
    fn inputize_emulated(&self) -> Vec<F>;
}

impl<F, T: InputizeEmulated<F>> InputizeEmulated<F> for [T] {
    fn inputize_emulated(&self) -> Vec<F> {
        self.iter()
            .flat_map(InputizeEmulated::<F>::inputize_emulated)
            .collect()
    }
}
