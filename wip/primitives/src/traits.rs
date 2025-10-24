pub use crate::algebra::{
    field::SonobeField,
    group::{SonobeCurve, CF1, CF2},
};

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

impl<F, T: Inputize<F>> Inputize<F> for [T] {
    fn inputize(&self) -> Vec<F> {
        self.iter().flat_map(Inputize::<F>::inputize).collect()
    }
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

impl<F, T: InputizeNonNative<F>> InputizeNonNative<F> for [T] {
    fn inputize_nonnative(&self) -> Vec<F> {
        self.iter()
            .flat_map(InputizeNonNative::<F>::inputize_nonnative)
            .collect()
    }
}
