use ark_ff::Field;
use ark_r1cs_std::GR1CSVar;

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
