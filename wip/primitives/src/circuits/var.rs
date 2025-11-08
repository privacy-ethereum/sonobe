use ark_ff::Field;
use ark_r1cs_std::{alloc::AllocVar, GR1CSVar};
use ark_std::fmt::Debug;

pub trait Var<F: Field>: AllocVar<Self::Native, F> + GR1CSVar<F, Value = Self::Native> {
    type Native: Clone + Eq + Debug;
}
