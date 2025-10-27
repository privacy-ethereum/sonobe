use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;

pub trait Var<F: Field>: AllocVar<Self::Native, F> {
    type Native;
}
