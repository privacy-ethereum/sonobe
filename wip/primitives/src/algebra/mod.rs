use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, GR1CSVar};

use crate::traits::SonobeField;

pub mod field;
pub mod group;
pub mod ops;

pub trait Val {
    type ConstraintField: PrimeField;
    type Var: AllocVar<Self, Self::ConstraintField> + GR1CSVar<Self::ConstraintField, Value = Self>;

    type EmulatedVar<F: SonobeField>: AllocVar<Self, F> + GR1CSVar<F, Value = Self>;
}

pub type Var<T> = <T as Val>::Var;
pub type EmulatedVar<F, T> = <T as Val>::EmulatedVar<F>;