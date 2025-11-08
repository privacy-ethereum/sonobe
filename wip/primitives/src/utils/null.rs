use ark_ff::Field;
use ark_r1cs_std::{GR1CSVar, alloc::{AllocVar, AllocationMode}};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    iter::Sum,
    ops::{Add, Mul},
};

use crate::circuits::var::Var;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
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

impl<F: Field> Var<F> for Null {
    type Native = Null;
}

impl<F: Field> AllocVar<Null, F> for Null {
    fn new_variable<T: Borrow<Null>>(
        _cs: impl Into<Namespace<F>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self)
    }
}

impl<F: Field> GR1CSVar<F> for Null {
    type Value = Null;

    fn cs(&self) -> ConstraintSystemRef<F> {
        ConstraintSystemRef::None
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(Null)
    }
}