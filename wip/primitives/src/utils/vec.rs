use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    ops::{Deref, DerefMut},
    rand::RngCore,
};

use crate::{
    arithmetizations::ArithConfig,
    circuits::var::Var,
    traits::Dummy,
    transcripts::{Absorbable, AbsorbableGadget},
};

#[derive(Clone, Debug, PartialEq)]
pub struct WrappedVec<V>(Vec<V>);

impl<V> Deref for WrappedVec<V> {
    type Target = Vec<V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V> DerefMut for WrappedVec<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<V> From<Vec<V>> for WrappedVec<V> {
    fn from(v: Vec<V>) -> Self {
        Self(v)
    }
}

impl<F, V: Absorbable<F>> Absorbable<F> for WrappedVec<V> {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest)
    }
}

impl<F: PrimeField, V: AbsorbableGadget<F>> AbsorbableGadget<F> for WrappedVec<V> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)
    }
}

impl<X: AllocVar<Y, F>, Y, F: Field> AllocVar<WrappedVec<Y>, F> for WrappedVec<X> {
    fn new_variable<T: Borrow<WrappedVec<Y>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let v = f()?;
        Vec::new_variable(cs, || Ok(&v.borrow()[..]), mode).map(|v| Self(v))
    }
}

impl<F: PrimeField, X: CondSelectGadget<F>> CondSelectGadget<F> for WrappedVec<X> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.len() != false_value.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(WrappedVec(
            true_value
                .0
                .iter()
                .zip(false_value.0.iter())
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl<F: Field, V: Var<F>> Var<F> for WrappedVec<V> {
    type Native = WrappedVec<V::Native>;
}

impl<V: Default + Clone, A: ArithConfig> Dummy<&A> for WrappedVec<V> {
    fn dummy(cfg: &A) -> Self {
        vec![V::default(); cfg.n_public_inputs()].into()
    }
}
