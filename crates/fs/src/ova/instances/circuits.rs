//! In-circuit variables for Ova instances.

use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{commitments::CommitmentDefGadget, transcripts::AbsorbableVar};

use super::RunningInstance;
use crate::FoldingInstanceVar;

/// [`RunningInstanceVar`] defines Ova's running instance variable.
#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<CM: CommitmentDefGadget> {
    /// [`RunningInstanceVar::u`] is the constant term.
    pub u: CM::ScalarVar,
    /// [`RunningInstanceVar::cm`] is the combined witness and error term
    /// commitment.
    pub cm: CM::CommitmentVar,
    /// [`RunningInstanceVar::x`] is the vector of public inputs (to the
    /// circuit).
    pub x: Vec<CM::ScalarVar>,
}

impl<CM: CommitmentDefGadget> AllocVar<RunningInstance<CM::Widget>, CM::ConstraintField>
    for RunningInstanceVar<CM>
{
    fn new_variable<T: Borrow<RunningInstance<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let RunningInstance { u, cm, x } = v.borrow();
        Ok(Self {
            u: AllocVar::new_variable(cs.clone(), || Ok(u), mode)?,
            cm: AllocVar::new_variable(cs.clone(), || Ok(cm), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for RunningInstanceVar<CM> {
    type Value = RunningInstance<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.u.cs().or(self.cm.cs()).or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningInstance {
            u: self.u.value()?,
            cm: self.cm.value()?,
            x: self.x.value()?,
        })
    }
}

impl<CM: CommitmentDefGadget> AbsorbableVar<CM::ConstraintField> for RunningInstanceVar<CM> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<CM::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.cm.absorb_into(dest)
    }
}

impl<CM: CommitmentDefGadget> CondSelectGadget<CM::ConstraintField> for RunningInstanceVar<CM> {
    fn conditionally_select(
        cond: &Boolean<CM::ConstraintField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.x.len() != false_value.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            u: cond.select(&true_value.u, &false_value.u)?,
            x: true_value
                .x
                .iter()
                .zip(&false_value.x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
            cm: cond.select(&true_value.cm, &false_value.cm)?,
        })
    }
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for RunningInstanceVar<CM> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &Vec<CM::ScalarVar> {
        &self.x
    }

    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        u: &Self::Value,
        x: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        Ok(Self {
            u: AllocVar::new_witness(cs.clone(), || Ok(&u.u))?,
            cm: AllocVar::new_witness(cs.clone(), || Ok(&u.cm))?,
            x,
        })
    }
}
