//! In-circuit variables for Mova instances.

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

/// [`RunningInstanceVar`] defines Mova's running instance variable.
#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<CM: CommitmentDefGadget> {
    /// [`RunningInstanceVar::r_e`] is the random evaluation point for the error
    /// term.
    pub r_e: Vec<CM::ScalarVar>,
    /// [`RunningInstanceVar::v`] is the evaluation of the MLE of the error term
    /// at `r_e`.
    pub v: CM::ScalarVar,
    /// [`RunningInstanceVar::u`] is the constant term.
    pub u: CM::ScalarVar,
    /// [`RunningInstanceVar::cm_w`] is the witness commitment.
    pub cm_w: CM::CommitmentVar,
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
        let RunningInstance { r_e, v, u, cm_w, x } = v.borrow();
        Ok(Self {
            r_e: AllocVar::new_variable(cs.clone(), || Ok(&r_e[..]), mode)?,
            v: AllocVar::new_variable(cs.clone(), || Ok(v), mode)?,
            u: AllocVar::new_variable(cs.clone(), || Ok(u), mode)?,
            cm_w: AllocVar::new_variable(cs.clone(), || Ok(cm_w), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for RunningInstanceVar<CM> {
    type Value = RunningInstance<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.r_e
            .cs()
            .or(self.v.cs())
            .or(self.u.cs())
            .or(self.cm_w.cs())
            .or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningInstance {
            r_e: self.r_e.value()?,
            v: self.v.value()?,
            u: self.u.value()?,
            cm_w: self.cm_w.value()?,
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
        self.v.absorb_into(dest)?;
        self.r_e.absorb_into(dest)?;
        self.cm_w.absorb_into(dest)
    }
}

impl<CM: CommitmentDefGadget> CondSelectGadget<CM::ConstraintField> for RunningInstanceVar<CM> {
    fn conditionally_select(
        cond: &Boolean<CM::ConstraintField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.r_e.len() != false_value.r_e.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if true_value.x.len() != false_value.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            r_e: true_value
                .r_e
                .iter()
                .zip(&false_value.r_e)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
            v: cond.select(&true_value.v, &false_value.v)?,
            u: cond.select(&true_value.u, &false_value.u)?,
            x: true_value
                .x
                .iter()
                .zip(&false_value.x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
            cm_w: cond.select(&true_value.cm_w, &false_value.cm_w)?,
        })
    }
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for RunningInstanceVar<CM> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![&self.cm_w]
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
            r_e: AllocVar::new_witness(cs.clone(), || Ok(&u.r_e[..]))?,
            v: AllocVar::new_witness(cs.clone(), || Ok(u.v))?,
            u: AllocVar::new_witness(cs.clone(), || Ok(u.u))?,
            cm_w: AllocVar::new_witness(cs.clone(), || Ok(&u.cm_w))?,
            x,
        })
    }
}
