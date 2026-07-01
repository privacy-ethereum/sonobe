//! In-circuit variables for Nova instances.

use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{commitments::CommitmentDefGadget, transcripts::AbsorbableVar};

use super::{IncomingInstance, RunningInstance};
use crate::FoldingInstanceVar;

/// [`RunningInstanceVar`] defines Nova's running instance variable.
#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<CM: CommitmentDefGadget> {
    /// [`RunningInstanceVar::cm_e`] is the error term commitment.
    pub cm_e: CM::CommitmentVar,
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
        let RunningInstance { cm_e, u, cm_w, x } = v.borrow();
        Ok(Self {
            cm_e: AllocVar::new_variable(cs.clone(), || Ok(cm_e), mode)?,
            u: AllocVar::new_variable(cs.clone(), || Ok(u), mode)?,
            cm_w: AllocVar::new_variable(cs.clone(), || Ok(cm_w), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for RunningInstanceVar<CM> {
    type Value = RunningInstance<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.cm_e
            .cs()
            .or(self.u.cs())
            .or(self.cm_w.cs())
            .or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningInstance {
            cm_e: self.cm_e.value()?,
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
        self.cm_e.absorb_into(dest)?;
        self.cm_w.absorb_into(dest)
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
            cm_e: cond.select(&true_value.cm_e, &false_value.cm_e)?,
            u: cond.select(&true_value.u, &false_value.u)?,
            cm_w: cond.select(&true_value.cm_w, &false_value.cm_w)?,
            x: true_value
                .x
                .iter()
                .zip(&false_value.x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for RunningInstanceVar<CM> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![&self.cm_e, &self.cm_w]
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
            cm_e: AllocVar::new_witness(cs.clone(), || Ok(&u.cm_e))?,
            u: AllocVar::new_witness(cs.clone(), || Ok(&u.u))?,
            cm_w: AllocVar::new_witness(cs.clone(), || Ok(&u.cm_w))?,
            x,
        })
    }
}

/// [`IncomingInstanceVar`] defines Nova's incoming instance variable.
#[derive(Clone, Debug, PartialEq)]
pub struct IncomingInstanceVar<CM: CommitmentDefGadget> {
    /// [`IncomingInstanceVar::cm_w`] is the witness commitment.
    pub cm_w: CM::CommitmentVar,
    /// [`IncomingInstanceVar::x`] is the vector of public inputs (to the
    /// circuit).
    pub x: Vec<CM::ScalarVar>,
}

impl<CM: CommitmentDefGadget> AllocVar<IncomingInstance<CM::Widget>, CM::ConstraintField>
    for IncomingInstanceVar<CM>
{
    fn new_variable<T: Borrow<IncomingInstance<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let IncomingInstance { cm_w, x } = v.borrow();
        Ok(Self {
            cm_w: AllocVar::new_variable(cs.clone(), || Ok(cm_w), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for IncomingInstanceVar<CM> {
    type Value = IncomingInstance<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.cm_w.cs().or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(IncomingInstance {
            cm_w: self.cm_w.value()?,
            x: self.x.value()?,
        })
    }
}

impl<CM: CommitmentDefGadget> AbsorbableVar<CM::ConstraintField> for IncomingInstanceVar<CM> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<CM::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.x.absorb_into(dest)?;
        self.cm_w.absorb_into(dest)
    }
}

impl<CM: CommitmentDefGadget> CondSelectGadget<CM::ConstraintField> for IncomingInstanceVar<CM> {
    fn conditionally_select(
        cond: &Boolean<CM::ConstraintField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.x.len() != false_value.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            cm_w: cond.select(&true_value.cm_w, &false_value.cm_w)?,
            x: true_value
                .x
                .iter()
                .zip(&false_value.x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for IncomingInstanceVar<CM> {
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
            cm_w: AllocVar::new_witness(cs.clone(), || Ok(&u.cm_w))?,
            x,
        })
    }
}
