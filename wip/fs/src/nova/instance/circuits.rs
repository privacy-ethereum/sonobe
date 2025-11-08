use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    circuits::var::Var, commitments::VectorCommitmentGadget, transcripts::AbsorbableGadget,
};

use super::{IncomingInstance, RunningInstance};
use crate::FoldingInstanceVar;

#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<VC: VectorCommitmentGadget> {
    pub cm_e: VC::CommitmentVar,
    pub u: VC::ScalarVar,
    pub cm_w: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadget> Var<VC::ConstraintField> for RunningInstanceVar<VC> {
    type Native = RunningInstance<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<RunningInstance<VC::Native>, VC::ConstraintField>
    for RunningInstanceVar<VC>
{
    fn new_variable<T: Borrow<RunningInstance<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
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

impl<VC: VectorCommitmentGadget> GR1CSVar<VC::ConstraintField> for RunningInstanceVar<VC> {
    type Value = RunningInstance<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
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

impl<VC: VectorCommitmentGadget> AbsorbableGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.cm_e.absorb_into(dest)?;
        self.cm_w.absorb_into(dest)
    }
}

impl<VC: VectorCommitmentGadget> CondSelectGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
    fn conditionally_select(
        cond: &Boolean<VC::ConstraintField>,
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

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for RunningInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![&self.cm_w, &self.cm_e]
    }

    fn public_inputs(&self) -> &Vec<VC::ScalarVar> {
        &self.x
    }

    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        u: &Self::Native,
        x: Vec<VC::ScalarVar>,
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

#[derive(Clone, Debug, PartialEq)]
pub struct IncomingInstanceVar<VC: VectorCommitmentGadget> {
    pub cm_w: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadget> Var<VC::ConstraintField> for IncomingInstanceVar<VC> {
    type Native = IncomingInstance<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<IncomingInstance<VC::Native>, VC::ConstraintField>
    for IncomingInstanceVar<VC>
{
    fn new_variable<T: Borrow<IncomingInstance<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
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

impl<VC: VectorCommitmentGadget> GR1CSVar<VC::ConstraintField> for IncomingInstanceVar<VC> {
    type Value = IncomingInstance<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.cm_w.cs().or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(IncomingInstance {
            cm_w: self.cm_w.value()?,
            x: self.x.value()?,
        })
    }
}

impl<VC: VectorCommitmentGadget> AbsorbableGadget<VC::ConstraintField> for IncomingInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.x.absorb_into(dest)?;
        self.cm_w.absorb_into(dest)
    }
}

impl<VC: VectorCommitmentGadget> CondSelectGadget<VC::ConstraintField> for IncomingInstanceVar<VC> {
    fn conditionally_select(
        cond: &Boolean<VC::ConstraintField>,
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

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for IncomingInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![&self.cm_w]
    }

    fn public_inputs(&self) -> &Vec<VC::ScalarVar> {
        &self.x
    }

    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        u: &Self::Native,
        x: Vec<VC::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        Ok(Self {
            cm_w: AllocVar::new_witness(cs.clone(), || Ok(&u.cm_w))?,
            x,
        })
    }
}
