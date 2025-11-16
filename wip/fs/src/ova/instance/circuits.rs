use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{commitments::VectorCommitmentGadget, transcripts::AbsorbableGadget};

use super::RunningInstance;
use crate::FoldingInstanceVar;

#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<VC: VectorCommitmentGadget> {
    pub u: VC::ScalarVar,
    pub cm: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
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
        let RunningInstance { u, cm, x } = v.borrow();
        Ok(Self {
            u: AllocVar::new_variable(cs.clone(), || Ok(u), mode)?,
            cm: AllocVar::new_variable(cs.clone(), || Ok(cm), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<VC: VectorCommitmentGadget> GR1CSVar<VC::ConstraintField> for RunningInstanceVar<VC> {
    type Value = RunningInstance<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
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

impl<VC: VectorCommitmentGadget> AbsorbableGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.cm.absorb_into(dest)
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

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for RunningInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &Vec<VC::ScalarVar> {
        &self.x
    }

    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        u: &Self::Value,
        x: Vec<VC::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        Ok(Self {
            u: AllocVar::new_witness(cs.clone(), || Ok(&u.u))?,
            cm: AllocVar::new_witness(cs.clone(), || Ok(&u.cm))?,
            x,
        })
    }
}
