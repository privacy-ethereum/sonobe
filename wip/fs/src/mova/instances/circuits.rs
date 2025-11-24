use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{commitments::VectorCommitmentGadgetDef, transcripts::AbsorbableGadget};

use super::RunningInstance;
use crate::FoldingInstanceVar;

#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<VC: VectorCommitmentGadgetDef> {
    // Random evaluation point for the E
    pub r_e: Vec<VC::ScalarVar>,
    // Evaluation of the MLE of E at r_E
    pub v: VC::ScalarVar,
    pub u: VC::ScalarVar,
    pub cm_w: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadgetDef> AllocVar<RunningInstance<VC::Native>, VC::ConstraintField>
    for RunningInstanceVar<VC>
{
    fn new_variable<T: Borrow<RunningInstance<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
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

impl<VC: VectorCommitmentGadgetDef> GR1CSVar<VC::ConstraintField> for RunningInstanceVar<VC> {
    type Value = RunningInstance<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
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

impl<VC: VectorCommitmentGadgetDef> AbsorbableGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.v.absorb_into(dest)?;
        self.r_e.absorb_into(dest)?;
        self.cm_w.absorb_into(dest)
    }
}

impl<VC: VectorCommitmentGadgetDef> CondSelectGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
    fn conditionally_select(
        cond: &Boolean<VC::ConstraintField>,
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

impl<VC: VectorCommitmentGadgetDef> FoldingInstanceVar<VC> for RunningInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![&self.cm_w]
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
            r_e: AllocVar::new_witness(cs.clone(), || Ok(&u.r_e[..]))?,
            v: AllocVar::new_witness(cs.clone(), || Ok(u.v))?,
            u: AllocVar::new_witness(cs.clone(), || Ok(u.u))?,
            cm_w: AllocVar::new_witness(cs.clone(), || Ok(&u.cm_w))?,
            x,
        })
    }
}
