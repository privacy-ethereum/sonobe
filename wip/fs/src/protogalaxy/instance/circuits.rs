use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    circuits::var::Var,
    commitments::{VectorCommitment, VectorCommitmentGadget},
    transcripts::{Absorbable, AbsorbableGadget},
};

use super::{IncomingInstance, RunningInstance};
use crate::{FoldingInstance, FoldingInstanceVar};

#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<VC: VectorCommitmentGadget> {
    pub phi: VC::CommitmentVar,
    pub betas: Vec<VC::ScalarVar>,
    pub e: VC::ScalarVar,
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
        let RunningInstance { phi, betas, e, x } = v.borrow();
        Ok(Self {
            phi: AllocVar::new_variable(cs.clone(), || Ok(phi), mode)?,
            betas: AllocVar::new_variable(cs.clone(), || Ok(&betas[..]), mode)?,
            e: AllocVar::new_variable(cs.clone(), || Ok(e), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<VC: VectorCommitmentGadget> AbsorbableGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.phi.absorb_into(dest)?;
        self.betas.absorb_into(dest)?;
        self.e.absorb_into(dest)?;
        self.x.absorb_into(dest)
    }
}

impl<VC: VectorCommitmentGadget> CondSelectGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
    fn conditionally_select(
        cond: &Boolean<VC::ConstraintField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.betas.len() != false_value.betas.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if true_value.x.len() != false_value.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            phi: cond.select(&true_value.phi, &false_value.phi)?,
            betas: true_value
                .betas
                .iter()
                .zip(&false_value.betas)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
            e: cond.select(&true_value.e, &false_value.e)?,
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
        vec![&self.phi]
    }

    fn public_inputs(&self) -> &Vec<VC::ScalarVar> {
        &self.x
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IncomingInstanceVar<VC: VectorCommitmentGadget> {
    pub phi: VC::CommitmentVar,
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
        let IncomingInstance { phi, x } = v.borrow();
        Ok(Self {
            phi: AllocVar::new_variable(cs.clone(), || Ok(phi), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<VC: VectorCommitmentGadget> AbsorbableGadget<VC::ConstraintField> for IncomingInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.phi.absorb_into(dest)?;
        self.x.absorb_into(dest)
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
            phi: cond.select(&true_value.phi, &false_value.phi)?,
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
        vec![&self.phi]
    }

    fn public_inputs(&self) -> &Vec<VC::ScalarVar> {
        &self.x
    }
}
