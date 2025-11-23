use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{commitments::VectorCommitmentGadgetDef, transcripts::AbsorbableGadget};

use super::{IncomingInstance, RunningInstance};
use crate::FoldingInstanceVar;

#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<VC: VectorCommitmentGadgetDef> {
    pub phi: VC::CommitmentVar,
    pub betas: Vec<VC::ScalarVar>,
    pub e: VC::ScalarVar,
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
        let RunningInstance { phi, betas, e, x } = v.borrow();
        Ok(Self {
            phi: AllocVar::new_variable(cs.clone(), || Ok(phi), mode)?,
            betas: AllocVar::new_variable(cs.clone(), || Ok(&betas[..]), mode)?,
            e: AllocVar::new_variable(cs.clone(), || Ok(e), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<VC: VectorCommitmentGadgetDef> GR1CSVar<VC::ConstraintField> for RunningInstanceVar<VC> {
    type Value = RunningInstance<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.phi
            .cs()
            .or(self.betas.cs())
            .or(self.e.cs())
            .or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningInstance {
            phi: self.phi.value()?,
            betas: self.betas.value()?,
            e: self.e.value()?,
            x: self.x.value()?,
        })
    }
}

impl<VC: VectorCommitmentGadgetDef> AbsorbableGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
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

impl<VC: VectorCommitmentGadgetDef> CondSelectGadget<VC::ConstraintField> for RunningInstanceVar<VC> {
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

impl<VC: VectorCommitmentGadgetDef> FoldingInstanceVar<VC> for RunningInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![&self.phi]
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
            phi: AllocVar::new_witness(cs.clone(), || Ok(&u.phi))?,
            betas: AllocVar::new_witness(cs.clone(), || Ok(&u.betas[..]))?,
            e: AllocVar::new_witness(cs.clone(), || Ok(&u.e))?,
            x,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IncomingInstanceVar<VC: VectorCommitmentGadgetDef> {
    pub phi: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadgetDef> AllocVar<IncomingInstance<VC::Native>, VC::ConstraintField>
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

impl<VC: VectorCommitmentGadgetDef> GR1CSVar<VC::ConstraintField> for IncomingInstanceVar<VC> {
    type Value = IncomingInstance<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.phi.cs().or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(IncomingInstance {
            phi: self.phi.value()?,
            x: self.x.value()?,
        })
    }
}

impl<VC: VectorCommitmentGadgetDef> AbsorbableGadget<VC::ConstraintField> for IncomingInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.phi.absorb_into(dest)?;
        self.x.absorb_into(dest)
    }
}

impl<VC: VectorCommitmentGadgetDef> CondSelectGadget<VC::ConstraintField> for IncomingInstanceVar<VC> {
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

impl<VC: VectorCommitmentGadgetDef> FoldingInstanceVar<VC> for IncomingInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![&self.phi]
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
            phi: AllocVar::new_witness(cs.clone(), || Ok(&u.phi))?,
            x,
        })
    }
}
