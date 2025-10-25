use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    commitments::{VectorCommitment, VectorCommitmentGadget},
    transcripts::{Absorbable, AbsorbableGadget},
};

use super::{IncomingInstance, RunningInstance};
use crate::{FoldingInstance, FoldingInstanceVar};

#[derive(Debug, PartialEq)]
pub struct RunningInstanceVar<VC: VectorCommitmentGadget> {
    pub cm_e: VC::CommitmentVar,
    pub u: VC::ScalarVar,
    pub cm_w: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for RunningInstanceVar<VC> {
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

impl<FV, VC> AbsorbableGadget<FV> for RunningInstanceVar<VC>
where
    VC: VectorCommitmentGadget<
        ScalarVar: AbsorbableGadget<FV>,
        CommitmentVar: AbsorbableGadget<FV>,
    >,
{
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.cm_e.absorb_into(dest)?;
        self.cm_w.absorb_into(dest)
    }
}

#[derive(Debug, PartialEq)]
pub struct IncomingInstanceVar<VC: VectorCommitmentGadget> {
    pub cm_w: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for IncomingInstanceVar<VC> {
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

impl<FV, VC> AbsorbableGadget<FV> for IncomingInstanceVar<VC>
where
    VC: VectorCommitmentGadget<
        ScalarVar: AbsorbableGadget<FV>,
        CommitmentVar: AbsorbableGadget<FV>,
    >,
{
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        self.x.absorb_into(dest)?;
        self.cm_w.absorb_into(dest)
    }
}
