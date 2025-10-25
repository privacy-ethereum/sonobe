use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;

use sonobe_primitives::commitments::VectorCommitmentGadget;
use sonobe_primitives::transcripts::AbsorbableGadget;
use sonobe_primitives::{commitments::VectorCommitment, transcripts::Absorbable};

use crate::{FoldingInstance, FoldingInstanceVar};

use super::RunningInstance;

#[derive(Debug, PartialEq)]
pub struct RunningInstanceVar<VC: VectorCommitmentGadget> {
    pub u: VC::ScalarVar,
    pub cm: VC::CommitmentVar,
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
        let RunningInstance { u, cm, x } = v.borrow();
        Ok(Self {
            u: AllocVar::new_variable(cs.clone(), || Ok(u), mode)?,
            cm: AllocVar::new_variable(cs.clone(), || Ok(cm), mode)?,
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
        self.cm.absorb_into(dest)
    }
}
