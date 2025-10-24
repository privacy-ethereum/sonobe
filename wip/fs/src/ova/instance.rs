use std::borrow::Borrow;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use sonobe_primitives::{
    commitments::VectorCommitment, transcripts::Absorbable,
};
use sonobe_primitives::commitments::VectorCommitmentGadget;
use sonobe_primitives::transcripts::AbsorbableGadget;
use crate::{FoldingInstance, FoldingInstanceVar};

#[derive(Debug, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    pub u: VC::Scalar,
    pub cm: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

#[derive(Debug, PartialEq)]
pub struct RunningInstanceVar<VC: VectorCommitmentGadget> {
    pub u: VC::ScalarVar,
    pub cm: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

pub type IncomingInstance<VC> = Vec<<VC as VectorCommitment>::Scalar>;

pub type IncomingInstanceVar<VC> = Vec<<VC as VectorCommitmentGadget>::ScalarVar>;

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
    }
}

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for RunningInstance<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.cm.absorb_into(dest);
    }
}

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for RunningInstanceVar<VC> {
    type Native = RunningInstance<VC::Native>;
}

impl<VC: VectorCommitmentGadget, F: Field> AllocVar<RunningInstance<VC::Native>, F> for RunningInstanceVar<VC>
{
    fn new_variable<T: Borrow<RunningInstance<VC::Native>>>(cs: impl Into<Namespace<F>>, f: impl FnOnce() -> Result<T, SynthesisError>, mode: AllocationMode) -> Result<Self, SynthesisError> {
        todo!()
    }
}

impl<FV, VC: VectorCommitmentGadget<ScalarVar: AbsorbableGadget<FV>, CommitmentVar: AbsorbableGadget<FV>>>
    AbsorbableGadget<FV> for RunningInstanceVar<VC>
{
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.cm.absorb_into(dest)
    }
}
