use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    commitments::{VectorCommitment, VectorCommitmentGadget},
    transcripts::{Absorbable, AbsorbableGadget},
};

use super::{CCCSInstance, LCCCSInstance};
use crate::{FoldingInstance, FoldingInstanceVar};

#[derive(Debug, PartialEq)]
pub struct LCCCSInstanceVar<VC: VectorCommitmentGadget> {
    pub cm: VC::CommitmentVar,
    pub u: VC::ScalarVar,
    pub x: Vec<VC::ScalarVar>,
    pub r_x: Vec<VC::ScalarVar>,
    pub v: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for LCCCSInstanceVar<VC> {
    type Native = LCCCSInstance<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<LCCCSInstance<VC::Native>, VC::ConstraintField>
    for LCCCSInstanceVar<VC>
{
    fn new_variable<T: Borrow<LCCCSInstance<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let LCCCSInstance { cm, u, x, r_x, v } = v.borrow();
        Ok(Self {
            cm: AllocVar::new_variable(cs.clone(), || Ok(cm), mode)?,
            u: AllocVar::new_variable(cs.clone(), || Ok(u), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
            r_x: AllocVar::new_variable(cs.clone(), || Ok(&r_x[..]), mode)?,
            v: AllocVar::new_variable(cs.clone(), || Ok(&v[..]), mode)?,
        })
    }
}

impl<FV, VC> AbsorbableGadget<FV> for LCCCSInstanceVar<VC>
where
    VC: VectorCommitmentGadget<
        ScalarVar: AbsorbableGadget<FV>,
        CommitmentVar: AbsorbableGadget<FV>,
    >,
{
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        self.cm.absorb_into(dest)?;
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.r_x.absorb_into(dest)?;
        self.v.absorb_into(dest)
    }
}

#[derive(Debug, PartialEq)]
pub struct CCCSInstanceVar<VC: VectorCommitmentGadget> {
    pub cm: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for CCCSInstanceVar<VC> {
    type Native = CCCSInstance<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<CCCSInstance<VC::Native>, VC::ConstraintField>
    for CCCSInstanceVar<VC>
{
    fn new_variable<T: Borrow<CCCSInstance<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let CCCSInstance { cm, x } = v.borrow();
        Ok(Self {
            cm: AllocVar::new_variable(cs.clone(), || Ok(cm), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<FV, VC> AbsorbableGadget<FV> for CCCSInstanceVar<VC>
where
    VC: VectorCommitmentGadget<
        ScalarVar: AbsorbableGadget<FV>,
        CommitmentVar: AbsorbableGadget<FV>,
    >,
{
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        self.x.absorb_into(dest)?;
        self.cm.absorb_into(dest)
    }
}
