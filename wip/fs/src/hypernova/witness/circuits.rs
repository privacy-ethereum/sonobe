use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    circuits::var::Var,
    commitments::{VectorCommitment, VectorCommitmentGadget},
};

use super::{CCCSWitness, LCCCSWitness};
use crate::FoldingWitnessVar;

#[derive(Debug, PartialEq)]
pub struct LCCCSWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r: VC::RandomnessVar,
}

impl<VC: VectorCommitmentGadget> Var<VC::ConstraintField> for LCCCSWitnessVar<VC> {
    type Native = LCCCSWitness<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<LCCCSWitness<VC::Native>, VC::ConstraintField>
    for LCCCSWitnessVar<VC>
{
    fn new_variable<T: Borrow<LCCCSWitness<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let LCCCSWitness { w, r } = v.borrow();
        Ok(Self {
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r: AllocVar::new_variable(cs.clone(), || Ok(r), mode)?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct CCCSWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r: VC::RandomnessVar,
}

impl<VC: VectorCommitmentGadget> Var<VC::ConstraintField> for CCCSWitnessVar<VC> {
    type Native = CCCSWitness<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<CCCSWitness<VC::Native>, VC::ConstraintField>
    for CCCSWitnessVar<VC>
{
    fn new_variable<T: Borrow<CCCSWitness<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let CCCSWitness { w, r } = v.borrow();
        Ok(Self {
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r: AllocVar::new_variable(cs.clone(), || Ok(r), mode)?,
        })
    }
}
