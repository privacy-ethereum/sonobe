use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::{VectorCommitment, VectorCommitmentGadget};

use super::{IncomingWitness, RunningWitness};
use crate::FoldingWitnessVar;

#[derive(Debug, PartialEq)]
pub struct RunningWitnessVar<VC: VectorCommitmentGadget> {
    pub e: Vec<VC::ScalarVar>,
    pub r_e: VC::RandomnessVar,
    pub w: Vec<VC::ScalarVar>,
    pub r_w: VC::RandomnessVar,
}

impl<VC: VectorCommitmentGadget> FoldingWitnessVar<VC> for RunningWitnessVar<VC> {
    type Native = RunningWitness<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<RunningWitness<VC::Native>, VC::ConstraintField>
    for RunningWitnessVar<VC>
{
    fn new_variable<T: Borrow<RunningWitness<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let RunningWitness { e, r_e, w, r_w } = v.borrow();
        Ok(Self {
            e: AllocVar::new_variable(cs.clone(), || Ok(&e[..]), mode)?,
            r_e: AllocVar::new_variable(cs.clone(), || Ok(r_e), mode)?,
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r_w: AllocVar::new_variable(cs.clone(), || Ok(r_w), mode)?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct IncomingWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r_w: VC::RandomnessVar,
}

impl<VC: VectorCommitmentGadget> FoldingWitnessVar<VC> for IncomingWitnessVar<VC> {
    type Native = IncomingWitness<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<IncomingWitness<VC::Native>, VC::ConstraintField>
    for IncomingWitnessVar<VC>
{
    fn new_variable<T: Borrow<IncomingWitness<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let IncomingWitness { w, r_w } = v.borrow();
        Ok(Self {
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r_w: AllocVar::new_variable(cs.clone(), || Ok(r_w), mode)?,
        })
    }
}
