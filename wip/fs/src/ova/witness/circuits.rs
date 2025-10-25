use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::{VectorCommitment, VectorCommitmentGadget};

use super::RunningWitness;
use crate::FoldingWitnessVar;

#[derive(Debug, PartialEq)]
pub struct RunningWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r: VC::RandomnessVar,
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
        let RunningWitness { w, r } = v.borrow();
        Ok(Self {
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r: AllocVar::new_variable(cs.clone(), || Ok(r), mode)?,
        })
    }
}
