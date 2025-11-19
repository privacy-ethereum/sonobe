use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::VectorCommitmentGadget;

use super::RunningWitness;

#[derive(Debug, PartialEq)]
pub struct RunningWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r_w: VC::RandomnessVar,
    pub e: Vec<VC::ScalarVar>,
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
        let RunningWitness { w, r_w, e } = v.borrow();
        Ok(Self {
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r_w: AllocVar::new_variable(cs.clone(), || Ok(r_w), mode)?,
            e: AllocVar::new_variable(cs.clone(), || Ok(&e[..]), mode)?,
        })
    }
}

impl<VC: VectorCommitmentGadget> GR1CSVar<VC::ConstraintField> for RunningWitnessVar<VC> {
    type Value = RunningWitness<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.w.cs().or(self.r_w.cs()).or(self.e.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningWitness {
            w: self.w.value()?,
            r_w: self.r_w.value()?,
            e: self.e.value()?,
        })
    }
}
