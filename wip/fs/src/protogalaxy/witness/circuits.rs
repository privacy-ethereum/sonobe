use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::VectorCommitmentGadget;

use super::{IncomingWitness, RunningWitness};

#[derive(Debug, PartialEq)]
pub struct RunningWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r: VC::RandomnessVar,
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

impl<VC: VectorCommitmentGadget> GR1CSVar<VC::ConstraintField> for RunningWitnessVar<VC> {
    type Value = RunningWitness<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.w.cs().or(self.r.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningWitness {
            w: self.w.value()?,
            r: self.r.value()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct IncomingWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r: VC::RandomnessVar,
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
        let IncomingWitness { w, r } = v.borrow();
        Ok(Self {
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r: AllocVar::new_variable(cs.clone(), || Ok(r), mode)?,
        })
    }
}

impl<VC: VectorCommitmentGadget> GR1CSVar<VC::ConstraintField> for IncomingWitnessVar<VC> {
    type Value = IncomingWitness<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.w.cs().or(self.r.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(IncomingWitness {
            w: self.w.value()?,
            r: self.r.value()?,
        })
    }
}
