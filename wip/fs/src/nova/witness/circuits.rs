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
    pub e: Vec<VC::ScalarVar>,
    pub r_e: VC::RandomnessVar,
    pub w: Vec<VC::ScalarVar>,
    pub r_w: VC::RandomnessVar,
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

impl<VC: VectorCommitmentGadget> GR1CSVar<VC::ConstraintField> for RunningWitnessVar<VC> {
    type Value = RunningWitness<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.e
            .cs()
            .or(self.r_e.cs())
            .or(self.w.cs())
            .or(self.r_w.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningWitness {
            e: self.e.value()?,
            r_e: self.r_e.value()?,
            w: self.w.value()?,
            r_w: self.r_w.value()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct IncomingWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r_w: VC::RandomnessVar,
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

impl<VC: VectorCommitmentGadget> GR1CSVar<VC::ConstraintField> for IncomingWitnessVar<VC> {
    type Value = IncomingWitness<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.w.cs().or(self.r_w.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(IncomingWitness {
            w: self.w.value()?,
            r_w: self.r_w.value()?,
        })
    }
}
