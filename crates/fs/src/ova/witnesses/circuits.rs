//! In-circuit variables for Ova witnesses.

use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::CommitmentDefGadget;

use super::RunningWitness;

/// [`RunningWitnessVar`] defines Ova's running witness variable.
#[derive(Debug, PartialEq)]
pub struct RunningWitnessVar<CM: CommitmentDefGadget> {
    /// [`RunningWitnessVar::w`] is the witness (to the circuit).
    pub w: Vec<CM::ScalarVar>,
    /// [`RunningWitnessVar::r`] is the randomness for the witness commitment.
    pub r: CM::RandomnessVar,
}

impl<CM: CommitmentDefGadget> AllocVar<RunningWitness<CM::Widget>, CM::ConstraintField>
    for RunningWitnessVar<CM>
{
    fn new_variable<T: Borrow<RunningWitness<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
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

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for RunningWitnessVar<CM> {
    type Value = RunningWitness<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.w.cs().or(self.r.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningWitness {
            w: self.w.value()?,
            r: self.r.value()?,
        })
    }
}
