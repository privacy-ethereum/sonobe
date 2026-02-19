//! In-circuit variables for ProtoGalaxy witnesses.

use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::CommitmentDefGadget;

use super::{IncomingWitness, RunningWitness};

/// [`RunningWitnessVar`] defines ProtoGalaxy's running witness variable.
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

/// [`IncomingWitnessVar`] defines ProtoGalaxy's incoming witness variable.
#[derive(Debug, PartialEq)]
pub struct IncomingWitnessVar<CM: CommitmentDefGadget> {
    /// [`IncomingWitnessVar::w`] is the witness (to the circuit).
    pub w: Vec<CM::ScalarVar>,
    /// [`IncomingWitnessVar::r`] is the randomness for the witness commitment.
    pub r: CM::RandomnessVar,
}

impl<CM: CommitmentDefGadget> AllocVar<IncomingWitness<CM::Widget>, CM::ConstraintField>
    for IncomingWitnessVar<CM>
{
    fn new_variable<T: Borrow<IncomingWitness<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
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

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for IncomingWitnessVar<CM> {
    type Value = IncomingWitness<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.w.cs().or(self.r.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(IncomingWitness {
            w: self.w.value()?,
            r: self.r.value()?,
        })
    }
}
