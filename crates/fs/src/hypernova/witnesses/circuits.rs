//! In-circuit variables for HyperNova witnesses.

use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::CommitmentDefGadget;

use super::{CCCSWitness, LCCCSWitness};

/// [`LCCCSWitnessVar`] defines HyperNova's running witness variable.
#[derive(Debug, PartialEq)]
pub struct LCCCSWitnessVar<CM: CommitmentDefGadget> {
    /// [`LCCCSWitnessVar::w`] is the witness (to the circuit).
    pub w: Vec<CM::ScalarVar>,
    /// [`LCCCSWitnessVar::r`] is the randomness for the witness commitment.
    pub r: CM::RandomnessVar,
}

impl<CM: CommitmentDefGadget> AllocVar<LCCCSWitness<CM::Widget>, CM::ConstraintField>
    for LCCCSWitnessVar<CM>
{
    fn new_variable<T: Borrow<LCCCSWitness<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
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

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for LCCCSWitnessVar<CM> {
    type Value = LCCCSWitness<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.w.cs().or(self.r.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(LCCCSWitness {
            w: self.w.value()?,
            r: self.r.value()?,
        })
    }
}

/// [`CCCSWitnessVar`] defines HyperNova's incoming witness variable.
#[derive(Debug, PartialEq)]
pub struct CCCSWitnessVar<CM: CommitmentDefGadget> {
    /// [`CCCSWitnessVar::w`] is the witness (to the circuit).
    pub w: Vec<CM::ScalarVar>,
    /// [`CCCSWitnessVar::r`] is the randomness for the witness commitment.
    pub r: CM::RandomnessVar,
}

impl<CM: CommitmentDefGadget> AllocVar<CCCSWitness<CM::Widget>, CM::ConstraintField>
    for CCCSWitnessVar<CM>
{
    fn new_variable<T: Borrow<CCCSWitness<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
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

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for CCCSWitnessVar<CM> {
    type Value = CCCSWitness<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.w.cs().or(self.r.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(CCCSWitness {
            w: self.w.value()?,
            r: self.r.value()?,
        })
    }
}
