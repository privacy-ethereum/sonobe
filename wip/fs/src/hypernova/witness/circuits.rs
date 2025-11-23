use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::VectorCommitmentGadgetDef;

use super::{CCCSWitness, LCCCSWitness};

#[derive(Debug, PartialEq)]
pub struct LCCCSWitnessVar<VC: VectorCommitmentGadgetDef> {
    pub w: Vec<VC::ScalarVar>,
    pub r: VC::RandomnessVar,
}

impl<VC: VectorCommitmentGadgetDef> AllocVar<LCCCSWitness<VC::Native>, VC::ConstraintField>
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

impl<VC: VectorCommitmentGadgetDef> GR1CSVar<VC::ConstraintField> for LCCCSWitnessVar<VC> {
    type Value = LCCCSWitness<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.w.cs().or(self.r.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(LCCCSWitness {
            w: self.w.value()?,
            r: self.r.value()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct CCCSWitnessVar<VC: VectorCommitmentGadgetDef> {
    pub w: Vec<VC::ScalarVar>,
    pub r: VC::RandomnessVar,
}

impl<VC: VectorCommitmentGadgetDef> AllocVar<CCCSWitness<VC::Native>, VC::ConstraintField>
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

impl<VC: VectorCommitmentGadgetDef> GR1CSVar<VC::ConstraintField> for CCCSWitnessVar<VC> {
    type Value = CCCSWitness<VC::Native>;

    fn cs(&self) -> ConstraintSystemRef<VC::ConstraintField> {
        self.w.cs().or(self.r.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(CCCSWitness {
            w: self.w.value()?,
            r: self.r.value()?,
        })
    }
}
