//! In-circuit variables for ProtoGalaxy instances.

use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{commitments::CommitmentDefGadget, transcripts::AbsorbableVar};

use super::{IncomingInstance, RunningInstance};
use crate::FoldingInstanceVar;

/// [`RunningInstanceVar`] defines ProtoGalaxy's running instance variable.
#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstanceVar<CM: CommitmentDefGadget> {
    /// [`RunningInstanceVar::phi`] is the witness commitment.
    pub phi: CM::CommitmentVar,
    /// [`RunningInstanceVar::betas`] is the vector of randomness.
    pub betas: Vec<CM::ScalarVar>,
    /// [`RunningInstanceVar::e`] is the error term.
    pub e: CM::ScalarVar,
    /// [`RunningInstanceVar::x`] is the vector of public inputs (to the
    /// circuit).
    pub x: Vec<CM::ScalarVar>,
}

impl<CM: CommitmentDefGadget> AllocVar<RunningInstance<CM::Widget>, CM::ConstraintField>
    for RunningInstanceVar<CM>
{
    fn new_variable<T: Borrow<RunningInstance<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let RunningInstance { phi, betas, e, x } = v.borrow();
        Ok(Self {
            phi: AllocVar::new_variable(cs.clone(), || Ok(phi), mode)?,
            betas: AllocVar::new_variable(cs.clone(), || Ok(&betas[..]), mode)?,
            e: AllocVar::new_variable(cs.clone(), || Ok(e), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for RunningInstanceVar<CM> {
    type Value = RunningInstance<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.phi
            .cs()
            .or(self.betas.cs())
            .or(self.e.cs())
            .or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningInstance {
            phi: self.phi.value()?,
            betas: self.betas.value()?,
            e: self.e.value()?,
            x: self.x.value()?,
        })
    }
}

impl<CM: CommitmentDefGadget> AbsorbableVar<CM::ConstraintField> for RunningInstanceVar<CM> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<CM::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.phi.absorb_into(dest)?;
        self.betas.absorb_into(dest)?;
        self.e.absorb_into(dest)?;
        self.x.absorb_into(dest)
    }
}

impl<CM: CommitmentDefGadget> CondSelectGadget<CM::ConstraintField> for RunningInstanceVar<CM> {
    fn conditionally_select(
        cond: &Boolean<CM::ConstraintField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.betas.len() != false_value.betas.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if true_value.x.len() != false_value.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            phi: cond.select(&true_value.phi, &false_value.phi)?,
            betas: true_value
                .betas
                .iter()
                .zip(&false_value.betas)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
            e: cond.select(&true_value.e, &false_value.e)?,
            x: true_value
                .x
                .iter()
                .zip(&false_value.x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for RunningInstanceVar<CM> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![&self.phi]
    }

    fn public_inputs(&self) -> &Vec<CM::ScalarVar> {
        &self.x
    }

    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        u: &Self::Value,
        x: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        Ok(Self {
            phi: AllocVar::new_witness(cs.clone(), || Ok(&u.phi))?,
            betas: AllocVar::new_witness(cs.clone(), || Ok(&u.betas[..]))?,
            e: AllocVar::new_witness(cs.clone(), || Ok(&u.e))?,
            x,
        })
    }
}

/// [`IncomingInstanceVar`] defines ProtoGalaxy's incoming instance variable.
#[derive(Clone, Debug, PartialEq)]
pub struct IncomingInstanceVar<CM: CommitmentDefGadget> {
    /// [`IncomingInstanceVar::phi`] is the witness commitment.
    pub phi: CM::CommitmentVar,
    /// [`IncomingInstanceVar::x`] is the vector of public inputs (to the
    /// circuit).
    pub x: Vec<CM::ScalarVar>,
}

impl<CM: CommitmentDefGadget> AllocVar<IncomingInstance<CM::Widget>, CM::ConstraintField>
    for IncomingInstanceVar<CM>
{
    fn new_variable<T: Borrow<IncomingInstance<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let IncomingInstance { phi, x } = v.borrow();
        Ok(Self {
            phi: AllocVar::new_variable(cs.clone(), || Ok(phi), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for IncomingInstanceVar<CM> {
    type Value = IncomingInstance<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.phi.cs().or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(IncomingInstance {
            phi: self.phi.value()?,
            x: self.x.value()?,
        })
    }
}

impl<CM: CommitmentDefGadget> AbsorbableVar<CM::ConstraintField> for IncomingInstanceVar<CM> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<CM::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.phi.absorb_into(dest)?;
        self.x.absorb_into(dest)
    }
}

impl<CM: CommitmentDefGadget> CondSelectGadget<CM::ConstraintField> for IncomingInstanceVar<CM> {
    fn conditionally_select(
        cond: &Boolean<CM::ConstraintField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.x.len() != false_value.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            phi: cond.select(&true_value.phi, &false_value.phi)?,
            x: true_value
                .x
                .iter()
                .zip(&false_value.x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for IncomingInstanceVar<CM> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![&self.phi]
    }

    fn public_inputs(&self) -> &Vec<CM::ScalarVar> {
        &self.x
    }

    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        u: &Self::Value,
        x: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        Ok(Self {
            phi: AllocVar::new_witness(cs.clone(), || Ok(&u.phi))?,
            x,
        })
    }
}
