//! In-circuit variables for HyperNova instances.
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

use super::{CCCSInstance, LCCCSInstance};
use crate::FoldingInstanceVar;

/// [`LCCCSInstanceVar`] defines HyperNova's running instance variable.
#[derive(Clone, Debug, PartialEq)]
pub struct LCCCSInstanceVar<CM: CommitmentDefGadget> {
    /// [`LCCCSInstanceVar::cm`] is the witness commitment.
    pub cm: CM::CommitmentVar,
    /// [`LCCCSInstanceVar::u`] is the constant term.
    pub u: CM::ScalarVar,
    /// [`LCCCSInstanceVar::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::ScalarVar>,
    /// [`LCCCSInstanceVar::r_x`] is the random evaluation point.
    pub r_x: Vec<CM::ScalarVar>,
    /// [`LCCCSInstanceVar::v`] is the vector of sums of MLE evaluations defined
    /// in Definition 2.
    pub v: Vec<CM::ScalarVar>,
}

impl<CM: CommitmentDefGadget> AllocVar<LCCCSInstance<CM::Widget>, CM::ConstraintField>
    for LCCCSInstanceVar<CM>
{
    fn new_variable<T: Borrow<LCCCSInstance<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let LCCCSInstance { cm, u, x, r_x, v } = v.borrow();
        Ok(Self {
            cm: AllocVar::new_variable(cs.clone(), || Ok(cm), mode)?,
            u: AllocVar::new_variable(cs.clone(), || Ok(u), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
            r_x: AllocVar::new_variable(cs.clone(), || Ok(&r_x[..]), mode)?,
            v: AllocVar::new_variable(cs.clone(), || Ok(&v[..]), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for LCCCSInstanceVar<CM> {
    type Value = LCCCSInstance<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.cm
            .cs()
            .or(self.u.cs())
            .or(self.x.cs())
            .or(self.r_x.cs())
            .or(self.v.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(LCCCSInstance {
            cm: self.cm.value()?,
            u: self.u.value()?,
            x: self.x.value()?,
            r_x: self.r_x.value()?,
            v: self.v.value()?,
        })
    }
}

impl<CM: CommitmentDefGadget> AbsorbableVar<CM::ConstraintField> for LCCCSInstanceVar<CM> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<CM::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.cm.absorb_into(dest)?;
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.r_x.absorb_into(dest)?;
        self.v.absorb_into(dest)
    }
}

impl<CM: CommitmentDefGadget> CondSelectGadget<CM::ConstraintField> for LCCCSInstanceVar<CM> {
    fn conditionally_select(
        cond: &Boolean<CM::ConstraintField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.x.len() != false_value.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if true_value.r_x.len() != false_value.r_x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if true_value.v.len() != false_value.v.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            cm: cond.select(&true_value.cm, &false_value.cm)?,
            u: cond.select(&true_value.u, &false_value.u)?,
            x: true_value
                .x
                .iter()
                .zip(&false_value.x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
            r_x: true_value
                .r_x
                .iter()
                .zip(&false_value.r_x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
            v: true_value
                .v
                .iter()
                .zip(&false_value.v)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for LCCCSInstanceVar<CM> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![&self.cm]
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
            cm: AllocVar::new_witness(cs.clone(), || Ok(&u.cm))?,
            u: AllocVar::new_witness(cs.clone(), || Ok(&u.u))?,
            x,
            r_x: AllocVar::new_witness(cs.clone(), || Ok(&u.r_x[..]))?,
            v: AllocVar::new_witness(cs.clone(), || Ok(&u.v[..]))?,
        })
    }
}

/// [`CCCSInstanceVar`] defines HyperNova's incoming instance variable.
#[derive(Clone, Debug, PartialEq)]
pub struct CCCSInstanceVar<CM: CommitmentDefGadget> {
    /// [`CCCSInstanceVar::cm`] is the witness commitment.
    pub cm: CM::CommitmentVar,
    /// [`CCCSInstanceVar::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::ScalarVar>,
}

impl<CM: CommitmentDefGadget> AllocVar<CCCSInstance<CM::Widget>, CM::ConstraintField>
    for CCCSInstanceVar<CM>
{
    fn new_variable<T: Borrow<CCCSInstance<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let CCCSInstance { cm, x } = v.borrow();
        Ok(Self {
            cm: AllocVar::new_variable(cs.clone(), || Ok(cm), mode)?,
            x: AllocVar::new_variable(cs.clone(), || Ok(&x[..]), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for CCCSInstanceVar<CM> {
    type Value = CCCSInstance<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.cm.cs().or(self.x.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(CCCSInstance {
            cm: self.cm.value()?,
            x: self.x.value()?,
        })
    }
}

impl<CM: CommitmentDefGadget> AbsorbableVar<CM::ConstraintField> for CCCSInstanceVar<CM> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<CM::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.cm.absorb_into(dest)?;
        self.x.absorb_into(dest)
    }
}

impl<CM: CommitmentDefGadget> CondSelectGadget<CM::ConstraintField> for CCCSInstanceVar<CM> {
    fn conditionally_select(
        cond: &Boolean<CM::ConstraintField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.x.len() != false_value.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            cm: cond.select(&true_value.cm, &false_value.cm)?,
            x: true_value
                .x
                .iter()
                .zip(&false_value.x)
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for CCCSInstanceVar<CM> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![&self.cm]
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
            cm: AllocVar::new_witness(cs.clone(), || Ok(&u.cm))?,
            x,
        })
    }
}
