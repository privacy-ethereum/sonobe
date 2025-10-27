use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    circuits::var::Var,
    commitments::{VectorCommitment, VectorCommitmentGadget},
    transcripts::{Absorbable, AbsorbableGadget},
};

use super::{CCCSInstance, LCCCSInstance};
use crate::{FoldingInstance, FoldingInstanceVar};

#[derive(Clone, Debug, PartialEq)]
pub struct LCCCSInstanceVar<VC: VectorCommitmentGadget> {
    pub cm: VC::CommitmentVar,
    pub u: VC::ScalarVar,
    pub x: Vec<VC::ScalarVar>,
    pub r_x: Vec<VC::ScalarVar>,
    pub v: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadget> Var<VC::ConstraintField> for LCCCSInstanceVar<VC> {
    type Native = LCCCSInstance<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<LCCCSInstance<VC::Native>, VC::ConstraintField>
    for LCCCSInstanceVar<VC>
{
    fn new_variable<T: Borrow<LCCCSInstance<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
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

impl<VC: VectorCommitmentGadget> AbsorbableGadget<VC::ConstraintField> for LCCCSInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.cm.absorb_into(dest)?;
        self.u.absorb_into(dest)?;
        self.x.absorb_into(dest)?;
        self.r_x.absorb_into(dest)?;
        self.v.absorb_into(dest)
    }
}

impl<VC: VectorCommitmentGadget> CondSelectGadget<VC::ConstraintField> for LCCCSInstanceVar<VC> {
    fn conditionally_select(
        cond: &Boolean<VC::ConstraintField>,
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

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for LCCCSInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &Vec<VC::ScalarVar> {
        &self.x
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CCCSInstanceVar<VC: VectorCommitmentGadget> {
    pub cm: VC::CommitmentVar,
    pub x: Vec<VC::ScalarVar>,
}

impl<VC: VectorCommitmentGadget> Var<VC::ConstraintField> for CCCSInstanceVar<VC> {
    type Native = CCCSInstance<VC::Native>;
}

impl<VC: VectorCommitmentGadget> AllocVar<CCCSInstance<VC::Native>, VC::ConstraintField>
    for CCCSInstanceVar<VC>
{
    fn new_variable<T: Borrow<CCCSInstance<VC::Native>>>(
        cs: impl Into<Namespace<VC::ConstraintField>>,
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

impl<VC: VectorCommitmentGadget> AbsorbableGadget<VC::ConstraintField> for CCCSInstanceVar<VC> {
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<VC::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        self.x.absorb_into(dest)?;
        self.cm.absorb_into(dest)
    }
}

impl<VC: VectorCommitmentGadget> CondSelectGadget<VC::ConstraintField> for CCCSInstanceVar<VC> {
    fn conditionally_select(
        cond: &Boolean<VC::ConstraintField>,
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

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for CCCSInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &Vec<VC::ScalarVar> {
        &self.x
    }
}
