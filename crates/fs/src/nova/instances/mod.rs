//! Definitions of out-of-circuit values and in-circuit variables for Nova
//! instances.

use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::CommitmentDef, transcripts::Absorbable,
    utils::dummy::Dummy,
};

use crate::FoldingInstance;

pub mod circuits;

/// [`RunningInstance`] defines Nova's running instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningInstance<CM: CommitmentDef> {
    /// [`RunningInstance::cm_e`] is the error term commitment.
    pub cm_e: CM::Commitment,
    /// [`RunningInstance::u`] is the constant term.
    pub u: CM::Scalar,
    /// [`RunningInstance::cm_w`] is the witness commitment.
    pub cm_w: CM::Commitment,
    /// [`RunningInstance::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for RunningInstance<CM> {
    fn commitments(&self) -> Vec<CM::Commitment> {
        vec![self.cm_e.clone(), self.cm_w.clone()]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }
}

impl<CM: CommitmentDef> Dummy<&ArithConfig> for RunningInstance<CM> {
    fn dummy(cfg: &ArithConfig) -> Self {
        Self {
            cm_e: Default::default(),
            u: Default::default(),
            cm_w: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for RunningInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.cm_e.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}

/// [`IncomingInstance`] defines Nova's incoming instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingInstance<CM: CommitmentDef> {
    /// [`IncomingInstance::cm_w`] is the witness commitment.
    pub cm_w: CM::Commitment,
    /// [`IncomingInstance::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for IncomingInstance<CM> {
    fn commitments(&self) -> Vec<CM::Commitment> {
        vec![self.cm_w.clone()]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }
}

impl<CM: CommitmentDef> Dummy<&ArithConfig> for IncomingInstance<CM> {
    fn dummy(cfg: &ArithConfig) -> Self {
        Self {
            cm_w: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for IncomingInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.x.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}
