//! Definitions of out-of-circuit values and in-circuit variables for Ova
//! instances.

use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::CommitmentDef, traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

/// [`RunningInstance`] defines Ova's running instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningInstance<CM: CommitmentDef> {
    /// [`RunningInstance::u`] is the constant term.
    pub u: CM::Scalar,
    /// [`RunningInstance::cm`] is the combined witness and error term
    /// commitment.
    pub cm: CM::Commitment,
    /// [`RunningInstance::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for RunningInstance<CM> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar] {
        &mut self.x
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for RunningInstance<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            u: Default::default(),
            cm: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for RunningInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.cm.absorb_into(dest);
    }
}
