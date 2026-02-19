//! Definitions of out-of-circuit values and in-circuit variables for Mova
//! instances.

use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::CommitmentDef, traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

/// [`RunningInstance`] defines Mova's running instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningInstance<CM: CommitmentDef> {
    /// [`RunningInstance::r_e`] is the random evaluation point for the error
    /// term.
    pub r_e: Vec<CM::Scalar>,
    /// [`RunningInstance::v`] is the evaluation of the MLE of the error term
    /// at `r_e`.
    pub v: CM::Scalar,
    /// [`RunningInstance::u`] is the constant term.
    pub u: CM::Scalar,
    /// [`RunningInstance::cm_w`] is the witness commitment.
    pub cm_w: CM::Commitment,
    /// [`RunningInstance::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for RunningInstance<CM> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![&self.cm_w]
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
            r_e: vec![Default::default(); cfg.log_constraints()],
            v: Default::default(),
            u: Default::default(),
            cm_w: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for RunningInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.v.absorb_into(dest);
        self.r_e.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}
