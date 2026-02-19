//! Definitions of out-of-circuit values and in-circuit variables for Mova
//! witnesses.

use sonobe_primitives::{arithmetizations::ArithConfig, commitments::CommitmentDef, traits::Dummy};

use crate::FoldingWitness;

pub mod circuits;

/// [`RunningWitness`] defines Mova's running witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningWitness<CM: CommitmentDef> {
    /// [`RunningWitness::w`] is the witness (to the circuit).
    pub w: Vec<CM::Scalar>,
    /// [`RunningWitness::r_w`] is the randomness for the witness commitment.
    pub r_w: CM::Randomness,
    /// [`RunningWitness::e`] is the error term.
    pub e: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingWitness<CM> for RunningWitness<CM> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[CM::Scalar], &CM::Randomness)> {
        vec![(&self.w, &self.r_w)]
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for RunningWitness<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r_w: Default::default(),
            e: vec![Default::default(); cfg.n_constraints()],
        }
    }
}
