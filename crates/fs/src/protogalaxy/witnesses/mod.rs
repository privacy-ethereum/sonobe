//! Definitions of out-of-circuit values and in-circuit variables for ProtoGalaxy
//! witnesses.

use sonobe_primitives::{arithmetizations::ArithConfig, commitments::CommitmentDef, traits::Dummy};

use crate::FoldingWitness;

pub mod circuits;

/// [`RunningWitness`] defines ProtoGalaxy's running witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningWitness<CM: CommitmentDef> {
    /// [`RunningWitness::w`] is the witness (to the circuit).
    pub w: Vec<CM::Scalar>,
    /// [`RunningWitness::r`] is the randomness for the witness commitment.
    pub r: CM::Randomness,
}

impl<CM: CommitmentDef> FoldingWitness<CM> for RunningWitness<CM> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[CM::Scalar], &CM::Randomness)> {
        vec![(&self.w, &self.r)]
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for RunningWitness<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r: Default::default(),
        }
    }
}

/// [`IncomingWitness`] defines ProtoGalaxy's incoming witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingWitness<CM: CommitmentDef> {
    /// [`IncomingWitness::w`] is the witness (to the circuit).
    pub w: Vec<CM::Scalar>,
    /// [`IncomingWitness::r`] is the randomness for the witness commitment.
    pub r: CM::Randomness,
}

impl<CM: CommitmentDef> FoldingWitness<CM> for IncomingWitness<CM> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[CM::Scalar], &CM::Randomness)> {
        vec![(&self.w, &self.r)]
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for IncomingWitness<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r: Default::default(),
        }
    }
}
