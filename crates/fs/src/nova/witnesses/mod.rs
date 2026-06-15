//! Definitions of out-of-circuit values and in-circuit variables for Nova
//! witnesses.

use sonobe_primitives::{arithmetizations::ArithConfig, commitments::CommitmentDef, traits::Dummy};

use crate::FoldingWitness;

pub mod circuits;

/// [`RunningWitness`] defines Nova's running witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningWitness<CM: CommitmentDef> {
    /// [`RunningWitness::e`] is the error term.
    pub e: Vec<CM::Scalar>,
    /// [`RunningWitness::r_e`] is the randomness for the error term commitment.
    pub r_e: CM::Randomness,
    /// [`RunningWitness::w`] is the vector of witnesses (to the circuit).
    pub w: Vec<CM::Scalar>,
    /// [`RunningWitness::r_w`] is the randomness for the witness commitment.
    pub r_w: CM::Randomness,
}

impl<CM: CommitmentDef> FoldingWitness<CM> for RunningWitness<CM> {}

impl<CM: CommitmentDef> Dummy<&ArithConfig> for RunningWitness<CM> {
    fn dummy(cfg: &ArithConfig) -> Self {
        Self {
            e: vec![Default::default(); cfg.n_constraints],
            r_e: Default::default(),
            w: vec![Default::default(); cfg.n_witnesses],
            r_w: Default::default(),
        }
    }
}

/// [`IncomingWitness`] defines Nova's incoming witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingWitness<CM: CommitmentDef> {
    /// [`IncomingWitness::w`] is the witness (to the circuit).
    pub w: Vec<CM::Scalar>,
    /// [`IncomingWitness::r_w`] is the randomness for the witness commitment.
    pub r_w: CM::Randomness,
}

impl<CM: CommitmentDef> FoldingWitness<CM> for IncomingWitness<CM> {}

impl<CM: CommitmentDef> Dummy<&ArithConfig> for IncomingWitness<CM> {
    fn dummy(cfg: &ArithConfig) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses],
            r_w: Default::default(),
        }
    }
}
