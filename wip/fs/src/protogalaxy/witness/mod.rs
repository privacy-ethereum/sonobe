use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::VectorCommitment, traits::Dummy,
};

use crate::FoldingWitness;

pub mod circuits;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

impl<VC: VectorCommitment> FoldingWitness<VC> for RunningWitness<VC> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)> {
        vec![(&self.w, &self.r)]
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for RunningWitness<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r: Default::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

impl<VC: VectorCommitment> FoldingWitness<VC> for IncomingWitness<VC> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)> {
        vec![(&self.w, &self.r)]
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for IncomingWitness<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r: Default::default(),
        }
    }
}
