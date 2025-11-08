use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::VectorCommitment, traits::Dummy,
};

use crate::FoldingWitness;

pub mod circuits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LCCCSWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

impl<VC: VectorCommitment> FoldingWitness<VC> for LCCCSWitness<VC> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)> {
        vec![(&self.w, &self.r)]
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for LCCCSWitness<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CCCSWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

impl<VC: VectorCommitment> FoldingWitness<VC> for CCCSWitness<VC> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)> {
        vec![(&self.w, &self.r)]
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for CCCSWitness<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r: Default::default(),
        }
    }
}
