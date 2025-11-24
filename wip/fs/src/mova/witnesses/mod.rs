use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::VectorCommitmentDef, traits::Dummy,
};

use crate::FoldingWitness;

pub mod circuits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningWitness<VC: VectorCommitmentDef> {
    pub w: Vec<VC::Scalar>,
    pub r_w: VC::Randomness,
    pub e: Vec<VC::Scalar>,
}

impl<VC: VectorCommitmentDef> FoldingWitness<VC> for RunningWitness<VC> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)> {
        vec![(&self.w, &self.r_w)]
    }
}

impl<VC: VectorCommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for RunningWitness<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r_w: Default::default(),
            e: vec![Default::default(); cfg.n_constraints()],
        }
    }
}
