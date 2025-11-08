use sonobe_primitives::{arithmetizations::ArithConfig, commitments::VectorCommitment, traits::Dummy};

use crate::FoldingWitness;

pub mod circuits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningWitness<VC: VectorCommitment> {
    pub e: Vec<VC::Scalar>,
    pub r_e: VC::Randomness,
    pub w: Vec<VC::Scalar>,
    pub r_w: VC::Randomness,
}

impl<VC: VectorCommitment> FoldingWitness<VC> for RunningWitness<VC> {
    const N_OPENINGS: usize = 2;

    fn openings(
        &self,
    ) -> Vec<(
        &[VC::Scalar],
        &VC::Randomness,
    )> {
        vec![(&self.e, &self.r_e), (&self.w, &self.r_w)]
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for RunningWitness<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            e: vec![Default::default(); cfg.n_constraints()],
            r_e: Default::default(),
            w: vec![Default::default(); cfg.n_witnesses()],
            r_w: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r_w: VC::Randomness,
}

impl<VC: VectorCommitment> FoldingWitness<VC> for IncomingWitness<VC> {
    const N_OPENINGS: usize = 1;

    fn openings(
        &self,
    ) -> Vec<(
        &[VC::Scalar],
        &VC::Randomness,
    )> {
        vec![(&self.w, &self.r_w)]
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for IncomingWitness<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r_w: Default::default(),
        }
    }
}
