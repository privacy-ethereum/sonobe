use ark_ff::PrimeField;
use ark_std::log2;
use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::VectorCommitment, traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    pub phi: VC::Commitment,
    pub betas: Vec<VC::Scalar>,
    pub e: VC::Scalar,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.phi]
    }

    fn public_inputs(&self) -> &[VC::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [VC::Scalar] {
        &mut self.x
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for RunningInstance<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            phi: Default::default(),
            betas: vec![Default::default(); log2(cfg.n_constraints()) as usize],
            e: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<VC: VectorCommitment> Absorbable for RunningInstance<VC> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.phi.absorb_into(dest);
        self.betas.absorb_into(dest);
        self.e.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingInstance<VC: VectorCommitment> {
    pub phi: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for IncomingInstance<VC> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.phi]
    }

    fn public_inputs(&self) -> &[VC::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [VC::Scalar] {
        &mut self.x
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for IncomingInstance<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            phi: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<VC: VectorCommitment> Absorbable for IncomingInstance<VC> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.phi.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}
