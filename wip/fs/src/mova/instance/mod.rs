use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::VectorCommitment, traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    // Random evaluation point for the E
    pub r_e: Vec<VC::Scalar>,
    // Evaluation of the MLE of E at r_E
    pub v: VC::Scalar,
    pub u: VC::Scalar,
    pub cm_w: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm_w]
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
            r_e: vec![Default::default(); cfg.log_constraints()],
            v: Default::default(),
            u: Default::default(),
            cm_w: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<VC: VectorCommitment> Absorbable for RunningInstance<VC> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.v.absorb_into(dest);
        self.r_e.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}
