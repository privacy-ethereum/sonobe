use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::VectorCommitment, traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    pub cm_e: VC::Commitment,
    pub u: VC::Scalar,
    pub cm_w: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm_e, &self.cm_w]
    }

    fn public_inputs(&self) -> &[<VC as VectorCommitment>::Scalar] {
        &self.x
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for RunningInstance<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            cm_e: Default::default(),
            u: Default::default(),
            cm_w: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for RunningInstance<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.cm_e.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IncomingInstance<VC: VectorCommitment> {
    pub cm_w: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for IncomingInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm_w]
    }

    fn public_inputs(&self) -> &[<VC as VectorCommitment>::Scalar] {
        &self.x
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for IncomingInstance<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            cm_w: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for IncomingInstance<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.x.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}
