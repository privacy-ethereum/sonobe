use ark_ff::PrimeField;
use ark_std::log2;
use sonobe_primitives::{arithmetizations::{ArithConfig, ccs::CCSConfig}, commitments::VectorCommitment, traits::Dummy, transcripts::Absorbable};

use crate::FoldingInstance;

pub mod circuits;

#[derive(Clone, Debug, PartialEq)]
pub struct LCCCSInstance<VC: VectorCommitment> {
    pub cm: VC::Commitment,
    pub u: VC::Scalar,
    pub x: Vec<VC::Scalar>,
    pub r_x: Vec<VC::Scalar>,
    pub v: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for LCCCSInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &[<VC as VectorCommitment>::Scalar] {
        &self.x
    }
}

impl<VC: VectorCommitment> Dummy<&CCSConfig<VC::Scalar>> for LCCCSInstance<VC> {
    fn dummy(cfg: &CCSConfig<VC::Scalar>) -> Self {
        Self {
            cm: Default::default(),
            u: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
            r_x: vec![Default::default(); log2(cfg.n_constraints()) as usize],
            v: vec![Default::default(); cfg.t],
        }
    }
}

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for LCCCSInstance<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.cm.absorb_into(dest);
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.r_x.absorb_into(dest);
        self.v.absorb_into(dest);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CCCSInstance<VC: VectorCommitment> {
    pub cm: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for CCCSInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &[<VC as VectorCommitment>::Scalar] {
        &self.x
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for CCCSInstance<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            cm: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for CCCSInstance<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.cm.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}
