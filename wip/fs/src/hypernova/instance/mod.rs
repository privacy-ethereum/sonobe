use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::{
        ccs::{CCSConfig, CCSVariant},
        ArithConfig,
    },
    commitments::VectorCommitmentDef,
    traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LCCCSInstance<VC: VectorCommitmentDef> {
    pub cm: VC::Commitment,
    pub u: VC::Scalar,
    pub x: Vec<VC::Scalar>,
    pub r_x: Vec<VC::Scalar>,
    pub v: Vec<VC::Scalar>,
}

impl<VC: VectorCommitmentDef> FoldingInstance<VC> for LCCCSInstance<VC> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &[VC::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [VC::Scalar] {
        &mut self.x
    }
}

impl<VC: VectorCommitmentDef, V: CCSVariant> Dummy<&CCSConfig<V>> for LCCCSInstance<VC> {
    fn dummy(cfg: &CCSConfig<V>) -> Self {
        Self {
            cm: Default::default(),
            u: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
            r_x: vec![Default::default(); cfg.log_constraints()],
            v: vec![Default::default(); V::n_matrices()],
        }
    }
}

impl<VC: VectorCommitmentDef> Absorbable for LCCCSInstance<VC> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.cm.absorb_into(dest);
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.r_x.absorb_into(dest);
        self.v.absorb_into(dest);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CCCSInstance<VC: VectorCommitmentDef> {
    pub cm: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitmentDef> FoldingInstance<VC> for CCCSInstance<VC> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &[VC::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [VC::Scalar] {
        &mut self.x
    }
}

impl<VC: VectorCommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for CCCSInstance<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            cm: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<VC: VectorCommitmentDef> Absorbable for CCCSInstance<VC> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.cm.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}
