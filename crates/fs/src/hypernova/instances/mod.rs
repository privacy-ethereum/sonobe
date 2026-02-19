//! Definitions of out-of-circuit values and in-circuit variables for HyperNova
//! instances.

use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::{
        ArithConfig,
        ccs::{CCSConfig, CCSVariant},
    },
    commitments::CommitmentDef,
    traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

/// [`LCCCSInstance`] defines HyperNova's running instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LCCCSInstance<CM: CommitmentDef> {
    /// [`LCCCSInstance::cm`] is the witness commitment.
    pub cm: CM::Commitment,
    /// [`LCCCSInstance::u`] is the constant term.
    pub u: CM::Scalar,
    /// [`LCCCSInstance::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::Scalar>,
    /// [`LCCCSInstance::r_x`] is the random evaluation point.
    pub r_x: Vec<CM::Scalar>,
    /// [`LCCCSInstance::v`] is the vector of sums of MLE evaluations defined in
    /// Definition 2.
    pub v: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for LCCCSInstance<CM> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar] {
        &mut self.x
    }
}

impl<CM: CommitmentDef, V: CCSVariant> Dummy<&CCSConfig<V>> for LCCCSInstance<CM> {
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

impl<CM: CommitmentDef> Absorbable for LCCCSInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.cm.absorb_into(dest);
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.r_x.absorb_into(dest);
        self.v.absorb_into(dest);
    }
}

/// [`CCCSInstance`] defines HyperNova's incoming instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CCCSInstance<CM: CommitmentDef> {
    /// [`CCCSInstance::cm`] is the witness commitment.
    pub cm: CM::Commitment,
    /// [`CCCSInstance::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for CCCSInstance<CM> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar] {
        &mut self.x
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for CCCSInstance<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            cm: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for CCCSInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.cm.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}
