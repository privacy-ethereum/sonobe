//! Definitions of out-of-circuit values and in-circuit variables for ProtoGalaxy
//! instances.

use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::CommitmentDef, traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

/// [`RunningInstance`] defines ProtoGalaxy's running instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningInstance<CM: CommitmentDef> {
    /// [`RunningInstance::phi`] is the witness commitment.
    pub phi: CM::Commitment,
    /// [`RunningInstance::betas`] is the vector of randomness.
    pub betas: Vec<CM::Scalar>,
    /// [`RunningInstance::e`] is the error term.
    pub e: CM::Scalar,
    /// [`RunningInstance::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for RunningInstance<CM> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![&self.phi]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar] {
        &mut self.x
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for RunningInstance<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            phi: Default::default(),
            betas: vec![Default::default(); cfg.log_constraints()],
            e: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for RunningInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.phi.absorb_into(dest);
        self.betas.absorb_into(dest);
        self.e.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}

/// [`IncomingInstance`] defines ProtoGalaxy's incoming instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingInstance<CM: CommitmentDef> {
    /// [`IncomingInstance::phi`] is the witness commitment.
    pub phi: CM::Commitment,
    /// [`IncomingInstance::x`] is the vector of public inputs (to the circuit).
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for IncomingInstance<CM> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![&self.phi]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar] {
        &mut self.x
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for IncomingInstance<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            phi: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for IncomingInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.phi.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}
