use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    arithmetizations::ArithConfig,
    commitments::{VectorCommitment, VectorCommitmentGadget},
    traits::Dummy,
    transcripts::{Absorbable, AbsorbableGadget},
};

use crate::{FoldingInstance, FoldingInstanceVar};

pub mod circuits;

#[derive(Clone, Debug, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    pub u: VC::Scalar,
    pub cm: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
    }

    fn public_inputs(&self) -> &[<VC as VectorCommitment>::Scalar] {
        &self.x
    }
}

impl<VC: VectorCommitment, Cfg: ArithConfig> Dummy<&Cfg> for RunningInstance<VC> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            u: Default::default(),
            cm: Default::default(),
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
        self.cm.absorb_into(dest);
    }
}
