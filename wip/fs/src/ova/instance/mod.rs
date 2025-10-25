use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_std::borrow::Borrow;

use sonobe_primitives::commitments::VectorCommitmentGadget;
use sonobe_primitives::transcripts::AbsorbableGadget;
use sonobe_primitives::{commitments::VectorCommitment, transcripts::Absorbable};

use crate::{FoldingInstance, FoldingInstanceVar};

pub mod circuits;

#[derive(Debug, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    pub u: VC::Scalar,
    pub cm: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
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
