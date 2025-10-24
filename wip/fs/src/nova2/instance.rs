use ark_ff::PrimeField;

use sonobe_primitives::{
    commitments::VectorCommitment, transcripts::Absorbable,
};

use crate::FoldingInstance;

#[derive(Debug, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    pub cm_e: VC::Commitment,
    pub u: VC::Scalar,
    pub cm_w: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

pub type IncomingInstance<VC> = Vec<<VC as VectorCommitment>::Scalar>;

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm_e, &self.cm_w]
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
