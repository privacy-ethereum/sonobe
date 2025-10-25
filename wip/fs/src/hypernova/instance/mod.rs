use ark_ff::PrimeField;
use sonobe_primitives::{commitments::VectorCommitment, transcripts::Absorbable};

use crate::FoldingInstance;

pub mod circuits;

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub struct CCCSInstance<VC: VectorCommitment> {
    pub cm: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> FoldingInstance<VC> for CCCSInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
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
