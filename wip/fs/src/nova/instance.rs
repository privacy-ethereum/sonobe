use ark_ff::PrimeField;

use sonobe_primitives::{
    commitments::VectorCommitment, relations::Referenceable, traits::Absorbable,
};

use crate::FoldingInstance;

#[derive(Debug, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    pub cm_e: VC::Commitment,
    pub u: VC::Scalar,
    pub cm_w: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

#[derive(Debug, PartialEq)]
pub struct IncomingInstance<VC: VectorCommitment> {
    pub cm_w: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> Referenceable for RunningInstance<VC> {
    type Ref<'a> = &'a Self;

    fn reference(&self) -> Self::Ref<'_> {
        self
    }
}

impl<VC: VectorCommitment> Referenceable for IncomingInstance<VC> {
    type Ref<'a> = &'a Self;

    fn reference(&self) -> Self::Ref<'_> {
        self
    }
}

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm_e, &self.cm_w]
    }
}

impl<VC: VectorCommitment> FoldingInstance<VC> for IncomingInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm_w]
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

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for IncomingInstance<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.x.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}
