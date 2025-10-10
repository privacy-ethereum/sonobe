use ark_ff::PrimeField;

use sonobe_primitives::{
    commitments::VectorCommitment, relations::Referenceable, traits::Absorbable,
};

use crate::FoldingInstance;

#[derive(Debug, PartialEq)]
pub struct LCCCS<VC: VectorCommitment> {
    pub cm: VC::Commitment,
    pub u: VC::Scalar,
    pub x: Vec<VC::Scalar>,
    pub r_x: Vec<VC::Scalar>,
    pub v: Vec<VC::Scalar>,
}

#[derive(Debug, PartialEq)]
pub struct CCCS<VC: VectorCommitment> {
    pub cm: VC::Commitment,
    pub x: Vec<VC::Scalar>,
}

impl<VC: VectorCommitment> Referenceable for LCCCS<VC> {
    type Ref<'a> = &'a Self;

    fn reference(&self) -> Self::Ref<'_> {
        self
    }
}

impl<VC: VectorCommitment> Referenceable for CCCS<VC> {
    type Ref<'a> = &'a Self;

    fn reference(&self) -> Self::Ref<'_> {
        self
    }
}

impl<VC: VectorCommitment> FoldingInstance<VC> for LCCCS<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
    }
}

impl<VC: VectorCommitment> FoldingInstance<VC> for CCCS<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.cm]
    }
}

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for LCCCS<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.cm.absorb_into(dest);
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.r_x.absorb_into(dest);
        self.v.absorb_into(dest);
    }
}

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for CCCS<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.cm.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}
