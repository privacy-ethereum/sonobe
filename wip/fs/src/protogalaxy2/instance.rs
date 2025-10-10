use ark_ff::PrimeField;

use sonobe_primitives::{
    commitments::VectorCommitment, relations::Referenceable, traits::Absorbable,
};

use crate::FoldingInstance;

#[derive(Debug, PartialEq)]
pub struct RunningInstance<VC: VectorCommitment> {
    pub phi: VC::Commitment,
    pub betas: Vec<VC::Scalar>,
    pub e: VC::Scalar,
    pub x: Vec<VC::Scalar>,
}

pub type IncomingInstance<VC> = Vec<<VC as VectorCommitment>::Scalar>;

impl<VC: VectorCommitment> Referenceable for RunningInstance<VC> {
    type Ref<'a> = &'a Self;

    fn reference(&self) -> Self::Ref<'_> {
        self
    }
}

impl<VC: VectorCommitment> FoldingInstance<VC> for RunningInstance<VC> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![&self.phi]
    }
}

impl<F: PrimeField, VC: VectorCommitment<Scalar: Absorbable<F>, Commitment: Absorbable<F>>>
    Absorbable<F> for RunningInstance<VC>
{
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.phi.absorb_into(dest);
        self.betas.absorb_into(dest);
        self.e.absorb_into(dest);
        self.x.absorb_into(dest);
    }
}
