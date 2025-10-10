use sonobe_primitives::{commitments::VectorCommitment, relations::Referenceable};

use crate::FoldingWitness;

#[derive(Debug, PartialEq)]
pub struct RunningWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

pub type IncomingWitness<VC> = Vec<<VC as VectorCommitment>::Scalar>;

impl<VC: VectorCommitment> Referenceable for RunningWitness<VC> {
    type Ref<'a> = &'a Self;

    fn reference(&self) -> Self::Ref<'_> {
        self
    }
}

impl<VC: VectorCommitment> FoldingWitness<VC> for RunningWitness<VC> {
    fn openings_ref(
        &self,
    ) -> Vec<(
        &[<VC as VectorCommitment>::Scalar],
        &<VC as VectorCommitment>::Randomness,
    )> {
        vec![(&self.w, &self.r)]
    }
}
