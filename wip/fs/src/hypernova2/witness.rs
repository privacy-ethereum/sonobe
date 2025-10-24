use sonobe_primitives::{commitments::VectorCommitment, };

use crate::FoldingWitness;

#[derive(Debug, PartialEq)]
pub struct RunningWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

pub type IncomingWitness<VC> = Vec<<VC as VectorCommitment>::Scalar>;

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
