use sonobe_primitives::commitments::VectorCommitment;

use crate::FoldingWitness;

pub mod circuits;

#[derive(Debug, PartialEq)]
pub struct LCCCSWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

#[derive(Debug, PartialEq)]
pub struct CCCSWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

impl<VC: VectorCommitment> FoldingWitness<VC> for LCCCSWitness<VC> {
    fn openings_ref(
        &self,
    ) -> Vec<(
        &[<VC as VectorCommitment>::Scalar],
        &<VC as VectorCommitment>::Randomness,
    )> {
        vec![(&self.w, &self.r)]
    }
}

impl<VC: VectorCommitment> FoldingWitness<VC> for CCCSWitness<VC> {
    fn openings_ref(
        &self,
    ) -> Vec<(
        &[<VC as VectorCommitment>::Scalar],
        &<VC as VectorCommitment>::Randomness,
    )> {
        vec![(&self.w, &self.r)]
    }
}
