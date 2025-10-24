use crate::{FoldingWitness, FoldingWitnessVar};
use sonobe_primitives::commitments::VectorCommitmentGadget;
use sonobe_primitives::{commitments::VectorCommitment, };

#[derive(Debug, PartialEq)]
pub struct RunningWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
}

#[derive(Debug, PartialEq)]
pub struct RunningWitnessVar<VC: VectorCommitmentGadget> {
    pub w: Vec<VC::ScalarVar>,
    pub r: VC::RandomnessVar,
}

pub type IncomingWitness<VC> = Vec<<VC as VectorCommitment>::Scalar>;

pub type IncomingWitnessVar<VC> = Vec<<VC as VectorCommitmentGadget>::ScalarVar>;

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

impl<VC: VectorCommitmentGadget> FoldingWitnessVar<VC> for RunningWitnessVar<VC> {
    type Native = RunningWitness<VC::Native>;
}
