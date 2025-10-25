pub mod circuits;

use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::{VectorCommitment, VectorCommitmentGadget};

use crate::{FoldingWitness, FoldingWitnessVar};

#[derive(Debug, PartialEq)]
pub struct RunningWitness<VC: VectorCommitment> {
    pub w: Vec<VC::Scalar>,
    pub r: VC::Randomness,
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
