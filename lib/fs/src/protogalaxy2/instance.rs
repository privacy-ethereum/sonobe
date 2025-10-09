use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

use sonobe_primitives::{
    commitments::VectorCommitment, relations::Referenceable, traits::AbsorbNonNative,
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

impl<VC: VectorCommitment<Scalar: Absorb, Commitment: AbsorbNonNative>> Absorb
    for RunningInstance<VC>
{
    fn to_sponge_bytes(&self, _dest: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.phi.to_native_sponge_field_elements(dest);
        self.betas.to_sponge_field_elements(dest);
        self.e.to_sponge_field_elements(dest);
        self.x.to_sponge_field_elements(dest);
    }
}
