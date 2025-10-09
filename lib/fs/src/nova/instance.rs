use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

use sonobe_primitives::{
    commitments::VectorCommitment, relations::Referenceable, traits::AbsorbNonNative,
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

impl<VC: VectorCommitment<Scalar: Absorb, Commitment: AbsorbNonNative>> Absorb
    for RunningInstance<VC>
{
    fn to_sponge_bytes(&self, _dest: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.u.to_sponge_field_elements(dest);
        self.x.to_sponge_field_elements(dest);
        self.cm_e.to_native_sponge_field_elements(dest);
        self.cm_w.to_native_sponge_field_elements(dest);
    }
}

impl<VC: VectorCommitment<Scalar: Absorb, Commitment: AbsorbNonNative>> Absorb
    for IncomingInstance<VC>
{
    fn to_sponge_bytes(&self, _dest: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.x.to_sponge_field_elements(dest);
        self.cm_w.to_native_sponge_field_elements(dest);
    }
}
