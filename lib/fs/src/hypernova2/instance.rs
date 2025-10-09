use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

use sonobe_primitives::{
    commitments::VectorCommitment, relations::Referenceable, traits::AbsorbNonNative,
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

pub type CCCS<VC> = Vec<<VC as VectorCommitment>::Scalar>;

impl<VC: VectorCommitment> Referenceable for LCCCS<VC> {
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

impl<VC: VectorCommitment<Scalar: Absorb, Commitment: AbsorbNonNative>> Absorb
    for LCCCS<VC>
{
    fn to_sponge_bytes(&self, _dest: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.cm.to_native_sponge_field_elements(dest);
        self.u.to_sponge_field_elements(dest);
        self.x.to_sponge_field_elements(dest);
        self.r_x.to_sponge_field_elements(dest);
        self.v.to_sponge_field_elements(dest);
    }
}
