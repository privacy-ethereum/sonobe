use ark_std::rand::RngCore;
use sonobe_primitives::{commitments::GroupBasedVectorCommitment, traits::SonobeField};

use crate::{
    nova::{AbstractNova, AbstractNova2},
    Error, FoldingSchemePreprocessor,
};

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemePreprocessor for AbstractNova<VC, TF, CHALLENGE_BITS>
{
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemePreprocessor for AbstractNova2<VC, TF, CHALLENGE_BITS>
{
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}
