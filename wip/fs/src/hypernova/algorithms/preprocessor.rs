use ark_std::rand::RngCore;
use sonobe_primitives::{
    arithmetizations::ccs::CCSVariant, commitments::GroupBasedVectorCommitment,
};

use crate::{
    hypernova::{HyperNova, HyperNova2},
    Error, FoldingSchemePreprocessor,
};

impl<VC: GroupBasedVectorCommitment, V: CCSVariant, const CHALLENGE_BITS: usize>
    FoldingSchemePreprocessor for HyperNova<VC, V, CHALLENGE_BITS>
{
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}

impl<VC: GroupBasedVectorCommitment, V: CCSVariant, const CHALLENGE_BITS: usize>
    FoldingSchemePreprocessor for HyperNova2<VC, V, CHALLENGE_BITS>
{
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}
