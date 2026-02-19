//! Preprocessing for HyperNova.

use ark_std::rand::RngCore;
use sonobe_primitives::{arithmetizations::ccs::CCSVariant, commitments::GroupBasedCommitment};

use crate::{
    Error, FoldingSchemePreprocessor,
    hypernova::{HyperNova, HyperNova2},
};

impl<CM: GroupBasedCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemePreprocessor
    for HyperNova<CM, V, CHALLENGE_BITS>
{
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = CM::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}

impl<CM: GroupBasedCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemePreprocessor
    for HyperNova2<CM, V, CHALLENGE_BITS>
{
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = CM::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}
