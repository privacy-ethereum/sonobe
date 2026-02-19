//! Preprocessing for Mova.

use ark_std::rand::RngCore;
use sonobe_primitives::commitments::GroupBasedCommitment;

use crate::{Error, FoldingSchemePreprocessor, mova::Mova};

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemePreprocessor
    for Mova<CM, CHALLENGE_BITS>
{
    fn preprocess(n_witnesses: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = CM::generate_key(n_witnesses, &mut rng)?;
        Ok(ck)
    }
}
