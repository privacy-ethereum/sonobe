//! Preprocessing for Nova.

use ark_std::rand::RngCore;
use sonobe_primitives::{commitments::GroupBasedCommitment, traits::SonobePrimeField};

use crate::{Error, FoldingSchemePreprocessor, nova::AbstractNova};

impl<CM: GroupBasedCommitment, TF: SonobePrimeField, const B: usize> FoldingSchemePreprocessor
    for AbstractNova<CM, TF, B>
{
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = CM::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}
