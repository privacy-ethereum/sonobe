use ark_std::rand::RngCore;
use sonobe_primitives::commitments::GroupBasedVectorCommitment;

use crate::{mova::Mova, Error, FoldingSchemePreprocessor};

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemePreprocessor
    for Mova<VC, CHALLENGE_BITS>
{
    fn preprocess(n_witnesses: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(n_witnesses, &mut rng)?;
        Ok(ck)
    }
}
