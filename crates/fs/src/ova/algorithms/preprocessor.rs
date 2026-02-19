//! Preprocessing for Ova.

use ark_std::rand::RngCore;
use sonobe_primitives::{commitments::GroupBasedCommitment, traits::SonobeField};

use crate::{Error, FoldingSchemePreprocessor, ova::AbstractOva};

impl<CM: GroupBasedCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemePreprocessor for AbstractOva<CM, TF, CHALLENGE_BITS>
{
    fn preprocess(
        (n_constraints, n_witnesses): (usize, usize),
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, Error> {
        let ck = CM::generate_key(n_constraints + n_witnesses, &mut rng)?;
        Ok(ck)
    }
}
