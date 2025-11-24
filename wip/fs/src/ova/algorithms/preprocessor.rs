use ark_std::rand::RngCore;
use sonobe_primitives::{commitments::GroupBasedVectorCommitment, traits::SonobeField};

use crate::{
    ova::AbstractOva,
    Error, FoldingSchemePreprocessor,
};

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemePreprocessor for AbstractOva<VC, TF, CHALLENGE_BITS>
{
    fn preprocess(
        (n_constraints, n_witnesses): (usize, usize),
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(n_constraints + n_witnesses, &mut rng)?;
        Ok(ck)
    }
}
