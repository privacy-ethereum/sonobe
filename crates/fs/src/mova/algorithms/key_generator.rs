//! Key generation for Mova.

use ark_std::sync::Arc;
use sonobe_primitives::{
    arithmetizations::{Arith, ArithConfig},
    commitments::{CommitmentKey, GroupBasedCommitment},
};

use crate::{
    Error, FoldingSchemeKeyGenerator,
    mova::{Mova, MovaKey},
};

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeKeyGenerator
    for Mova<CM, CHALLENGE_BITS>
{
    fn generate_keys(ck: Self::PublicParam, r1cs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let r1cs = Arc::new(r1cs);
        if ck.max_scalars_len() < r1cs.config().n_witnesses() {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the R1CS instance".into(),
            ));
        }
        Ok(MovaKey { arith: r1cs, ck })
    }
}
