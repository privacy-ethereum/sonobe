use ark_std::sync::Arc;
use sonobe_primitives::{
    arithmetizations::Arith,
    commitments::{CommitmentKey, GroupBasedVectorCommitment},
};

use crate::{
    mova::{Mova, MovaKey},
    Error, FoldingSchemeKeyGenerator,
};

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemeKeyGenerator
    for Mova<VC, CHALLENGE_BITS>
{
    fn generate_keys(ck: Self::PublicParam, r1cs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let r1cs = Arc::new(r1cs);
        if ck.max_scalars_len() < r1cs.n_witnesses() {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the R1CS instance".into(),
            ));
        }
        Ok(MovaKey { arith: r1cs, ck })
    }
}
