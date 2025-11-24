use ark_std::sync::Arc;
use sonobe_primitives::{
    arithmetizations::{ccs::CCSVariant, Arith},
    commitments::{CommitmentKey, GroupBasedVectorCommitment},
};

use crate::{
    hypernova::{HyperNova, HyperNova2},
    Error, FoldingSchemeKeyGenerator,
};

impl<VC: GroupBasedVectorCommitment, V: CCSVariant, const CHALLENGE_BITS: usize>
    FoldingSchemeKeyGenerator for HyperNova<VC, V, CHALLENGE_BITS>
{
    fn generate_keys(ck: Self::PublicParam, ccs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let ccs = Arc::new(ccs);
        if ck.max_scalars_len() < ccs.n_witnesses() {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the CCS instance".into(),
            ));
        }
        Ok(Self::DeciderKey { arith: ccs, ck })
    }
}

impl<VC: GroupBasedVectorCommitment, V: CCSVariant, const CHALLENGE_BITS: usize>
    FoldingSchemeKeyGenerator for HyperNova2<VC, V, CHALLENGE_BITS>
{
    fn generate_keys(ck: Self::PublicParam, ccs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let ccs = Arc::new(ccs);
        if ck.max_scalars_len() < ccs.n_witnesses() {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the CCS instance".into(),
            ));
        }
        Ok(Self::DeciderKey { arith: ccs, ck })
    }
}
