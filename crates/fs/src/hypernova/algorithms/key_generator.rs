//! Key generation for HyperNova.

use ark_std::sync::Arc;
use sonobe_primitives::{
    arithmetizations::{Arith, ArithConfig, ccs::CCSVariant},
    commitments::{CommitmentKey, GroupBasedCommitment},
};

use crate::{
    Error, FoldingSchemeKeyGenerator,
    hypernova::{HyperNova, HyperNova2},
};

impl<CM: GroupBasedCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemeKeyGenerator
    for HyperNova<CM, V, CHALLENGE_BITS>
{
    fn generate_keys(ck: Self::PublicParam, ccs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let ccs = Arc::new(ccs);
        if ck.max_scalars_len() < ccs.config().n_witnesses() {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the CCS instance".into(),
            ));
        }
        Ok(Self::DeciderKey { arith: ccs, ck })
    }
}

impl<CM: GroupBasedCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemeKeyGenerator
    for HyperNova2<CM, V, CHALLENGE_BITS>
{
    fn generate_keys(ck: Self::PublicParam, ccs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let ccs = Arc::new(ccs);
        if ck.max_scalars_len() < ccs.config().n_witnesses() {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the CCS instance".into(),
            ));
        }
        Ok(Self::DeciderKey { arith: ccs, ck })
    }
}
