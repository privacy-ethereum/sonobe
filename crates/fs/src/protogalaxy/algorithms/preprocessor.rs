//! Preprocessing for ProtoGalaxy.

use ark_std::rand::RngCore;
use sonobe_primitives::commitments::GroupBasedCommitment;

use crate::{
    Error, FoldingSchemePreprocessor,
    protogalaxy::{ProtoGalaxy, ProtoGalaxy2},
};

impl<CM: GroupBasedCommitment> FoldingSchemePreprocessor for ProtoGalaxy<CM> {
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = CM::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}

impl<CM: GroupBasedCommitment> FoldingSchemePreprocessor for ProtoGalaxy2<CM> {
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = CM::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}
