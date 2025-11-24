use ark_std::rand::RngCore;
use sonobe_primitives::commitments::GroupBasedVectorCommitment;

use crate::{
    protogalaxy::{ProtoGalaxy, ProtoGalaxy2},
    Error, FoldingSchemePreprocessor,
};

impl<VC: GroupBasedVectorCommitment> FoldingSchemePreprocessor for ProtoGalaxy<VC> {
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}

impl<VC: GroupBasedVectorCommitment> FoldingSchemePreprocessor for ProtoGalaxy2<VC> {
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}
