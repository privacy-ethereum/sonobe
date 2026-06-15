//! Preprocessing for SuperNeo.

use ark_std::rand::RngCore;
use sonobe_primitives::{
    algebra::{
        field::SonobeField,
        ring::{PolynomialRingConfig, PolynomialRingOverField},
    },
    arithmetizations::{ArithRelation, ccs::CCS},
    commitments::{CommitmentOps, GroupBasedCommitment},
    traits::SonobePrimeField,
    utils::null::Null,
};

use crate::{
    Error, FoldingSchemePreprocessor,
    superneo::{SuperNeo, SuperNeoConfig},
};

impl<Cfg: SuperNeoConfig, A: CCS<Field = Cfg::F> + ArithRelation<Vec<Cfg::F>, Vec<Cfg::F>>>
    FoldingSchemePreprocessor for SuperNeo<Cfg, A>
{
    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = Cfg::CM::generate_key(ck_len, &mut rng)?;
        Ok(ck)
    }
}
