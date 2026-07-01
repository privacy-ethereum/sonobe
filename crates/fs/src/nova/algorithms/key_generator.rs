//! Key generation for Nova.

use ark_std::sync::Arc;
use sonobe_primitives::{
    algebra::field::SonobeField,
    arithmetizations::Arith,
    commitments::{CommitmentKey, GroupBasedCommitment},
};

use crate::{Error, FoldingSchemeKeyGenerator, nova::AbstractNova};

impl<CM: GroupBasedCommitment, TF: SonobeField, const B: usize> FoldingSchemeKeyGenerator
    for AbstractNova<CM, TF, B>
{
    fn generate_keys(ck: Self::PublicParam, r1cs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let r1cs = Arc::new(r1cs);
        let cfg = r1cs.config();
        if ck.max_scalars_len() < cfg.n_constraints.max(cfg.n_witnesses) {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the R1CS instance".into(),
            ));
        }
        Ok(Self::DeciderKey { arith: r1cs, ck })
    }
}
