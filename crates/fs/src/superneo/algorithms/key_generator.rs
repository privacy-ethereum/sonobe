//! Key generation for SuperNeo.

use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::{cfg_into_iter, cfg_iter, sync::Arc};
use num_bigint::BigUint;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{
        field::SonobeField,
        ring::{PolynomialRingConfig, PolynomialRingOverField},
    },
    arithmetizations::{Arith, ArithRelation, ccs::CCS},
    commitments::{CommitmentKey, CommitmentOps, GroupBasedCommitment},
    traits::SonobePrimeField,
    utils::null::Null,
};

use crate::{
    Error, FoldingSchemeKeyGenerator,
    superneo::{SuperNeo, SuperNeoConfig},
};

impl<Cfg: SuperNeoConfig, A: CCS<Field = Cfg::F> + ArithRelation<Vec<Cfg::F>, Vec<Cfg::F>>>
    FoldingSchemeKeyGenerator for SuperNeo<Cfg, A>
{
    fn generate_keys(ck: Self::PublicParam, ccs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let ccs = Arc::new(ccs);
        let cfg = ccs.config();
        if ck.max_scalars_len() < cfg.n_witnesses {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the CCS instance".into(),
            ));
        }

        let base = Cfg::B;

        let m = Cfg::F::MODULUS.into();
        let mut l = m.to_radix_le(base as u32).len();
        if BigUint::from(base).pow(l as u32 - 1) == m {
            l -= 1;
        }

        Ok(Self::DeciderKey {
            transformed_matrices: Arc::new(
                ccs.matrices()
                    .iter()
                    .map(move |matrix| {
                        cfg_iter!(matrix)
                            .map(|row| {
                                row.iter()
                                    .map(|(v, j)| {
                                        let start = j * l;
                                        let end = start + l;

                                        let min = start / Cfg::P::DEGREE * Cfg::P::DEGREE;
                                        let max = end.div_ceil(Cfg::P::DEGREE) * Cfg::P::DEGREE;
                                        let mut vec = vec![Cfg::F::zero(); max - min];
                                        for i in 0..l {
                                            vec[i + start % Cfg::P::DEGREE] =
                                                *v * Cfg::F::from(Cfg::B as u64).pow([i as u64]);
                                        }
                                        (PolynomialRingOverField::<Cfg::P, Cfg::F>::vector_transform(
                                            vec,
                                        ), start / Cfg::P::DEGREE)
                                    })
                                    .collect()
                            })
                            .collect()
                    })
                    .chain([
                        cfg_into_iter!(0..cfg.n_variables * l)
                            .map(|i| {
                                let mut chunk = vec![Cfg::F::zero(); Cfg::P::DEGREE];
                                chunk[i % Cfg::P::DEGREE] = Cfg::F::one();

                                vec![(vec![PolynomialRingOverField::<Cfg::P, Cfg::F>::element_transform(chunk)], i / Cfg::P::DEGREE)]
                            }).collect::<_>()
                    ])
                    .collect(),
            ),
            arith: ccs,
            ck,
        })
    }
}
