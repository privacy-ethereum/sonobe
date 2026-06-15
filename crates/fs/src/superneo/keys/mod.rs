//! Definitions of SuperNeo keys and trait implementations for relation checks and
//! witness-instance sampling using SuperNeo keys.

use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, array, cfg_iter, log2, marker::PhantomData, rand::RngCore, sync::Arc};
use num_bigint::BigUint;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{
        field::SonobeField,
        ring::{PolynomialRingConfig, PolynomialRingOverField},
    },
    arithmetizations::{
        Arith, ArithConfig, ArithRelation, Error as ArithError,
        ccs::CCS,
        r1cs::{RelaxedInstance, RelaxedWitness},
    },
    circuits::{Assignments, AssignmentsOwned},
    commitments::{CommitmentDef, CommitmentOps},
    relations::{Relation, WitnessInstanceSampler},
    traits::SonobePrimeField,
    utils::null::Null,
};

use super::{
    instances::{IncomingInstance as IU, RunningInstance as RU},
    witnesses::{IncomingWitness as IW, RunningWitness as RW},
};
use crate::{
    DeciderKey, Error, PlainInstance as PU, PlainWitness as PW,
    superneo::{SuperNeoConfig, utils::decompose},
};

/// [`SuperNeoKey`] is SuperNeo's decider key.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SuperNeoKey<A: Arith, Cfg: SuperNeoConfig> {
    pub(super) arith: Arc<A>,
    pub(super) transformed_matrices:
        Arc<Vec<Vec<Vec<(Vec<PolynomialRingOverField<Cfg::P, Cfg::F>>, usize)>>>>,
    pub(super) ck: Arc<<Cfg::CM as CommitmentDef>::Key>,
}

impl<A: Arith, Cfg: SuperNeoConfig> DeciderKey for SuperNeoKey<A, Cfg> {
    type ProverKey = Self;
    type VerifierKey = ArithConfig;

    fn to_pk(&self) -> Self::ProverKey {
        self.clone()
    }

    fn to_vk(&self) -> Self::VerifierKey {
        self.arith.config()
    }

    fn to_arith_config(&self) -> ArithConfig {
        self.arith.config()
    }
}

impl<A: CCS<Field = Cfg::F>, Cfg: SuperNeoConfig> Relation<RW<Cfg>, RU<Cfg>>
    for SuperNeoKey<A, Cfg>
{
    type Error = Error;

    fn check_relation(&self, W: &RW<Cfg>, U: &RU<Cfg>) -> Result<(), Self::Error> {
        let cfg = self.arith.config();
        let base = Cfg::B;

        let m = Cfg::F::MODULUS.into();
        let mut l = m.to_radix_le(base as u32).len();
        if BigUint::from(base).pow(l as u32 - 1) == m {
            l -= 1;
        }

        let s = log2(cfg.n_variables * l) as usize;

        let ys = cfg_iter!(W.w)
            .zip(&U.x)
            .zip(&U.u)
            .map(|((w, x), u)| {
                let embedded_z = &PolynomialRingOverField::<Cfg::P, Cfg::F>::vector_embedding(
                    u.iter()
                        .chain(x)
                        .chain(w)
                        .map(|i| Cfg::F::from(*i))
                        .collect(),
                );
                self.transformed_matrices
                    .iter()
                    .map(move |matrix| {
                        matrix
                            .iter()
                            .map(|i| {
                                let mut r = PolynomialRingOverField::<Cfg::P, Cfg::F>::default();
                                for (j, offset) in i {
                                    j.iter().enumerate().for_each(|(i, v)| {
                                        r = r.add(&v.mul(&embedded_z[offset + i]));
                                    });
                                }
                                r
                            })
                            .collect::<Vec<_>>()
                    })
                    .map(|j| {
                        let mut poly = j
                            .into_iter()
                            .map(|k| PolynomialRingOverField::<Cfg::P, _> {
                                _t: PhantomData,
                                coeffs: k
                                    .coeffs
                                    .into_iter()
                                    .map(Cfg::K::from_base_prime_field)
                                    .collect(),
                            })
                            .collect::<Vec<_>>();
                        poly.resize(1 << s, Default::default());
                        let nv = s;
                        let dim = U.r.len();
                        // evaluate single variable of partial point from left to right
                        for i in 1..dim + 1 {
                            let r = U.r[i - 1];
                            for b in 0..(1 << (nv - i)) {
                                let left = &poly.get(b << 1).cloned().unwrap_or_default();
                                let right = &poly.get((b << 1) + 1).cloned().unwrap_or_default();
                                poly[b] = left.add(&right.sub(&left).scale(r));
                            }
                        }
                        poly.remove(0)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for i in 0..Cfg::M {
            for j in 0..cfg.n_matrices + 1 {
                assert_eq!(U.y[i][j], ys[i][j]);
            }
        }

        for i in 0..Cfg::M {
            Cfg::CM::open(
                &self.ck,
                &PolynomialRingOverField::vector_embedding(
                    W.w[i].iter().map(|i| Cfg::F::from(*i)).collect(),
                ),
                &Null,
                &U.c[i],
            )?;
        }

        Ok(())
    }
}

impl<A, Cfg: SuperNeoConfig>
    Relation<IW<Cfg::F>, IU<<Cfg::CM as CommitmentDef>::Commitment, Cfg::F>> for SuperNeoKey<A, Cfg>
where
    A: ArithRelation<Vec<Cfg::F>, Vec<Cfg::F>>,
{
    type Error = Error;

    fn check_relation(
        &self,
        w: &IW<Cfg::F>,
        u: &IU<<Cfg::CM as CommitmentDef>::Commitment, Cfg::F>,
    ) -> Result<(), Self::Error> {
        self.arith.check_relation(&w.w, &u.x)?;
        Cfg::CM::open(
            &self.ck,
            &PolynomialRingOverField::vector_embedding(
                w.w.iter()
                    .flat_map(|i| {
                        decompose::<Cfg::F>(*i, Cfg::B)
                            .into_iter()
                            .map(Cfg::F::from)
                            .collect::<Vec<_>>()
                    })
                    .collect(),
            ),
            &Null,
            &u.c,
        )?;
        Ok(())
    }
}

impl<A: Arith, Cfg: SuperNeoConfig>
    WitnessInstanceSampler<IW<Cfg::F>, IU<<Cfg::CM as CommitmentDef>::Commitment, Cfg::F>>
    for SuperNeoKey<A, Cfg>
{
    type Source = AssignmentsOwned<Cfg::F>;
    type Error = Error;

    fn sample(
        &self,
        z: Self::Source,
        rng: impl RngCore,
    ) -> Result<
        (
            IW<Cfg::F>,
            IU<<Cfg::CM as CommitmentDef>::Commitment, Cfg::F>,
        ),
        Error,
    > {
        let (w, x) = (z.private, z.public);
        let (c, _) = Cfg::CM::commit(
            &self.ck,
            &PolynomialRingOverField::vector_embedding(
                w.iter()
                    .flat_map(|i| {
                        decompose::<Cfg::F>(*i, Cfg::B)
                            .into_iter()
                            .map(Cfg::F::from)
                            .collect::<Vec<_>>()
                    })
                    .collect(),
            ),
            rng,
        )?;
        Ok((IW { w }, IU { c, x }))
    }
}

impl<A: CCS<Field = Cfg::F>, Cfg: SuperNeoConfig> WitnessInstanceSampler<RW<Cfg>, RU<Cfg>>
    for SuperNeoKey<A, Cfg>
{
    type Source = ();
    type Error = Error;

    #[allow(non_snake_case)]
    fn sample(&self, _: Self::Source, mut rng: impl RngCore) -> Result<(RW<Cfg>, RU<Cfg>), Error> {
        let cfg = self.arith.config();
        let base = Cfg::B;

        let m = Cfg::F::MODULUS.into();
        let mut l = m.to_radix_le(base as u32).len();
        if BigUint::from(base).pow(l as u32 - 1) == m {
            l -= 1;
        }

        let s = log2(cfg.n_variables * l) as usize;

        let u = (0..Cfg::M)
            .map(|_| decompose(Cfg::F::rand(&mut rng), Cfg::B))
            .collect::<Vec<_>>();
        let x = (0..Cfg::M)
            .map(|_| {
                (0..cfg.n_public_inputs)
                    .flat_map(|_| decompose(Cfg::F::rand(&mut rng), Cfg::B))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let w = (0..Cfg::M)
            .map(|_| {
                (0..cfg.n_witnesses)
                    .flat_map(|_| decompose(Cfg::F::rand(&mut rng), Cfg::B))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let c = w
            .iter()
            .map(|w| {
                Cfg::CM::commit(
                    &self.ck,
                    &PolynomialRingOverField::vector_embedding(
                        w.iter().map(|i| Cfg::F::from(*i)).collect::<Vec<_>>(),
                    ),
                    &mut rng,
                )
                .map(|(c, r)| c)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let r = (0..s).map(|_| Cfg::K::rand(&mut rng)).collect::<Vec<_>>();

        let ys = cfg_iter!(w)
            .zip(&x)
            .zip(&u)
            .map(|((w, x), u)| {
                let embedded_z = &PolynomialRingOverField::<Cfg::P, Cfg::F>::vector_embedding(
                    u.iter()
                        .chain(x)
                        .chain(w)
                        .map(|i| Cfg::F::from(*i))
                        .collect(),
                );
                self.transformed_matrices
                    .iter()
                    .map(move |matrix| {
                        matrix
                            .iter()
                            .map(|i| {
                                let mut r = PolynomialRingOverField::<Cfg::P, Cfg::F>::default();
                                for (j, offset) in i {
                                    j.iter().enumerate().for_each(|(i, v)| {
                                        r = r.add(&v.mul(&embedded_z[offset + i]));
                                    });
                                }
                                r
                            })
                            .collect::<Vec<_>>()
                    })
                    .map(|j| {
                        let mut poly = j
                            .into_iter()
                            .map(|k| PolynomialRingOverField::<Cfg::P, _> {
                                _t: PhantomData,
                                coeffs: k
                                    .coeffs
                                    .into_iter()
                                    .map(Cfg::K::from_base_prime_field)
                                    .collect(),
                            })
                            .collect::<Vec<_>>();
                        poly.resize(1 << s, Default::default());
                        let nv = s;
                        let dim = r.len();
                        // evaluate single variable of partial point from left to right
                        for i in 1..dim + 1 {
                            let r = r[i - 1];
                            for b in 0..(1 << (nv - i)) {
                                let left = &poly.get(b << 1).cloned().unwrap_or_default();
                                let right = &poly.get((b << 1) + 1).cloned().unwrap_or_default();
                                poly[b] = left.add(&right.sub(&left).scale(r));
                            }
                        }
                        poly.remove(0)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let W = RW { _t: PhantomData, w };
        let U = RU {
            c: c.try_into().unwrap(),
            u,
            x,
            r,
            y: ys,
        };

        Ok((W, U))
    }
}
