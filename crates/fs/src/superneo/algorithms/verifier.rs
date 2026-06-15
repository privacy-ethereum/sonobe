//! Proof verification for SuperNeo.

use std::marker::PhantomData;

use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::{borrow::Borrow, cfg_iter, log2, ops::Mul};
#[cfg(not(feature = "parallel"))]
use itertools::Itertools;
use num_bigint::BigUint;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{
        ops::{bits::FromBits, pow::Pow},
        ring::{PolynomialRingConfig, PolynomialRingOverField},
    },
    arithmetizations::{ArithConfig, ArithRelation, ccs::CCS},
    commitments::GroupBasedCommitment,
    sumcheck::{
        SumCheck,
        utils::{EqPoly, VPAuxInfo},
    },
    transcripts::Transcript,
};

use crate::{
    Error, FoldingSchemeVerifier,
    nova::AbstractNova,
    superneo::{
        SuperNeo, SuperNeoConfig,
        utils::{decompose, decompose2},
    },
};

impl<
    Cfg: SuperNeoConfig,
    A: CCS<Field = Cfg::F> + ArithRelation<Vec<Cfg::F>, Vec<Cfg::F>>,
    const N: usize,
> FoldingSchemeVerifier<1, N> for SuperNeo<Cfg, A>
{
    fn verify(
        vk: &ArithConfig,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<1, N>,
    ) -> Result<Self::RU, Error> {
        let U = Us[0].borrow();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let base = Cfg::B;

        let m = Cfg::F::MODULUS.into();
        let mut l = m.to_radix_le(base as u32).len();
        if BigUint::from(base).pow(l as u32 - 1) == m {
            l -= 1;
        }

        let cfg = vk;
        let s = log2(cfg.n_variables * l) as usize;
        let t = cfg.n_matrices + 1;
        let S = &A::multisets();
        let c = &A::coefficients();

        transcript.add(U);
        transcript.add(&us[..]);

        let alpha = transcript.challenge_many::<Cfg::K>(s);
        let gamma = transcript.challenge::<Cfg::K>();

        let gamma_powers = &gamma.powers(Cfg::M * t * Cfg::P::DEGREE + N + Cfg::M + N);

        let vp_aux_info = VPAuxInfo {
            num_variables: s,
            max_degree: cfg.degree.max(Cfg::B * 2 - 1) + 1,
        };

        let sum_v_j_gamma = (0..Cfg::M)
            .map(|i| {
                (0..t)
                    .map(|j| {
                        (0..Cfg::P::DEGREE)
                            .map(|k| {
                                gamma_powers[i * t * Cfg::P::DEGREE
                                    + j * Cfg::P::DEGREE
                                    + k
                                    + N
                                    + Cfg::M
                                    + N]
                                    * U.y[i][j].coeffs[k]
                            })
                            .sum::<Cfg::K>()
                    })
                    .sum::<Cfg::K>()
            })
            .sum::<Cfg::K>();

        let (claimed_eval, r_prime) =
            SumCheck::verify(sum_v_j_gamma, &proof.sc_proof, &vp_aux_info, transcript)?;

        let f = (0..N)
            .map(|i| {
                gamma_powers[i]
                    * S.iter()
                        .zip(c)
                        .map(|(s, c)| {
                            Cfg::K::from_base_prime_field(*c)
                                * s.iter()
                                    .map(|&j| proof.y_prime[i][j].coeffs[0])
                                    .product::<Cfg::K>()
                        })
                        .sum::<Cfg::K>()
            })
            .sum::<Cfg::K>();
        let n = (0..N + Cfg::M)
            .map(|i| {
                gamma_powers[i + N]
                    * (1 - Cfg::B as i8..Cfg::B as i8)
                        .map(|j| proof.y_prime[i][t - 1].coeffs[0] - Cfg::K::from(j))
                        .product::<Cfg::K>()
            })
            .sum::<Cfg::K>();
        let e = EqPoly::fix_xy_eval(&U.r, &r_prime)
            * (0..Cfg::M)
                .map(|i| {
                    (0..t)
                        .map(|j| {
                            (0..Cfg::P::DEGREE)
                                .map(|k| {
                                    gamma_powers[i * t * Cfg::P::DEGREE
                                        + j * Cfg::P::DEGREE
                                        + k
                                        + N
                                        + Cfg::M
                                        + N]
                                        * proof.y_prime[N + i][j].coeffs[k]
                                })
                                .sum::<Cfg::K>()
                        })
                        .sum::<Cfg::K>()
                })
                .sum::<Cfg::K>();
        assert_eq!(
            claimed_eval,
            EqPoly::fix_xy_eval(&r_prime, &alpha) * (f + n) + e
        );

        let rhos = PolynomialRingOverField::<Cfg::P, _>::vector_embedding(
            transcript
                .get_decomposed(
                    Cfg::CHALLENGE_COEFF_RANGE.len() as u8,
                    Cfg::P::DEGREE * (Cfg::M + N),
                )
                .into_iter()
                .map(|i| Cfg::F::from(i as i8 + Cfg::CHALLENGE_COEFF_RANGE.start))
                .collect(),
        );

        let mut c = vec![PolynomialRingOverField::default(); Cfg::KAPPA];
        for (c_i, rho) in us.iter().map(|i| &i.c).chain(&U.c).zip(&rhos) {
            for i in 0..c.len() {
                c[i] = c[i].add(&c_i[i].mul(rho));
            }
        }

        for i in 0..Cfg::M {
            let b = Cfg::F::from(BigUint::from(Cfg::B).pow(i as u32));
            for j in 0..Cfg::KAPPA {
                c[j] = c[j].sub(&proof.c_prime[i][j].scale(b));
            }
        }
        for i in 0..Cfg::KAPPA {
            for j in 0..Cfg::P::DEGREE {
                assert!(c[i].coeffs[j].is_zero());
            }
        }

        let mut y = vec![PolynomialRingOverField::default(); t];
        for j in 0..t {
            for i in 0..Cfg::M + N {
                y[j] = y[j].add(&proof.y_prime[i][j].mul(&{
                    PolynomialRingOverField {
                        _t: PhantomData,
                        coeffs: rhos[i]
                            .coeffs
                            .iter()
                            .map(|i| Cfg::K::from_base_prime_field(*i))
                            .collect(),
                    }
                }))
            }
        }
        for i in 0..Cfg::M {
            let b =
                Cfg::K::from_base_prime_field(Cfg::F::from(BigUint::from(Cfg::B).pow(i as u32)));
            for j in 0..t {
                y[j] = y[j].sub(&proof.y[i][j].scale(b));
            }
        }
        for i in 0..t {
            for j in 0..Cfg::P::DEGREE {
                assert!(y[i].coeffs[j].is_zero());
            }
        }

        let decomposed_uxs = us
            .iter()
            .map(|u| {
                [One::one()]
                    .iter()
                    .chain(&u.x)
                    .flat_map(|i| decompose::<Cfg::F>(*i, Cfg::B))
                    .collect()
            })
            .chain(U.x.iter().zip(&U.u).map(|(x, u)| [&u[..], x].concat()))
            .collect::<Vec<_>>();
        let embedded_uxs = decomposed_uxs
            .into_iter()
            .map(|z| {
                PolynomialRingOverField::vector_embedding(
                    z.iter().map(|i| Cfg::F::from(*i)).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        let mut ux = vec![PolynomialRingOverField::default(); embedded_uxs[0].len()];
        for (embedded_z, rho) in embedded_uxs.into_iter().zip(&rhos) {
            for i in 0..ux.len() {
                ux[i] = ux[i].add(&embedded_z[i].mul(rho));
            }
        }
        let ux = PolynomialRingOverField::vector_unembedding(ux);

        assert_eq!(ux.len(), (cfg.n_public_inputs + 1) * l);

        let mut us = vec![vec![]; Cfg::M];
        let mut xs = vec![vec![]; Cfg::M];
        for i in 0..ux.len() {
            let d = decompose2(ux[i], Cfg::B, Cfg::M);
            for j in 0..Cfg::M {
                if i < l {
                    us[j].push(d[j]);
                } else {
                    xs[j].push(d[j]);
                }
            }
        }

        Ok(Self::RU {
            u: us,
            x: xs,
            c: proof.c_prime.clone(),
            r: r_prime,
            y: proof.y.to_vec(),
        })
    }
}
