//! Proof generation for SuperNeo.

use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_poly::{
    DenseMultilinearExtension as MLE, DenseUVPolynomial, MultilinearExtension, Polynomial,
    univariate::DensePolynomial,
};
use ark_std::{
    borrow::Borrow, cfg_into_iter, cfg_iter, log2, marker::PhantomData, ops::Mul, rand::RngCore,
};
#[cfg(not(feature = "parallel"))]
use itertools::Itertools;
use num_bigint::{BigInt, BigUint, Sign};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{
        field::SonobeField,
        ops::{bits::FromBits, poly::MLEHelper, pow::Pow},
        ring::{PolynomialRingConfig, PolynomialRingOverField},
    },
    arithmetizations::{ArithRelation, ccs::CCS, r1cs::R1CS},
    circuits::{Assignments, AssignmentsOwned},
    commitments::{CommitmentOps, GroupBasedCommitment},
    sumcheck::{
        SumCheck,
        utils::{EqPoly, VPAuxInfo, VirtualPolynomial},
    },
    traits::SonobePrimeField,
    transcripts::Transcript,
    utils::null::Null,
};

use crate::{
    Error, FoldingSchemeProver,
    nova::AbstractNova,
    superneo::{
        SuperNeo, SuperNeoConfig,
        keys::SuperNeoKey,
        utils::{decompose, decompose2},
    },
};

impl<
    Cfg: SuperNeoConfig,
    A: CCS<Field = Cfg::F> + ArithRelation<Vec<Cfg::F>, Vec<Cfg::F>>,
    const N: usize,
> FoldingSchemeProver<1, N> for SuperNeo<Cfg, A>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &SuperNeoKey<Self::Arith, Cfg>,
        transcript: &mut impl Transcript<Cfg::F>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        mut rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<1, N>), Error> {
        let W = Ws[0].borrow();
        let U = Us[0].borrow();
        let ws = &ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let base = Cfg::B;

        let m = Cfg::F::MODULUS.into();
        let mut l = m.to_radix_le(base as u32).len();
        if BigUint::from(base).pow(l as u32 - 1) == m {
            l -= 1;
        }

        let ccs = &pk.arith; // TODO: M1
        let cfg = ccs.config();
        let s = log2(cfg.n_variables * l) as usize;
        let t = cfg.n_matrices + 1;
        let S = &A::multisets();
        let c = &A::coefficients();

        transcript.add(U);
        transcript.add(&us[..]);

        let alpha = transcript.challenge_many::<Cfg::K>(s);
        let gamma = transcript.challenge::<Cfg::K>();

        let gamma_powers = &gamma.powers(Cfg::M * t * Cfg::P::DEGREE + N + Cfg::M + N);

        let decomposed_zs = ws
            .iter()
            .zip(us)
            .map(|(w, u)| {
                [One::one()]
                    .iter()
                    .chain(&u.x)
                    .chain(&w.w)
                    .flat_map(|i| decompose::<Cfg::F>(*i, Cfg::B))
                    .collect()
            })
            .chain(
                W.w.iter()
                    .zip(&U.x)
                    .zip(&U.u)
                    .map(|((w, x), u)| [&u[..], x, w].concat()),
            )
            .collect::<Vec<_>>();

        let mz = cfg_iter!(decomposed_zs)
            .map(|decomposed_z| {
                let embedded_z = &decomposed_z.chunks(Cfg::P::DEGREE).collect::<Vec<_>>();
                pk.transformed_matrices
                    .iter()
                    .map(move |matrix| {
                        matrix
                            .iter()
                            .map(|i| {
                                let mut r = PolynomialRingOverField::<Cfg::P, Cfg::F>::default();
                                for (j, offset) in i {
                                    j.iter().enumerate().for_each(|(i, v)| {
                                        r = r.add(&v.mul_small(&embedded_z[offset + i]));
                                    });
                                }
                                r
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // 0..t * N
        let incoming_mles = ws
            .iter()
            .zip(us)
            .flat_map(|(w, u)| {
                ccs.mles((One::one(), &u.x, &w.w).into())
                    .into_iter()
                    .chain([{ MLE::from_evaluations(&[&[One::one()][..], &u.x, &w.w].concat()) }])
            })
            .map(|mle| {
                let mut e = mle.evaluations;
                e.resize(1 << s, Zero::zero());
                MLE {
                    num_vars: s,
                    evaluations: e.into_iter().map(Cfg::K::from_base_prime_field).collect(),
                }
            });
        // t * N..t * N + (M + N) * (2B - 1)
        let z_mles = decomposed_zs
            .iter()
            .flat_map(|v| {
                (1 - Cfg::B as i8..Cfg::B as i8).map(move |j| {
                    let mut e = v.iter().map(|i| Cfg::K::from(i - j)).collect::<Vec<_>>();
                    e.resize(1 << s, Cfg::K::from(-j));

                    MLE {
                        num_vars: s,
                        evaluations: e,
                    }
                })
            })
            .collect::<Vec<_>>();
        // t * N + (M + N) * (2B - 1)..t * N + (M + N) * (2B - 1) + M * t * D
        let running_mles = mz.iter().skip(N).flat_map(|i| {
            i.iter().flat_map(move |j| {
                (0..Cfg::P::DEGREE).map(move |k| {
                    let mut e = j
                        .iter()
                        .map(|c| Cfg::K::from_base_prime_field(c.coeffs[k]))
                        .collect::<Vec<_>>();
                    e.resize(1 << s, Zero::zero());
                    MLE::from_evaluations(&e)
                })
            })
        });
        // t * N + (M + N) * (2B - 1) + M * t * D
        // t * N + (M + N) * (2B - 1) + M * t * D + 1
        let eq_mles = [
            MLE::from_evaluations_vec(s, EqPoly::fix_y_evals(&U.r)),
            MLE::from_evaluations_vec(s, EqPoly::fix_y_evals(&alpha)),
        ];

        let f_products = (0..N).flat_map(|k| {
            let gamma = gamma_powers[k];
            S.iter().zip(c).map(move |(S_i, &c_i)| {
                (
                    Cfg::K::from_base_prime_field(c_i) * gamma,
                    S_i.iter()
                        .map(|j| k * t + j)
                        .chain([t * N
                            + (Cfg::M + N) * (2 * Cfg::B - 1)
                            + Cfg::M * t * Cfg::P::DEGREE
                            + 1])
                        .collect::<Vec<_>>(),
                )
            })
        });
        let nc_products = (0..Cfg::M + N).map(|k| {
            let gamma = gamma_powers[k + N];
            (
                gamma,
                (t * N + k * (2 * Cfg::B - 1)..t * N + (k + 1) * (2 * Cfg::B - 1))
                    .chain([t * N
                        + (Cfg::M + N) * (2 * Cfg::B - 1)
                        + Cfg::M * t * Cfg::P::DEGREE
                        + 1])
                    .collect::<Vec<_>>(),
            )
        });
        let eval_products = (0..Cfg::M).flat_map(|i| {
            (0..t).flat_map(move |j| {
                (0..Cfg::P::DEGREE).map(move |k| {
                    let gamma = gamma_powers
                        [i * t * Cfg::P::DEGREE + j * Cfg::P::DEGREE + k + N + Cfg::M + N];

                    (
                        gamma,
                        vec![
                            t * N
                                + (Cfg::M + N) * (2 * Cfg::B - 1)
                                + i * t * Cfg::P::DEGREE
                                + j * Cfg::P::DEGREE
                                + k,
                            t * N + (Cfg::M + N) * (2 * Cfg::B - 1) + Cfg::M * t * Cfg::P::DEGREE,
                        ],
                    )
                })
            })
        });

        let q = VirtualPolynomial {
            aux_info: VPAuxInfo {
                num_variables: s,
                max_degree: cfg.degree.max(Cfg::B * 2 - 1) + 1,
            },
            flattened_ml_extensions: incoming_mles
                .chain(z_mles)
                .chain(running_mles)
                .chain(eq_mles)
                .collect(),
            products: f_products.chain(nc_products).chain(eval_products).collect(),
        };

        let (sumcheck_proof, r_prime, mles) = SumCheck::prove(q, transcript)?;

        let y_prime = cfg_into_iter!(mz)
            .map(|mz| {
                mz.into_iter()
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
                        let dim = r_prime.len();
                        // evaluate single variable of partial point from left to right
                        for i in 1..dim + 1 {
                            let r = r_prime[i - 1];
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

        let embedded_zs = decomposed_zs
            .into_iter()
            .map(|z| {
                PolynomialRingOverField::vector_embedding(
                    z.iter().map(|i| Cfg::F::from(*i)).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        let mut z = vec![PolynomialRingOverField::default(); embedded_zs[0].len()];
        for (embedded_z, rho) in embedded_zs.into_iter().zip(&rhos) {
            for i in 0..z.len() {
                z[i] = z[i].add(&embedded_z[i].mul(rho));
            }
        }
        let z = PolynomialRingOverField::vector_unembedding(z);

        assert_eq!(z.len(), cfg.n_variables * l);

        let mut zs = vec![vec![]; Cfg::M];
        let mut us = vec![vec![]; Cfg::M];
        let mut xs = vec![vec![]; Cfg::M];
        let mut ws = vec![vec![]; Cfg::M];
        for i in 0..z.len() {
            let d = decompose2(z[i], Cfg::B, Cfg::M);
            for j in 0..Cfg::M {
                zs[j].push(d[j]);
                if i < l {
                    us[j].push(d[j]);
                } else if i < l + cfg.n_public_inputs * l {
                    xs[j].push(d[j]);
                } else {
                    ws[j].push(d[j]);
                }
            }
        }

        let cs = ws
            .iter()
            .map(|w| {
                Cfg::CM::commit(
                    &pk.ck,
                    &PolynomialRingOverField::vector_embedding(
                        w.iter().map(|i| Cfg::F::from(*i)).collect::<Vec<_>>(),
                    ),
                    &mut rng,
                )
                .map(|(c, r)| c)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let y = cfg_into_iter!(zs)
            .map(|decomposed_z| {
                let embedded_z = &decomposed_z.chunks(Cfg::P::DEGREE).collect::<Vec<_>>();
                pk.transformed_matrices
                    .iter()
                    .map(|matrix| {
                        let mut poly = matrix
                            .iter()
                            .map(|i| {
                                let mut r = PolynomialRingOverField::<Cfg::P, Cfg::F>::default();
                                for (j, offset) in i {
                                    j.iter().enumerate().for_each(|(i, v)| {
                                        r = r.add(&v.mul_small(&embedded_z[offset + i]));
                                    });
                                }
                                PolynomialRingOverField::<Cfg::P, _> {
                                _t: PhantomData,
                                    coeffs: r
                                    .coeffs
                                    .into_iter()
                                    .map(Cfg::K::from_base_prime_field)
                                    .collect(),
                                }
                            })
                            .collect::<Vec<_>>();
                        poly.resize(1 << s, Default::default());
                        let nv = s;
                        let dim = r_prime.len();
                        // evaluate single variable of partial point from left to right
                        for i in 1..dim + 1 {
                            let r = r_prime[i - 1];
                            for b in 0..(1 << (nv - i)) {
                                let left = &poly[b << 1];
                                let right = &poly[(b << 1) + 1];
                                poly[b] = left.add(&right.sub(&left).scale(r));
                            }
                        }
                        poly.remove(0)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        Ok((
            Self::RW {
                _t: PhantomData,
                w: ws,
            },
            Self::RU {
                u: us,
                x: xs,
                c: cs.clone(),
                r: r_prime,
                y: y.clone(),
            },
            Self::Proof::<1, N> {
                sc_proof: sumcheck_proof,
                y_prime,
                y,
                c_prime: cs.clone(),
            },
        ))
    }
}
