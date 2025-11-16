// code forked from:
// https://github.com/EspressoSystems/hyperplonk/tree/main/subroutines/src/poly_iop/sum_check
//
// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! This module implements the sum check protocol.

use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, DenseMultilinearExtension, DenseUVPolynomial, Polynomial,
};
use ark_std::{cfg_chunks, cfg_into_iter, cfg_iter, fmt::Debug};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use thiserror::Error;

use self::utils::{
    barycentric_weights, compute_lagrange_interpolated_poly, extrapolate, VPAuxInfo,
    VirtualPolynomial,
};
use crate::transcripts::{Absorbable, Transcript};

pub mod circuits;
pub mod utils;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Incorrect evaluations: {0} + {1} != {2}")]
    IncorrectEvaluations(String, String, String),
    #[error("Incorrect proof length: expected {0}, got {1}")]
    UnexpectedProofLength(usize, usize),
    #[error("Unexpected polynomial degree: expected at most {0}, got {1}")]
    UnexpectedPolynomialDegree(usize, usize),
}

#[derive(Clone, Debug, Default, Copy, PartialEq, Eq)]
pub struct IOPSumCheck;

impl IOPSumCheck {
    pub fn prove<F: PrimeField + Absorbable>(
        mut poly: VirtualPolynomial<F>,
        transcript: &mut impl Transcript<F>,
    ) -> Result<(Vec<Vec<F>>, Vec<F>, Vec<DenseMultilinearExtension<F>>), Error> {
        transcript.add(&F::from(poly.aux_info.num_variables as u64));
        transcript.add(&F::from(poly.aux_info.max_degree as u64));
        let extrapolation_aux = (1..poly.aux_info.max_degree)
            .map(|degree| {
                let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                let weights = barycentric_weights(&points);
                (points, weights)
            })
            .collect::<Vec<_>>();
        let mut prover_msgs = Vec::with_capacity(poly.aux_info.num_variables);
        let mut challenges = Vec::with_capacity(poly.aux_info.num_variables);
        for i in 0..poly.aux_info.num_variables {
            let mut products_sum = vec![F::ZERO; poly.aux_info.max_degree + 1];

            // Step 2: generate sum for the partial evaluated polynomial:
            // f(r_1, ... r_m,, x_{m+1}... x_n)

            poly.products.iter().for_each(|(coefficient, products)| {
                #[cfg(feature = "parallel")]
                let mut sum = cfg_into_iter!(0..1 << (poly.aux_info.num_variables - i - 1))
                    .fold(
                        || {
                            (
                                vec![(F::ZERO, F::ZERO); products.len()],
                                vec![F::ZERO; products.len() + 1],
                            )
                        },
                        |(mut buf, mut acc), b| {
                            buf.iter_mut()
                                .zip(products.iter())
                                .for_each(|((eval, step), f)| {
                                    let table = &poly.flattened_ml_extensions[*f];
                                    *eval = table[b << 1];
                                    *step = table[(b << 1) + 1] - table[b << 1];
                                });
                            acc[0] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            acc[1..].iter_mut().for_each(|acc| {
                                buf.iter_mut().for_each(|(eval, step)| *eval += step);
                                *acc += buf.iter().map(|(eval, _)| eval).product::<F>();
                            });
                            (buf, acc)
                        },
                    )
                    .map(|(_, partial)| partial)
                    .reduce(
                        || vec![F::ZERO; products.len() + 1],
                        |mut sum, partial| {
                            sum.iter_mut()
                                .zip(partial.iter())
                                .for_each(|(sum, partial)| *sum += partial);
                            sum
                        },
                    );
                #[cfg(not(feature = "parallel"))]
                let mut sum = cfg_into_iter!(0..1 << (poly.aux_info.num_variables - i - 1))
                    .fold(
                        (
                            vec![(F::ZERO, F::ZERO); products.len()],
                            vec![F::ZERO; products.len() + 1],
                        ),
                        |(mut buf, mut acc), b| {
                            buf.iter_mut()
                                .zip(products.iter())
                                .for_each(|((eval, step), f)| {
                                    let table = &poly.flattened_ml_extensions[*f];
                                    *eval = table[b << 1];
                                    *step = table[(b << 1) + 1] - table[b << 1];
                                });
                            acc[0] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            acc[1..].iter_mut().for_each(|acc| {
                                buf.iter_mut().for_each(|(eval, step)| *eval += step as &_);
                                *acc += buf.iter().map(|(eval, _)| eval).product::<F>();
                            });
                            (buf, acc)
                        },
                    )
                    .1;
                sum.iter_mut().for_each(|sum| *sum *= coefficient);
                let extraploation = cfg_into_iter!(0..poly.aux_info.max_degree - products.len())
                    .map(|i| {
                        let (points, weights) = &extrapolation_aux[products.len() - 1];
                        let at = F::from((products.len() + 1 + i) as u64);
                        extrapolate(points, weights, &sum, &at)
                    })
                    .collect::<Vec<_>>();
                products_sum
                    .iter_mut()
                    .zip(sum.iter().chain(extraploation.iter()))
                    .for_each(|(products_sum, sum)| *products_sum += sum);
            });

            let mut prover_poly = compute_lagrange_interpolated_poly(&products_sum).coeffs;
            prover_poly.resize(poly.aux_info.max_degree + 1, F::ZERO);
            transcript.add(&prover_poly);
            prover_msgs.push(prover_poly);

            let challenge = transcript.challenge_field_element();
            challenges.push(challenge);
            poly.flattened_ml_extensions.iter_mut().for_each(|mle| {
                mle.evaluations = cfg_chunks!(mle.evaluations, 2)
                    .map(|chunk| chunk[0] + challenge * (chunk[1] - chunk[0]))
                    .collect();
                mle.num_vars -= 1;
            });
        }

        Ok((prover_msgs, challenges, poly.flattened_ml_extensions))
    }

    pub fn verify<F: PrimeField + Absorbable>(
        claimed_sum: F,
        proofs: &[Vec<F>],
        aux_info: &VPAuxInfo,
        transcript: &mut impl Transcript<F>,
    ) -> Result<(F, Vec<F>), Error> {
        transcript.add(&F::from(aux_info.num_variables as u64));
        transcript.add(&F::from(aux_info.max_degree as u64));
        if proofs.len() != aux_info.num_variables {
            return Err(Error::UnexpectedProofLength(
                aux_info.num_variables,
                proofs.len(),
            ));
        }

        let mut challenges = Vec::with_capacity(aux_info.num_variables);
        let mut expected = claimed_sum;

        // Outer loop is not parallelized because `DensePolynomial::evaluate` is
        // already parallelized internally.
        for coeffs in proofs {
            if coeffs.len() - 1 != aux_info.max_degree {
                return Err(Error::UnexpectedPolynomialDegree(
                    aux_info.max_degree,
                    coeffs.len() - 1,
                ));
            }

            let eval_at_zero = coeffs[0];
            let eval_at_one = coeffs.iter().sum::<F>();

            // the deferred check during the interactive phase:
            // 1. check if the received 'P(0) + P(1) = expected`.
            if eval_at_zero + eval_at_one != expected {
                return Err(Error::IncorrectEvaluations(
                    eval_at_zero.to_string(),
                    eval_at_one.to_string(),
                    expected.to_string(),
                ));
            }

            transcript.add(coeffs);
            let challenge = transcript.challenge_field_element();

            // 2. set `expected` to `P(r)`
            expected = DensePolynomial::from_coefficients_slice(coeffs).evaluate(&challenge);
            challenges.push(challenge);
        }

        Ok((expected, challenges))
    }
}

#[cfg(test)]
pub mod tests {
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;
    use ark_pallas::Fr;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::{test_rng, One, Zero};

    use super::*;
    use crate::transcripts::poseidon::poseidon_canonical_config;

    #[test]
    pub fn sumcheck_poseidon() -> Result<(), Error> {
        let n_vars = 10;

        let mut rng = test_rng();
        let poly_mle = DenseMultilinearExtension::rand(n_vars, &mut rng);
        let virtual_poly = VirtualPolynomial::new_from_mle(poly_mle, Fr::ONE);

        sumcheck_poseidon_opt(virtual_poly)?;

        // test with zero poly
        let poly_mle = DenseMultilinearExtension::from_evaluations_vec(
            n_vars,
            vec![Fr::zero(); 2usize.pow(n_vars as u32)],
        );
        let virtual_poly = VirtualPolynomial::new_from_mle(poly_mle, Fr::ONE);
        sumcheck_poseidon_opt(virtual_poly)?;
        Ok(())
    }

    fn sumcheck_poseidon_opt(virtual_poly: VirtualPolynomial<Fr>) -> Result<(), Error> {
        let aux_info = virtual_poly.aux_info.clone();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // sum-check prove
        let mut transcript_p: PoseidonSponge<Fr> = PoseidonSponge::<Fr>::new(&poseidon_config);
        let (proofs, _, _) = IOPSumCheck::prove(virtual_poly, &mut transcript_p)?;

        // sum-check verify
        let poly = DensePolynomial::from_coefficients_slice(&proofs[0]);
        let claimed_sum = poly.evaluate(&Fr::one()) + poly.evaluate(&Fr::zero());
        let mut transcript_v: PoseidonSponge<Fr> = PoseidonSponge::<Fr>::new(&poseidon_config);
        let res_verify = IOPSumCheck::verify(claimed_sum, &proofs, &aux_info, &mut transcript_v);

        assert!(res_verify.is_ok());
        Ok(())
    }
}
