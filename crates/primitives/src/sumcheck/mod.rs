//! This module implements the sumcheck protocol and its in-circuit gadgets for
//! verification.
//!
//! The code is forked from HyperPlonk's sumcheck [implementation] and modified
//! to fit Sonobe's design & use case.
//!
//! [implementation]: https://github.com/EspressoSystems/hyperplonk/tree/main/subroutines/src/poly_iop/sum_check

// Below we attach HyperPlonk's original license notice.
//
// The MIT License (MIT)
//
// Copyright (c) 2022 Espresso Systems (espressosys.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use ark_ff::{Field, PrimeField};
use ark_poly::{
    DenseMultilinearExtension, DenseUVPolynomial, Polynomial, univariate::DensePolynomial,
};
use ark_std::{cfg_chunks, cfg_into_iter, fmt::Debug};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use thiserror::Error;

use self::utils::{
    VPAuxInfo, VirtualPolynomial, barycentric_weights, compute_lagrange_interpolated_poly,
    extrapolate,
};
use crate::{
    algebra::field::SonobeField,
    traits::SonobePrimeField,
    transcripts::{Absorbable, Transcript},
};

pub mod circuits;
pub mod utils;

/// [`Error`] enumerates possible errors during the sumcheck protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// [`Error::IncorrectEvaluation`] indicates that the evaluation does not
    /// match the claimed value.
    #[error("Incorrect evaluation: claimed {0}, got {1}")]
    IncorrectEvaluation(String, String),
    /// [`Error::UnexpectedProofLength`] indicates that the proof length does
    /// not match the expected length.
    #[error("Incorrect proof length: expected {0}, got {1}")]
    UnexpectedProofLength(usize, usize),
    /// [`Error::UnexpectedPolynomialDegree`] indicates that the polynomial
    /// degree exceeds the expected degree.
    #[error("Unexpected polynomial degree: expected at most {0}, got {1}")]
    UnexpectedPolynomialDegree(usize, usize),
}

/// [`SumCheck`] implements the sumcheck protocol.
///
/// In the sumcheck protocol, a prover wants to convince a verifier that the sum
/// of a multilinear polynomial `f` over the Boolean hypercube equals a claimed
/// value `z`, i.e., `∑_{x_1, ..., x_n ∈ {0,1}} f(x_1, ..., x_n) = z`, without
/// having the verifier evaluate the sum themselves.
///
/// To this end, the prover and verifier engage in `n` rounds of interaction.
/// In each round `i`, we consider a variant of the original problem: given
/// polynomial `f_i` of `n - i + 1` variables `x_i, ..., x_n` and a claim `z_i`,
/// check if `∑_{x_i, ..., x_n ∈ {0,1}} f_i(x_i, ..., x_n) = z_i`.
/// The prover and the verifier's goal is to reduce this problem to the next
/// round's problem, where the new polynomial and claim are defined as:
/// - `f_{i+1}(x_{i+1}, ..., x_n) = f_i(r_i, x_{i+1}, ..., x_n)` for a random
///   `r_i`
/// - `z_{i+1} = ∑_{x_{i+1}, ..., x_n ∈ {0,1}} f_i(r_i, x_{i+1}, ..., x_n)`
///
/// Such a reduction is achieved by the following steps:
/// 1. The prover sends to the verifier the univariate polynomial
///    `g_i(x_i) = ∑_{x_{i+1}, ..., x_n ∈ {0,1}} f_i(x_i, x_{i+1}, ..., x_n)`.
/// 2. The verifier checks if the current claim `z_i = g_i(0) + g_i(1)`.
/// 3. The verifier sends to the prover a random challenge `r_i`.
/// 4. Both parties prepares for the next round's polynomial
///    `f_{i+1}(x_{i+1}, ..., x_n) = f_i(r_i, x_{i+1}, ..., x_n)` and claim
///    `z_{i+1} = g_i(r_i)`, until the last round where all variables are fixed.
#[derive(Clone, Debug, Default, Copy, PartialEq, Eq)]
pub struct SumCheck;

impl SumCheck {
    /// [`SumCheck::prove`] runs the prover of the sumcheck protocol over a
    /// [`VirtualPolynomial`] `poly = f` with the given `transcript`.
    /// It returns the proof (i.e., round polynomials `g_1, ..., g_n`),
    /// Fiat-Shamir challenges `r_1, ..., r_n`, and the final "polynomial" with
    /// all variables fixed (i.e., the evaluation `f_{n+1} = f(r_1, ..., r_n)`).
    #[allow(clippy::type_complexity)]
    pub fn prove<F: SonobeField>(
        mut poly: VirtualPolynomial<F>,
        transcript: &mut impl Transcript<F::BasePrimeField>,
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
            // `f_i(x_i, ..., x_n) = f(r_1, ... r_{i-1}, x_i, ..., x_n)`

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

            let challenge = transcript.challenge();
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

    /// [`SumCheck::verify`] runs the verifier of the sumcheck protocol given
    /// the claimed sum `claimed_sum = z`, the proof `proofs` (i.e., round
    /// polynomials `g_1, ..., g_n`), the auxiliary info `aux_info`, and the
    /// transcript `transcript`.
    /// It returns the final evaluation `z_{n+1} = f(r_1, ..., r_n)` and the
    /// Fiat-Shamir challenges `r_1, ..., r_n`.
    pub fn verify<F: SonobeField>(
        mut claimed_sum: F,
        proofs: &[Vec<F>],
        aux_info: &VPAuxInfo,
        transcript: &mut impl Transcript<F::BasePrimeField>,
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
            // 1. check if the received 'g_i(0) + g_i(1) = z_i`.
            if eval_at_zero + eval_at_one != claimed_sum {
                return Err(Error::IncorrectEvaluation(
                    claimed_sum.to_string(),
                    format!("{} + {}", eval_at_zero, eval_at_one),
                ));
            }

            transcript.add(coeffs);
            let challenge = transcript.challenge();

            // 2. set next `z_{i+1}` to `g_i(r_i)`
            claimed_sum = DensePolynomial::from_coefficients_slice(coeffs).evaluate(&challenge);
            challenges.push(challenge);
        }

        Ok((claimed_sum, challenges))
    }
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;
    use ark_pallas::Fr;
    use ark_poly::MultilinearExtension;
    use ark_std::{One, Zero, rand::thread_rng};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::transcripts::poseidon::poseidon_circom_config;

    #[test]
    fn test_sumcheck() -> Result<(), Error> {
        let n_vars = 10;

        let mut rng = thread_rng();
        let poly_mle = DenseMultilinearExtension::rand(n_vars, &mut rng);

        test_sumcheck_opt(poly_mle)?;

        // test with zero poly
        let poly_mle = DenseMultilinearExtension::from_evaluations_vec(
            n_vars,
            vec![Fr::zero(); 2usize.pow(n_vars as u32)],
        );
        test_sumcheck_opt(poly_mle)?;
        Ok(())
    }

    fn test_sumcheck_opt(poly_mle: DenseMultilinearExtension<Fr>) -> Result<(), Error> {
        let virtual_poly = VirtualPolynomial::new_from_mle(poly_mle, Fr::ONE);

        let aux_info = virtual_poly.aux_info.clone();
        let poseidon_config = poseidon_circom_config::<Fr>();

        // sum-check prove
        let mut transcript_p: PoseidonSponge<Fr> =
            PoseidonSponge::<Fr>::new(poseidon_config.clone());
        let (proofs, challenges_p, eval_p) = SumCheck::prove(virtual_poly, &mut transcript_p)?;

        // sum-check verify
        let poly = DensePolynomial::from_coefficients_slice(&proofs[0]);
        let claimed_sum = poly.evaluate(&Fr::one()) + poly.evaluate(&Fr::zero());
        let mut transcript_v: PoseidonSponge<Fr> = PoseidonSponge::<Fr>::new(poseidon_config);
        let (eval_v, challenges_v) =
            SumCheck::verify(claimed_sum, &proofs, &aux_info, &mut transcript_v)?;

        assert_eq!(eval_p[0].evaluate(&vec![]), eval_v);
        assert_eq!(challenges_p, challenges_v);
        Ok(())
    }
}
