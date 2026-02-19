//! Proof generation for Mova.

use ark_ff::{One, Zero};
use ark_poly::{
    DenseMultilinearExtension as MLE, DenseUVPolynomial, Polynomial, univariate::DensePolynomial,
};
use ark_std::{borrow::Borrow, cfg_into_iter, cfg_iter, rand::RngCore};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::{bits::FromBits, poly::MLEHelper},
    arithmetizations::{Arith, ArithConfig},
    circuits::AssignmentsOwned,
    commitments::GroupBasedCommitment,
    transcripts::Transcript,
};

use crate::{
    Error, FoldingSchemeProver,
    mova::{Mova, MovaKey, MovaProof},
};

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeProver<1, 1>
    for Mova<CM, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &MovaKey<Self::Arith, CM>,
        transcript: &mut impl Transcript<CM::Scalar>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<1, 1>, Self::Challenge), Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        // Protocol 5

        // Step 5.1: Commit to w & send commitment
        let (cm_w, r_w) = CM::commit(&pk.ck, w, rng)?;

        transcript.add(U);
        transcript.add(u);
        transcript.add(&cm_w);

        // Step 5.2: Get challenge r_E
        let r_e = transcript.challenge_field_elements(U.r_e.len());

        // Protocol 6

        // Step 6.1: Compute l(X) such that l(0) = r1, l(1) = r2
        let l = U
            .r_e
            .iter()
            .zip(&r_e)
            .map(|(&r1, &r2)| DensePolynomial::from_coefficients_vec(vec![r1, r2 - r1]))
            .collect::<Vec<_>>();
        // Step 6.1: Compute h1(X) and h2(X), where h2(X) is empty in our case
        let h1 = {
            // Initialize the polynomial vector from the evaluations in the MLE.
            // Each evaluation is turned into a constant polynomial.
            let mut poly =
                W.e.iter()
                    .chain(vec![Zero::zero(); 1 << U.r_e.len()].iter())
                    .map(|&x| DensePolynomial::from_coefficients_slice(&[x]))
                    .collect::<Vec<_>>();

            for i in &l {
                poly = poly
                    .chunks_exact(2)
                    .map(|w| &w[0] + (&w[1] - &w[0]).naive_mul(i))
                    .collect();
            }

            poly.swap_remove(0)
        };
        // Step 6.1: Send h1(X) and h2(X), where the constant term is omitted
        // because it always equals v
        let mut h1_coeffs = h1.coeffs.clone();
        h1_coeffs.resize(pk.arith.config().log_constraints() + 1, Zero::zero());
        h1_coeffs.remove(0);
        transcript.add(&h1_coeffs);

        // Step 6.2: Get challenge beta
        let beta = transcript.challenge_field_element();

        // Step 6.3: Compute r_E'
        let r_e_prime = l.iter().map(|i| i.evaluate(&beta)).collect();

        // Protocol 7

        // Step 7.1: Compute cross term `T`. We follow the optimized approach in
        // [Mova](https://eprint.iacr.org/2024/1220.pdf)'s section 5.2.
        let v = pk.arith.evaluate_at(AssignmentsOwned::from((
            U.u + CM::Scalar::one(),
            cfg_iter!(U.x).zip(&u[..]).map(|(a, b)| *a + b).collect(),
            cfg_iter!(W.w).zip(&w[..]).map(|(a, b)| *a + b).collect(),
        )))?;
        let T = cfg_into_iter!(v)
            .zip(&W.e)
            .map(|(a, b)| a - b)
            .collect::<Vec<_>>();
        // Step 7.1: Evaluate & send T's MLE at r_E'
        let t = MLE::from_evaluations(&T).evaluate(&r_e_prime);
        transcript.add(&t);

        // Step 7.2: Get challenge rho
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = CM::Scalar::from_bits_le(&rho_bits);

        // Step 7.3: Compute new W and U
        Ok((
            Self::RW {
                e: cfg_iter!(W.e).zip(&T).map(|(a, b)| rho * b + a).collect(),
                w: cfg_iter!(W.w)
                    .zip(&w[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
                r_w: W.r_w + r_w * rho,
            },
            Self::RU {
                r_e: r_e_prime,
                v: h1.evaluate(&beta) + rho * t,
                u: U.u + rho,
                cm_w: U.cm_w + cm_w * rho,
                x: cfg_iter!(U.x)
                    .zip(&u[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
            },
            MovaProof { h1_coeffs, t, cm_w },
            rho_bits.try_into().unwrap(),
        ))
    }
}
