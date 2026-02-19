//! Proof verification for Mova.

use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_std::{borrow::Borrow, cfg_iter};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::bits::FromBits, commitments::GroupBasedCommitment, transcripts::Transcript,
};

use crate::{Error, FoldingSchemeVerifier, mova::Mova};

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeVerifier<1, 1>
    for Mova<CM, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<CM::Scalar>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (Us[0].borrow(), us[0].borrow());

        let h1 = DensePolynomial::from_coefficients_vec([&[U.v][..], &proof.h1_coeffs].concat());

        transcript.add(U);
        transcript.add(u);
        transcript.add(&proof.cm_w);

        let r_e = transcript.challenge_field_elements(U.r_e.len());

        transcript.add(&proof.h1_coeffs);

        let beta = transcript.challenge_field_element();

        transcript.add(&proof.t);

        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = CM::Scalar::from_bits_le(&rho_bits);

        Ok(Self::RU {
            r_e: U
                .r_e
                .iter()
                .zip(r_e)
                .map(|(&r1, r2)| r1 + beta * (r2 - r1))
                .collect(),
            v: h1.evaluate(&beta) + rho * proof.t,
            u: U.u + rho,
            cm_w: U.cm_w + proof.cm_w * rho,
            x: cfg_iter!(U.x)
                .zip(&u[..])
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
}
