//! Proof verification for Nova.

use ark_std::{borrow::Borrow, cfg_iter, ops::Mul};
#[cfg(not(feature = "parallel"))]
use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{field::SonobeField, ops::bits::FromBits},
    commitments::GroupBasedCommitment,
    transcripts::Transcript,
};

use crate::{Error, FoldingSchemeVerifier, nova::AbstractNova};

impl<CM: GroupBasedCommitment, TF: SonobeField, const B: usize> FoldingSchemeVerifier<1, 1>
    for AbstractNova<CM, TF, B>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<TF>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        cm_t: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (Us[0].borrow(), us[0].borrow());

        let rho_bits = transcript.add(&U).add(&u).add(cm_t).challenge_bits(B);
        let rho = CM::Scalar::from_bits_le(&rho_bits);

        Ok(Self::RU {
            cm_e: U.cm_e + cm_t.mul(rho),
            u: U.u + rho,
            cm_w: U.cm_w + u.cm_w.mul(rho),
            x: cfg_iter!(U.x)
                .zip_eq(&u.x)
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
}

impl<CM: GroupBasedCommitment, TF: SonobeField, const B: usize> FoldingSchemeVerifier<2, 0>
    for AbstractNova<CM, TF, B>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<TF>,
        [U1, U2]: &[impl Borrow<Self::RU>; 2],
        _: &[impl Borrow<Self::IU>; 0],
        cm_t: &Self::Proof<2, 0>,
    ) -> Result<Self::RU, Error> {
        let (U1, U2) = (U1.borrow(), U2.borrow());

        let rho_bits = transcript.add(&(U1, U2)).add(cm_t).challenge_bits(B);
        let rho = CM::Scalar::from_bits_le(&rho_bits);
        let rho_squared = rho * rho;

        Ok(Self::RU {
            cm_e: U1.cm_e + cm_t.mul(rho) + U2.cm_e.mul(rho_squared),
            u: U1.u + rho * U2.u,
            cm_w: U1.cm_w + U2.cm_w.mul(rho),
            x: cfg_iter!(U1.x)
                .zip_eq(&U2.x)
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
}
