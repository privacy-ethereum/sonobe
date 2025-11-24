use ark_std::{borrow::Borrow, cfg_iter, ops::Mul};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::bits::FromBits, commitments::GroupBasedVectorCommitment, traits::SonobeField,
    transcripts::Transcript,
};

use crate::{
    nova::{AbstractNova, AbstractNova2},
    Error, FoldingSchemeVerifier,
};

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeVerifier<1, 1> for AbstractNova<VC, TF, CHALLENGE_BITS>
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

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(cm_t);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from_bits_le(&rho_bits);

        Ok(Self::RU {
            cm_e: U.cm_e + cm_t.mul(rho),
            u: U.u + rho,
            cm_w: U.cm_w + u.cm_w.mul(rho),
            x: cfg_iter!(U.x).zip(&u.x).map(|(a, b)| rho * b + a).collect(),
        })
    }
}

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeVerifier<2, 0> for AbstractNova<VC, TF, CHALLENGE_BITS>
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

        let rho_bits = {
            transcript.add(&U1);
            transcript.add(&U2);
            transcript.add(cm_t);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from_bits_le(&rho_bits);
        let rho_squared = rho * rho;

        Ok(Self::RU {
            cm_e: U1.cm_e + cm_t.mul(rho) + U2.cm_e.mul(rho_squared),
            u: U1.u + rho * U2.u,
            cm_w: U1.cm_w + U2.cm_w.mul(rho),
            x: cfg_iter!(U1.x)
                .zip(&U2.x)
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
}

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeVerifier<1, 1> for AbstractNova2<VC, TF, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<TF>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        pi: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (Us[0].borrow(), us[0].borrow());

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(pi);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from_bits_le(&rho_bits);

        let (cm_w, cm_t) = pi;

        Ok(Self::RU {
            cm_e: U.cm_e + cm_t.mul(rho),
            u: U.u + rho,
            cm_w: U.cm_w + cm_w.mul(rho),
            x: cfg_iter!(U.x)
                .zip(&u[..])
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
}
