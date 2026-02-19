//! Proof verification for Ova.

use ark_std::{borrow::Borrow, cfg_iter};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::bits::FromBits, commitments::GroupBasedCommitment, traits::SonobeField,
    transcripts::Transcript,
};

use crate::{Error, FoldingSchemeVerifier, ova::AbstractOva};

impl<CM: GroupBasedCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeVerifier<1, 1> for AbstractOva<CM, TF, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<TF>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        cm: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (Us[0].borrow(), us[0].borrow());

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(cm);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = CM::Scalar::from_bits_le(&rho_bits);

        Ok(Self::RU {
            u: U.u + rho,
            cm: U.cm + *cm * rho,
            x: cfg_iter!(U.x)
                .zip(&u[..])
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
}
