//! Proof generation for Ova.

use ark_ff::One;
use ark_std::{borrow::Borrow, cfg_iter, rand::RngCore};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::bits::FromBits, circuits::Assignments, commitments::GroupBasedCommitment,
    traits::SonobeField, transcripts::Transcript,
};

use crate::{
    Error, FoldStep, FoldingSchemeProver,
    ova::{AbstractOva, OvaKey},
};

impl<CM: GroupBasedCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeProver<1, 1> for AbstractOva<CM, TF, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &OvaKey<Self::Arith, CM>,
        transcript: &mut impl Transcript<TF>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: impl RngCore,
    ) -> Result<FoldStep<Self, 1, 1>, Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        // Compute the cross term `T` by following the original Nova paper.
        let z1 = Assignments::from((U.u, &U.x, &W.w));
        let z2 = Assignments::from((CM::Scalar::one(), &u[..], &w[..]));
        let t = pk.arith.evaluate_rows(|((a, b), c)| {
            let az1: CM::Scalar = a.iter().map(|(val, col)| z1[*col] * val).sum();
            let az2: CM::Scalar = a.iter().map(|(val, col)| z2[*col] * val).sum();
            let bz1: CM::Scalar = b.iter().map(|(val, col)| z1[*col] * val).sum();
            let bz2: CM::Scalar = b.iter().map(|(val, col)| z2[*col] * val).sum();
            let cz1: CM::Scalar = c.iter().map(|(val, col)| z1[*col] * val).sum();
            let cz2: CM::Scalar = c.iter().map(|(val, col)| z2[*col] * val).sum();
            Ok(az1 * bz2 + az2 * bz1 - z2[0] * cz1 - z1[0] * cz2)
        })?;

        let (cm, r) = CM::commit(&pk.ck, &[w, &t[..]].concat(), rng)?;

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(&cm);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = CM::Scalar::from_bits_le(&rho_bits);

        Ok(FoldStep {
            next_running_witness: Self::RW {
                w: cfg_iter!(W.w)
                    .zip(&w[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
                r: W.r + r * rho,
            },
            next_running_instance: Self::RU {
                u: U.u + rho,
                cm: U.cm + cm * rho,
                x: cfg_iter!(U.x)
                    .zip(&u[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
            },
            proof: cm,
            challenge: rho_bits.try_into().unwrap(),
        })
    }
}
