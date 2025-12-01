use ark_ff::One;
use ark_std::{borrow::Borrow, cfg_iter, rand::RngCore};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::bits::FromBits, circuits::Assignments, commitments::GroupBasedVectorCommitment,
    traits::SonobeField, transcripts::Transcript,
};

use crate::{
    ova::{AbstractOva, OvaKey},
    Error, FoldingSchemeProver,
};

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeProver<1, 1> for AbstractOva<VC, TF, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &OvaKey<Self::Arith, VC>,
        transcript: &mut impl Transcript<TF>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: &mut impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<1, 1>, Self::Challenge), Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        // Compute the cross term `T` by following the original Nova paper.
        let z1 = Assignments::from((U.u, &U.x, &W.w));
        let z2 = Assignments::from((VC::Scalar::one(), &u[..], &w[..]));
        let t = cfg_iter!(pk.arith.A)
            .zip(&pk.arith.B)
            .zip(&pk.arith.C)
            .map(|((a, b), c)| {
                let az1: VC::Scalar = a.iter().map(|(val, col)| z1[*col] * val).sum();
                let az2: VC::Scalar = a.iter().map(|(val, col)| z2[*col] * val).sum();
                let bz1: VC::Scalar = b.iter().map(|(val, col)| z1[*col] * val).sum();
                let bz2: VC::Scalar = b.iter().map(|(val, col)| z2[*col] * val).sum();
                let cz1: VC::Scalar = c.iter().map(|(val, col)| z1[*col] * val).sum();
                let cz2: VC::Scalar = c.iter().map(|(val, col)| z2[*col] * val).sum();
                az1 * bz2 + az2 * bz1 - z2[0] * cz1 - z1[0] * cz2
            })
            .collect::<Vec<_>>();

        let (cm, r) = VC::commit(&pk.ck, &[w, &t[..]].concat(), rng)?;

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(&cm);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from_bits_le(&rho_bits);

        Ok((
            Self::RW {
                w: cfg_iter!(W.w)
                    .zip(&w[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
                r: W.r + r * rho,
            },
            Self::RU {
                u: U.u + rho,
                cm: U.cm + cm * rho,
                x: cfg_iter!(U.x)
                    .zip(&u[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
            },
            cm,
            rho_bits.try_into().unwrap(),
        ))
    }
}
