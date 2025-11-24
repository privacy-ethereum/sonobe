use ark_ff::One;
use ark_std::{borrow::Borrow, cfg_into_iter, cfg_iter, ops::Mul, rand::RngCore};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::bits::FromBits,
    circuits::AssignmentsOwned,
    commitments::GroupBasedVectorCommitment,
    traits::SonobeField,
    transcripts::Transcript,
};

use crate::{
    nova::{AbstractNova, AbstractNova2, NovaKey},
    Error, FoldingSchemeProver,
};

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeProver<1, 1> for AbstractNova<VC, TF, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &NovaKey<Self::Arith, VC>,
        transcript: &mut impl Transcript<TF>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<1, 1>, Self::Challenge), Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        // Compute the cross term `T` by following the optimized approach in
        // [Mova](https://eprint.iacr.org/2024/1220.pdf)'s section 5.2.
        let v = pk.arith.eval_assignments(AssignmentsOwned::from((
            U.u + VC::Scalar::one(),
            cfg_iter!(U.x).zip(&u.x).map(|(a, b)| *a + b).collect(),
            cfg_iter!(W.w).zip(&w.w).map(|(a, b)| *a + b).collect(),
        )))?;
        let t = cfg_into_iter!(v)
            .zip(&W.e)
            .map(|(a, b)| a - b)
            .collect::<Vec<_>>();

        let (cm_t, r_t) = VC::commit(&pk.ck, &t, rng)?;

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(&cm_t);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from_bits_le(&rho_bits);

        Ok((
            Self::RW {
                e: cfg_iter!(W.e).zip(&t).map(|(a, b)| rho * b + a).collect(),
                r_e: W.r_e + r_t * rho,
                w: cfg_iter!(W.w).zip(&w.w).map(|(a, b)| rho * b + a).collect(),
                r_w: W.r_w + w.r_w * rho,
            },
            Self::RU {
                cm_e: U.cm_e + cm_t.mul(rho),
                u: U.u + rho,
                cm_w: U.cm_w + u.cm_w.mul(rho),
                x: cfg_iter!(U.x).zip(&u.x).map(|(a, b)| rho * b + a).collect(),
            },
            cm_t,
            rho_bits.try_into().unwrap(),
        ))
    }
}

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeProver<2, 0> for AbstractNova<VC, TF, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &NovaKey<Self::Arith, VC>,
        transcript: &mut impl Transcript<TF>,
        [W1, W2]: &[impl Borrow<Self::RW>; 2],
        [U1, U2]: &[impl Borrow<Self::RU>; 2],
        _: &[impl Borrow<Self::IW>; 0],
        _: &[impl Borrow<Self::IU>; 0],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<2, 0>, Self::Challenge), Error> {
        let (W1, U1) = (W1.borrow(), U1.borrow());
        let (W2, U2) = (W2.borrow(), U2.borrow());

        // Compute the cross term `T` by following the optimized approach in
        // [Mova](https://eprint.iacr.org/2024/1220.pdf)'s section 5.2.
        let v = pk.arith.eval_assignments(AssignmentsOwned::from((
            U1.u + U2.u,
            cfg_iter!(U1.x).zip(&U2.x).map(|(a, b)| *a + b).collect(),
            cfg_iter!(W1.w).zip(&W2.w).map(|(a, b)| *a + b).collect(),
        )))?;
        let t = cfg_into_iter!(v)
            .zip(&W1.e)
            .zip(&W2.e)
            .map(|((a, b), c)| a - b - c)
            .collect::<Vec<_>>();

        let (cm_t, r_t) = VC::commit(&pk.ck, &t, rng)?;

        let rho_bits = {
            transcript.add(&U1);
            transcript.add(&U2);
            transcript.add(&cm_t);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from_bits_le(&rho_bits);
        let rho_squared = rho * rho;

        Ok((
            Self::RW {
                e: cfg_iter!(W1.e)
                    .zip(&t)
                    .zip(&W2.e)
                    .map(|((a, b), c)| rho_squared * c + rho * b + a)
                    .collect(),
                r_e: W1.r_e + r_t * rho + W2.r_e * rho_squared,
                w: cfg_iter!(W1.w)
                    .zip(&W2.w)
                    .map(|(a, b)| rho * b + a)
                    .collect(),
                r_w: W1.r_w + W2.r_w * rho,
            },
            Self::RU {
                cm_e: U1.cm_e + cm_t.mul(rho) + U2.cm_e.mul(rho_squared),
                u: U1.u + rho * U2.u,
                cm_w: U1.cm_w + U2.cm_w.mul(rho),
                x: cfg_iter!(U1.x)
                    .zip(&U2.x)
                    .map(|(a, b)| rho * b + a)
                    .collect(),
            },
            cm_t,
            rho_bits.try_into().unwrap(),
        ))
    }
}

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingSchemeProver<1, 1> for AbstractNova2<VC, TF, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &NovaKey<Self::Arith, VC>,
        transcript: &mut impl Transcript<TF>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        mut rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<1, 1>, Self::Challenge), Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        // Compute the cross term `T` by following the optimized approach in
        // [Mova](https://eprint.iacr.org/2024/1220.pdf)'s section 5.2.
        let v = pk.arith.eval_assignments(AssignmentsOwned::from((
            U.u + VC::Scalar::one(),
            cfg_iter!(U.x).zip(&u[..]).map(|(a, b)| *a + b).collect(),
            cfg_iter!(W.w).zip(&w[..]).map(|(a, b)| *a + b).collect(),
        )))?;
        let t = cfg_into_iter!(v)
            .zip(&W.e)
            .map(|(a, b)| a - b)
            .collect::<Vec<_>>();

        let (cm_w, r_w) = VC::commit(&pk.ck, w, &mut rng)?;

        let (cm_t, r_t) = VC::commit(&pk.ck, &t, &mut rng)?;

        let pi = (cm_w, cm_t);

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(&pi);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from_bits_le(&rho_bits);

        Ok((
            Self::RW {
                e: cfg_iter!(W.e).zip(&t).map(|(a, b)| rho * b + a).collect(),
                r_e: W.r_e + r_t * rho,
                w: cfg_iter!(W.w)
                    .zip(&w[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
                r_w: W.r_w + r_w * rho,
            },
            Self::RU {
                cm_e: U.cm_e + cm_t.mul(rho),
                u: U.u + rho,
                cm_w: U.cm_w + cm_w.mul(rho),
                x: cfg_iter!(U.x)
                    .zip(&u[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
            },
            pi,
            rho_bits.try_into().unwrap(),
        ))
    }
}
