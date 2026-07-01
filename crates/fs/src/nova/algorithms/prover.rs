//! Proof generation for Nova.

use ark_ff::{Field, One};
use ark_std::{borrow::Borrow, cfg_into_iter, cfg_iter, ops::Mul, rand::RngCore};
#[cfg(not(feature = "parallel"))]
use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{field::SonobeField, ops::bits::FromBits},
    arithmetizations::r1cs::R1CS,
    circuits::{Assignments, AssignmentsOwned},
    commitments::GroupBasedCommitment,
    transcripts::Transcript,
};

use crate::{
    Error, FoldingSchemeProver,
    nova::{AbstractNova, NovaKey},
};

fn cross_term<'a, F: Field>(
    arith: &R1CS<F>,
    z1: impl Into<Assignments<F, &'a [F]>>,
    z2: impl Into<Assignments<F, &'a [F]>>,
    #[cfg(feature = "parallel")] e: impl IndexedParallelIterator<Item: Borrow<F>>,
    #[cfg(not(feature = "parallel"))] e: impl Iterator<Item: Borrow<F>>,
) -> Result<Vec<F>, Error> {
    let z1 = z1.into();
    let z2 = z2.into();

    // Compute the cross term `T` by following the optimized approach in
    // [Mova](https://eprint.iacr.org/2024/1220.pdf)'s section 5.2.
    let v = arith.evaluate_r1cs(AssignmentsOwned::from((
        z1.constant + z2.constant,
        cfg_iter!(z1.public)
            .zip_eq(z2.public)
            .map(|(a, b)| *a + b)
            .collect(),
        cfg_iter!(z1.private)
            .zip_eq(z2.private)
            .map(|(a, b)| *a + b)
            .collect(),
    )))?;
    Ok(cfg_into_iter!(v)
        .zip_eq(e)
        .map(|(a, b)| a - b.borrow())
        .collect())
}

impl<CM: GroupBasedCommitment, TF: SonobeField, const B: usize> FoldingSchemeProver<1, 1>
    for AbstractNova<CM, TF, B>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &NovaKey<Self::Arith, CM>,
        transcript: &mut impl Transcript<TF>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<1, 1>), Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        let (z1, z2) = ((U.u, &U.x[..], &W.w[..]), (One::one(), &u.x[..], &w.w[..]));
        let t = cross_term(&pk.arith, z1, z2, cfg_iter!(W.e))?;

        let (cm_t, r_t) = CM::commit(&pk.ck, &t, rng)?;

        let rho_bits = transcript.add(&U).add(&u).add(&cm_t).challenge_bits(B);
        let rho = CM::Scalar::from_bits_le(&rho_bits);

        let WW = Self::RW {
            e: cfg_iter!(W.e)
                .zip_eq(&t)
                .map(|(a, b)| rho * b + a)
                .collect(),
            r_e: W.r_e + r_t * rho,
            w: cfg_iter!(W.w)
                .zip_eq(&w.w)
                .map(|(a, b)| rho * b + a)
                .collect(),
            r_w: W.r_w + w.r_w * rho,
        };
        let UU = Self::RU {
            cm_e: U.cm_e + cm_t.mul(rho),
            u: U.u + rho,
            cm_w: U.cm_w + u.cm_w.mul(rho),
            x: cfg_iter!(U.x)
                .zip_eq(&u.x)
                .map(|(a, b)| rho * b + a)
                .collect(),
        };
        Ok((WW, UU, cm_t))
    }
}

impl<CM: GroupBasedCommitment, TF: SonobeField, const B: usize> FoldingSchemeProver<2, 0>
    for AbstractNova<CM, TF, B>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &NovaKey<Self::Arith, CM>,
        transcript: &mut impl Transcript<TF>,
        [W1, W2]: &[impl Borrow<Self::RW>; 2],
        [U1, U2]: &[impl Borrow<Self::RU>; 2],
        _: &[impl Borrow<Self::IW>; 0],
        _: &[impl Borrow<Self::IU>; 0],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<2, 0>), Error> {
        let (W1, U1) = (W1.borrow(), U1.borrow());
        let (W2, U2) = (W2.borrow(), U2.borrow());

        let (z1, z2) = ((U1.u, &U1.x[..], &W1.w[..]), (U2.u, &U2.x[..], &W2.w[..]));
        let e = cfg_iter!(W1.e).zip_eq(&W2.e).map(|(a, b)| *a + b);
        let t = cross_term(&pk.arith, z1, z2, e)?;

        let (cm_t, r_t) = CM::commit(&pk.ck, &t, rng)?;

        let rho_bits = transcript.add(&(U1, U2)).add(&cm_t).challenge_bits(B);
        let rho = CM::Scalar::from_bits_le(&rho_bits);
        let rho_squared = rho * rho;

        let WW = Self::RW {
            e: cfg_iter!(W1.e)
                .zip_eq(&t)
                .zip_eq(&W2.e)
                .map(|((a, b), c)| rho_squared * c + rho * b + a)
                .collect(),
            r_e: W1.r_e + r_t * rho + W2.r_e * rho_squared,
            w: cfg_iter!(W1.w)
                .zip_eq(&W2.w)
                .map(|(a, b)| rho * b + a)
                .collect(),
            r_w: W1.r_w + W2.r_w * rho,
        };
        let UU = Self::RU {
            cm_e: U1.cm_e + cm_t.mul(rho) + U2.cm_e.mul(rho_squared),
            u: U1.u + rho * U2.u,
            cm_w: U1.cm_w + U2.cm_w.mul(rho),
            x: cfg_iter!(U1.x)
                .zip_eq(&U2.x)
                .map(|(a, b)| rho * b + a)
                .collect(),
        };
        Ok((WW, UU, cm_t))
    }
}
