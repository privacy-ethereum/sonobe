use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, marker::PhantomData, rand::RngCore};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    algebra::ring::{PolynomialRingConfig, PolynomialRingOverField},
    commitments::{CommitmentDef, CommitmentKey, CommitmentOps, Error},
    traits::SonobeField,
    utils::null::Null,
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AjtaiKey<P: PolynomialRingConfig, F: SonobeField, const KAPPA: usize> {
    m: Vec<Vec<PolynomialRingOverField<P, F>>>,
}

impl<P: PolynomialRingConfig, F: SonobeField, const KAPPA: usize> CommitmentKey
    for AjtaiKey<P, F, KAPPA>
{
    fn max_scalars_len(&self) -> usize {
        self.m[0].len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ajtai<P: PolynomialRingConfig, F: SonobeField, const KAPPA: usize> {
    _t: PhantomData<(P, F)>,
}

impl<P: PolynomialRingConfig, F: SonobeField, const KAPPA: usize> CommitmentDef
    for Ajtai<P, F, KAPPA>
{
    const IS_HIDING: bool = false;

    type Key = AjtaiKey<P, F, KAPPA>;

    type Scalar = PolynomialRingOverField<P, F>;
    type Commitment = Vec<PolynomialRingOverField<P, F>>;
    type Randomness = Null;
}

impl<P: PolynomialRingConfig, F: SonobeField, const KAPPA: usize> CommitmentOps
    for Ajtai<P, F, KAPPA>
{
    fn generate_key(len: usize, mut rng: impl RngCore) -> Result<Self::Key, Error> {
        Ok(AjtaiKey {
            m: vec![
                vec![
                    PolynomialRingOverField::element_embedding(
                        (0..P::DEGREE).map(|_| F::rand(&mut rng)).collect()
                    );
                    len
                ];
                KAPPA
            ],
        })
    }

    fn commit(
        ck: &Self::Key,
        v: &[Self::Scalar],
        _rng: impl RngCore,
    ) -> Result<(Self::Commitment, Null), Error> {
        Ok((
            cfg_iter!(ck.m)
                .map(|row| {
                    let mut sum = PolynomialRingOverField::default();
                    for (a, b) in row.iter().zip(v) {
                        sum = sum.add(&a.mul(b));
                    }
                    sum
                })
                .collect(),
            Null,
        ))
    }

    fn open(
        ck: &Self::Key,
        v: &[Self::Scalar],
        _r: &Null,
        cm: &Self::Commitment,
    ) -> Result<(), Error> {
        (&cfg_iter!(ck.m)
            .map(|row| {
                let mut sum = PolynomialRingOverField::default();
                for (a, b) in row.iter().zip(v) {
                    sum = sum.add(&a.mul(b));
                }
                sum
            })
            .collect::<Vec<_>>()
            == cm)
            .then_some(())
            .ok_or(Error::CommitmentVerificationFail)
    }
}
