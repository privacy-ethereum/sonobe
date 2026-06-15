use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_poly::{DenseMultilinearExtension as MLE, MultilinearExtension};
use ark_std::{
    borrow::Borrow, cfg_into_iter, cfg_iter, marker::PhantomData, ops::Mul, rand::RngCore,
};
#[cfg(not(feature = "parallel"))]
use itertools::Itertools;
use num_bigint::{BigInt, BigUint, Sign};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{
        field::SonobeField,
        ops::{bits::FromBits, pow::Pow},
        ring::{PolynomialRingConfig, PolynomialRingOverField},
    },
    arithmetizations::{ArithRelation, ccs::CCS, r1cs::R1CS},
    circuits::{Assignments, AssignmentsOwned},
    commitments::{CommitmentOps, GroupBasedCommitment},
    sumcheck::{
        SumCheck,
        utils::{EqPoly, VPAuxInfo, VirtualPolynomial},
    },
    traits::SonobePrimeField,
    transcripts::Transcript,
    utils::null::Null,
};

use crate::{
    Error, FoldingSchemeProver,
    nova::AbstractNova,
    superneo::{SuperNeo, SuperNeoConfig, keys::SuperNeoKey},
};

pub fn extend_mle_field<K: ark_ff::Field>(mle: MLE<K::BasePrimeField>) -> MLE<K> {
    let MLE {
        num_vars,
        evaluations,
    } = mle;

    MLE {
        num_vars: num_vars,
        evaluations: evaluations
            .into_iter()
            .map(K::from_base_prime_field)
            .collect(),
    }
}

pub fn decompose<F: PrimeField>(v: F, b: usize) -> Vec<i8> {
    let base = b;
    assert!(base <= 128);

    let m = F::MODULUS.into();
    let mut l = m.to_radix_le(base as u32).len();
    if BigUint::from(base).pow(l as u32 - 1) == m {
        l -= 1;
    }

    let x = v.into_bigint();
    let mut y: BigUint = x.into();
    if x > F::MODULUS_MINUS_ONE_DIV_TWO {
        y = m - y;
        let mut result = y.to_radix_le(base as u32);
        assert!(result.len() <= l);
        result.resize(l, 0);
        result.into_iter().map(|i| -(i as i8)).collect()
    } else {
        let mut result = y.to_radix_le(base as u32);
        assert!(result.len() <= l);
        result.resize(l, 0);
        result.into_iter().map(|i| i as i8).collect()
    }
}

pub fn decompose2<F: PrimeField>(v: F, b: usize, l: usize) -> Vec<i8> {
    let base = b;

    let x = v.into_bigint();
    let mut y: BigUint = x.into();
    if x > F::MODULUS_MINUS_ONE_DIV_TWO {
        y = F::MODULUS.into() - y;
        let mut result = y.to_radix_le(base as u32);
        assert!(result.len() <= l);
        result.resize(l, 0);
        result.into_iter().map(|i| -(i as i8)).collect()
    } else {
        let mut result = y.to_radix_le(base as u32);
        assert!(result.len() <= l);
        result.resize(l, 0);
        result.into_iter().map(|i| i as i8).collect()
    }
}
