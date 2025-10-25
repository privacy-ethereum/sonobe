use ark_ff::Field;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    iter::Sum,
    ops::{Add, Mul},
    rand::RngCore,
};
use thiserror::Error;

pub mod pedersen;
// TODO: add back other commitment schemes

#[derive(Debug, Error)]
pub enum Error {
    // Commitment errors
    #[error("The message being committed to has length {1}, exceeding the maximum supported length of {0}"
    )]
    MessageTooLong(usize, usize),
    #[error("Blinding factor not 0 for Commitment without hiding")]
    BlindingNotZero,
    #[error("Blinding factors incorrect, blinding is set to {0} but blinding values are {1}")]
    IncorrectBlinding(bool, String),
    #[error("Commitment verification failed")]
    CommitmentVerificationFail,
}

pub trait VectorCommitment: 'static + Debug + PartialEq {
    const IS_HIDING: bool;

    type Key;
    type Scalar: Clone + Copy + Debug + PartialEq + Sync;
    type Commitment: Default + Debug + PartialEq + Sync;
    type Randomness: Clone
        + Copy
        + Default
        + Debug
        + Sync
        + Add<Self::Scalar, Output = Self::Randomness>
        + Mul<Self::Scalar, Output = Self::Randomness>
        + for<'a> Add<&'a Self::Scalar, Output = Self::Randomness>
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Randomness>
        + Add<Output = Self::Randomness>
        + Mul<Output = Self::Randomness>
        + Sum;

    fn generate_key(rng: impl RngCore, len: usize) -> Result<Self::Key, Error>;

    fn commit(
        ck: &Self::Key,
        v: &[Self::Scalar],
        rng: impl RngCore,
    ) -> Result<(Self::Commitment, Self::Randomness), Error>;

    fn open(
        ck: &Self::Key,
        v: &[Self::Scalar],
        r: &Self::Randomness,
        cm: &Self::Commitment,
    ) -> Result<bool, Error>;
}

pub trait VectorCommitmentGadget {
    type Native: VectorCommitment;
    type ConstraintField: Field;

    type KeyVar;
    type ScalarVar: Clone
        + AllocVar<<Self::Native as VectorCommitment>::Scalar, Self::ConstraintField>
        + Add<Output = Self::IntermediateScalarVar>
        + for<'a> Add<&'a Self::ScalarVar, Output = Self::IntermediateScalarVar>
        + Mul<Output = Self::IntermediateScalarVar>
        + for<'a> Mul<&'a Self::ScalarVar, Output = Self::IntermediateScalarVar>;
    type IntermediateScalarVar: Clone
        + TryInto<Self::ScalarVar>
        + Add<Output = Self::IntermediateScalarVar>
        + for<'a> Add<&'a Self::IntermediateScalarVar, Output = Self::IntermediateScalarVar>
        + Mul<Output = Self::IntermediateScalarVar>
        + for<'a> Mul<&'a Self::IntermediateScalarVar, Output = Self::IntermediateScalarVar>
        + Add<Self::ScalarVar, Output = Self::IntermediateScalarVar>
        + for<'a> Add<&'a Self::ScalarVar, Output = Self::IntermediateScalarVar>
        + Mul<Self::ScalarVar, Output = Self::IntermediateScalarVar>
        + for<'a> Mul<&'a Self::ScalarVar, Output = Self::IntermediateScalarVar>;
    type CommitmentVar: Clone
        + AllocVar<<Self::Native as VectorCommitment>::Commitment, Self::ConstraintField>;
    type RandomnessVar: AllocVar<
        <Self::Native as VectorCommitment>::Randomness,
        Self::ConstraintField,
    >;

    fn open(
        ck: &Self::KeyVar,
        v: &[Self::ScalarVar],
        r: &Self::RandomnessVar,
        cm: &Self::CommitmentVar,
    ) -> Result<(), SynthesisError>;
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Null;

impl<F> Add<F> for Null {
    type Output = Null;

    fn add(self, _: F) -> Null {
        Null
    }
}

impl<F> Add<F> for &Null {
    type Output = Null;

    fn add(self, _: F) -> Null {
        Null
    }
}

impl<F> Mul<F> for Null {
    type Output = Self;

    fn mul(self, _: F) -> Null {
        Null
    }
}

impl<F> Mul<F> for &Null {
    type Output = Null;

    fn mul(self, _: F) -> Null {
        Null
    }
}

impl Sum for Null {
    fn sum<I: Iterator<Item = Self>>(_: I) -> Self {
        Null
    }
}

impl<F: Field> AllocVar<Null, F> for Null {
    fn new_variable<T: Borrow<Null>>(
        _cs: impl Into<Namespace<F>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use ark_std::error::Error;

    use super::*;

    pub fn test_commitment_correctness<VC: VectorCommitment<Scalar: UniformRand>>(
        mut rng: impl RngCore,
        len: usize,
    ) -> Result<(), Box<dyn Error>> {
        let v = (0..len)
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();

        let ck = VC::generate_key(&mut rng, len)?;
        let (cm, r) = VC::commit(&ck, &v, &mut rng)?;
        assert!(VC::open(&ck, &v, &r, &cm)?);
        Ok(())
    }
}
