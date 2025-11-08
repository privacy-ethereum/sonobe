use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, select::CondSelectGadget, GR1CSVar};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{
    fmt::Debug,
    iter::Sum,
    ops::{Add, Mul},
    rand::RngCore,
};
use thiserror::Error;

use crate::{
    circuits::var::Var,
    traits::{SonobeCurve, SonobeField, CF1},
    transcripts::{Absorbable, AbsorbableGadget},
};

pub mod pedersen;
// TODO: add back other commitment schemes

#[derive(Debug, Error)]
pub enum Error {
    // Commitment errors
    #[error("The message being committed to has length {1}, exceeding the maximum supported length ({0})")]
    MessageTooLong(usize, usize),
    #[error("Blinding factor not 0 for Commitment without hiding")]
    BlindingNotZero,
    #[error("Blinding factors incorrect, blinding is set to {0} but blinding values are {1}")]
    IncorrectBlinding(bool, String),
    #[error("Commitment verification failed")]
    CommitmentVerificationFail,
}

pub trait VectorCommitment: 'static + Clone + Debug + PartialEq + Eq {
    const IS_HIDING: bool;

    type Key: Clone;
    type Scalar: Clone + Copy + Default + Debug + PartialEq + Eq + Sync + Absorbable;
    type Commitment: Clone + Default + Debug + PartialEq + Eq + Sync + Absorbable;
    type Randomness: Clone
        + Copy
        + Default
        + Debug
        + PartialEq
        + Eq
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

pub trait GroupBasedVectorCommitment:
    VectorCommitment<Commitment: SonobeCurve, Scalar = CF1<<Self as VectorCommitment>::Commitment>>
{
}

impl<VC> GroupBasedVectorCommitment for VC where
    VC: VectorCommitment<
        Commitment: SonobeCurve,
        Scalar = CF1<<Self as VectorCommitment>::Commitment>,
    >
{
}

pub trait VectorCommitmentGadget: Clone {
    type Native: VectorCommitment;
    type ConstraintField: SonobeField;

    type KeyVar;
    type ScalarVar: Clone
        + GR1CSVar<Self::ConstraintField>
        + EqGadget<Self::ConstraintField>
        + AbsorbableGadget<Self::ConstraintField>
        + CondSelectGadget<Self::ConstraintField>
        + Var<Self::ConstraintField, Native = <Self::Native as VectorCommitment>::Scalar>
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
        + AbsorbableGadget<Self::ConstraintField>
        + CondSelectGadget<Self::ConstraintField>
        + Var<Self::ConstraintField, Native = <Self::Native as VectorCommitment>::Commitment>;
    type RandomnessVar: Var<
        Self::ConstraintField,
        Native = <Self::Native as VectorCommitment>::Randomness,
    >;

    fn open(
        ck: &Self::KeyVar,
        v: &[Self::ScalarVar],
        r: &Self::RandomnessVar,
        cm: &Self::CommitmentVar,
    ) -> Result<(), SynthesisError>;
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
