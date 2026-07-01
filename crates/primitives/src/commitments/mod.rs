//! Abstract traits and implementations for commitment schemes.

use ark_ff::UniformRand;
use ark_r1cs_std::{
    GR1CSVar, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, select::CondSelectGadget,
};
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    fmt::Debug,
    iter::Sum,
    ops::{Add, Mul},
    rand::RngCore,
};
use thiserror::Error;

use crate::{
    algebra::{
        Val,
        field::{SonobeField, TwoStageFieldVar, emulated::EmulatedFieldVar},
        group::{CF1, CF2, SonobeCurve, emulated::EmulatedAffineVar},
        ops::bits::FromBitsGadget,
    },
    circuits::inputize::Inputize,
    transcripts::{Absorbable, AbsorbableVar},
};

pub mod pedersen;
// TODO: add back other commitment schemes

/// [`Error`] enumerates possible errors during commitment operations.
#[derive(Debug, Error)]
pub enum Error {
    /// [`Error::MessageTooLong`] indicates that the message being committed to
    /// is longer than the maximum supported length.
    #[error(
        "The message being committed to has length {1}, exceeding the maximum supported length ({0})"
    )]
    MessageTooLong(usize, usize),
    /// [`Error::CommitmentVerificationFail`] indicates that the provided
    /// opening does not verify against the commitment.
    #[error("Commitment verification failed")]
    CommitmentVerificationFail,
}

/// [`CommitmentKey`] represents a commitment key (e.g., a vector of group
/// generators for many group-based commitment schemes).
pub trait CommitmentKey: Clone + Send + Sync + CanonicalSerialize + CanonicalDeserialize {
    /// [`CommitmentKey::max_scalars_len`] returns the maximum number of scalars
    /// that can be committed to with this key.
    fn max_scalars_len(&self) -> usize;
}

/// [`CommitmentDef`] provides the core type definitions of a commitment scheme,
/// defining the types of relevant cryptographic objects such as the commitment
/// key, scalars, commitments, and randomness.
pub trait CommitmentDef: 'static + Clone + Debug + PartialEq + Eq {
    /// [`CommitmentDef::IS_HIDING`] indicates whether the commitment scheme has
    /// the hiding property.
    const IS_HIDING: bool;

    /// [`CommitmentDef::Key`] is the type of the commitment key.
    type Key: CommitmentKey;
    /// [`CommitmentDef::Scalar`] is the type of the scalars being committed to.
    ///
    /// For generality, we do not restrict this to field elements and instead
    /// only bound it by necessary traits.
    type Scalar: Clone + Copy + Default + Debug + PartialEq + Eq + Sync + Absorbable + UniformRand;
    /// [`CommitmentDef::Commitment`] is the type of the commitment.
    ///
    /// In the future we may introduce other commitment schemes such as those
    /// based on hash functions or lattices, so we do not restrict this to be
    /// group elements.
    type Commitment: Clone + Default + Debug + PartialEq + Eq + Sync + Absorbable;
    /// [`CommitmentDef::Randomness`] is the type of the randomness used in
    /// the commitment.
    ///
    /// Hiding commitment schemes and non-hiding schemes may have different
    /// randomness types, e.g., the former holds real data, while the latter
    /// is just a placeholder type.
    ///
    /// In this way, we can leverage the compiler to reject misuse, e.g., using
    /// randomness where it is not needed, or vice versa, with a unified API.
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
}

/// [`CommitmentOps`] defines algorithms for commitment schemes.
pub trait CommitmentOps: CommitmentDef {
    /// [`CommitmentOps::generate_key`] defines the key generation algorithm,
    /// which is a randomized algorithm that takes as input the maximum length
    /// `len` of supported messages, and a randomness source `rng`, and outputs
    /// the commitment key.
    fn generate_key(len: usize, rng: impl RngCore) -> Result<Self::Key, Error>;

    /// [`CommitmentOps::commit`] defines the commitment generation algorithm,
    /// which is a (probably) randomized algorithm that takes as input
    /// commitment key `ck`, a vector of scalars `v` to be committed to, and a
    /// randomness source `rng`, and outputs the commitment and the randomness.
    fn commit(
        ck: &Self::Key,
        v: &[Self::Scalar],
        rng: impl RngCore,
    ) -> Result<(Self::Commitment, Self::Randomness), Error>;

    /// [`CommitmentOps::open`] defines the commitment opening algorithm, which
    /// is a deterministic algorithm that takes as input commitment key `ck`,
    /// a vector of scalars `v`, the randomness `r`, and a commitment `cm`, and
    /// outputs `Ok(())` if the opening verifies, or an error otherwise.
    fn open(
        ck: &Self::Key,
        v: &[Self::Scalar],
        r: &Self::Randomness,
        cm: &Self::Commitment,
    ) -> Result<(), Error>;
}

/// [`CommitmentDefGadget`] specifies the in-circuit associated types for a
/// commitment scheme gadget.
pub trait CommitmentDefGadget: Clone {
    /// [`CommitmentDefGadget::ConstraintField`] is the field over which the
    /// circuit running the commitment scheme is defined.
    type ConstraintField: SonobeField;

    /// [`CommitmentDefGadget::KeyVar`] is the in-circuit variable type for the
    /// commitment key.
    type KeyVar: AllocVar<<Self::Widget as CommitmentDef>::Key, Self::ConstraintField>;
    /// [`CommitmentDefGadget::ScalarVar`] is the in-circuit variable type for
    /// the scalars being committed to.
    type ScalarVar: AbsorbableVar<Self::ConstraintField>
        + CondSelectGadget<Self::ConstraintField>
        + EqGadget<Self::ConstraintField>
        + FromBitsGadget<Self::ConstraintField>
        + TwoStageFieldVar<
            ConstraintField = Self::ConstraintField,
            ValueField = <Self::Widget as CommitmentDef>::Scalar,
        >;
    /// [`CommitmentDefGadget::CommitmentVar`] is the in-circuit variable type
    /// for the commitment.
    type CommitmentVar: Clone
        + AbsorbableVar<Self::ConstraintField>
        + CondSelectGadget<Self::ConstraintField>
        + AllocVar<<Self::Widget as CommitmentDef>::Commitment, Self::ConstraintField>
        + GR1CSVar<Self::ConstraintField, Value = <Self::Widget as CommitmentDef>::Commitment>
        + Inputize<Self::ConstraintField>;
    /// [`CommitmentDefGadget::RandomnessVar`] is the in-circuit variable type
    /// for the randomness used in the commitment.
    type RandomnessVar: AllocVar<<Self::Widget as CommitmentDef>::Randomness, Self::ConstraintField>
        + GR1CSVar<Self::ConstraintField, Value = <Self::Widget as CommitmentDef>::Randomness>;

    /// [`CommitmentDefGadget::Widget`] points to the out-of-circuit commitment
    /// scheme widget.
    type Widget: CommitmentDef;
}

/// [`CommitmentOpsGadget`] defines algorithms (majorly the opening algorithm)
/// for commitment schemes in-circuit.
pub trait CommitmentOpsGadget: CommitmentDefGadget<Widget: CommitmentOps> {
    /// [`CommitmentOpsGadget::open`] defines the commitment opening gadget
    /// that matches its out-of-circuit widget [`CommitmentOps::open`].
    fn open(
        ck: &Self::KeyVar,
        v: &[Self::ScalarVar],
        r: &Self::RandomnessVar,
        cm: &Self::CommitmentVar,
    ) -> Result<(), SynthesisError>;
}

/// [`GroupBasedCommitment`] is a variant of commitment schemes built on groups
/// (elliptic curves).
pub trait GroupBasedCommitment:
    CommitmentDef<Commitment: SonobeCurve, Scalar = CF1<<Self as CommitmentDef>::Commitment>>
    + CommitmentOps
{
    /// [`GroupBasedCommitment::Gadget1`] points to the in-circuit gadget for
    /// the group-based commitment scheme over the curve's base field.
    type Gadget1: CommitmentOpsGadget<
            ConstraintField = CF2<Self::Commitment>,
            ScalarVar = EmulatedFieldVar<CF2<Self::Commitment>, Self::Scalar>,
            CommitmentVar = <Self::Commitment as Val>::Var,
            Widget = Self,
        >;
    /// [`GroupBasedCommitment::Gadget2`] points to the in-circuit gadget for
    /// the group-based commitment scheme over the curve's scalar field.
    type Gadget2: CommitmentOpsGadget<
            ConstraintField = Self::Scalar,
            ScalarVar = FpVar<Self::Scalar>,
            CommitmentVar = EmulatedAffineVar<Self::Scalar, Self::Commitment>,
            Widget = Self,
        >;
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::error::Error;

    use super::*;

    pub fn test_commitment_correctness<CM: CommitmentOps>(
        mut rng: impl RngCore,
        len: usize,
    ) -> Result<(), Box<dyn Error>> {
        let v = (0..len)
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();

        let ck = CM::generate_key(len, &mut rng)?;
        let (cm, r) = CM::commit(&ck, &v, &mut rng)?;
        CM::open(&ck, &v, &r, &cm)?;
        Ok(())
    }

    pub fn test_commitment_gadget_correctness<CM: CommitmentOpsGadget>(
        mut rng: impl RngCore,
        len: usize,
    ) -> Result<(), Box<dyn Error>> {
        let v = (0..len)
            .map(|_| UniformRand::rand(&mut rng))
            .collect::<Vec<_>>();

        let ck = CM::Widget::generate_key(len, &mut rng)?;
        let (cm, r) = CM::Widget::commit(&ck, &v, &mut rng)?;

        let cs = ConstraintSystem::new_ref();

        let v_var = Vec::new_witness(cs.clone(), || Ok(v))?;
        let r_var = AllocVar::new_witness(cs.clone(), || Ok(r))?;
        let ck_var = AllocVar::new_constant(cs.clone(), ck)?;
        let cm_var = AllocVar::new_witness(cs.clone(), || Ok(cm))?;

        CM::open(&ck_var, &v_var, &r_var, &cm_var)?;

        assert!(cs.is_satisfied()?);

        Ok(())
    }
}
