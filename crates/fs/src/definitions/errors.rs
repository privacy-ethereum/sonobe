//! Error definitions for folding schemes.

use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    arithmetizations::Error as ArithError, commitments::Error as CommitmentError,
    sumcheck::Error as SumCheckError,
};
use thiserror::Error;

/// [`Error`] enumerates possible errors during folding scheme operations.
#[derive(Debug, Error)]
pub enum Error {
    /// [`Error::ArithError`] indicates an error from the underlying constraint
    /// system.
    #[error(transparent)]
    ArithError(#[from] ArithError),
    /// [`Error::CommitmentError`] indicates an error from the underlying
    /// commitment scheme.
    #[error(transparent)]
    CommitmentError(#[from] CommitmentError),
    /// [`Error::SynthesisError`] indicates an error during constraint
    /// synthesis.
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    /// [`Error::SumCheckError`] indicates an error from the underlying sumcheck
    /// protocol.
    #[error(transparent)]
    SumCheckError(#[from] SumCheckError),
    /// [`Error::Unsupported`] indicates that a certain use case is not
    /// supported.
    #[error("Unsupported use case: {0}")]
    Unsupported(String),
    /// [`Error::DomainCreationFailure`] indicates a failure in creating
    /// evaluation domains.
    #[error("Failed to create domain")]
    DomainCreationFailure,
    /// [`Error::IndivisibleByVanishingPoly`] indicates that a polynomial is
    /// not divisible by the vanishing polynomial of a certain domain.
    #[error("Indivisible by vanishing polynomial")]
    IndivisibleByVanishingPoly,
    /// [`Error::UnsatisfiedRelation`] indicates that a certain relation is not
    /// satisfied.
    #[error("Unsatisfied relation: {0}")]
    UnsatisfiedRelation(String),
    /// [`Error::InvalidPublicParameters`] indicates that the provided public
    /// parameters are invalid.
    #[error("Invalid public parameters: {0}")]
    InvalidPublicParameters(String),
}
