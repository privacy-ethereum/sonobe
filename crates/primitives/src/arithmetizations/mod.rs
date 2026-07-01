//! This module defines and implements traits for arithmetizations, also known
//! as constraint systems.
//!
//! In Sonobe, we currently support two constraint systems: the Rank-1
//! Constraint System (R1CS) and the Customizable Constraint System (CCS).
//! However, user circuits are always synthesized into R1CS currently, since
//! R1CS is the only supported constraint system by ark-relations.

use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, log2};
use thiserror::Error;

use crate::relations::{Relation, RelationGadget};

pub mod ccs;
pub mod r1cs;

/// [`Error`] enumerates possible errors during arithmetization operations.
#[derive(Error, Debug)]
pub enum Error {
    /// [`Error::MalformedAssignments`] indicates that the provided assignments
    /// have incorrect shape.
    #[error("The provided assignments have incorrect shape: {0}")]
    MalformedAssignments(String),
    /// [`Error::UnsatisfiedAssignments`] indicates that the provided
    /// assignments do not satisfy the constraint system.
    #[error("The provided assignments do not satisfy the constraint system: {0}")]
    UnsatisfiedAssignments(String),
    /// [`Error::InvalidNumberOfConstraints`] indicates that the constraint
    /// system's number of constraints does not match the provided config.
    #[error(
        "The number of constraints in the constraint system configuration is invalid. Provided: {0}, expected: {1}"
    )]
    InvalidNumberOfConstraints(usize, usize),
    /// [`Error::InvalidNumberOfVariables`] indicates that the constraint
    /// system's number of variables does not match the provided config.
    #[error(
        "The number of variables in the constraint system configuration is invalid. Provided: {0}, expected: {1}"
    )]
    InvalidNumberOfVariables(usize, usize),
    /// [`Error::SynthesisError`] indicates an error during constraint
    /// synthesis.
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
}

/// [`ArithConfig`] describes the configuration of a constraint system.
#[derive(Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArithConfig {
    /// [`ArithConfig::degree`] specifies the degree of the constraint system.
    pub degree: usize,

    /// [`ArithConfig::n_constraints`] specifies the number of constraints in
    /// the constraint system.
    pub n_constraints: usize,

    /// [`ArithConfig::n_variables`] specifies the number of variables in the
    /// constraint system.
    pub n_variables: usize,

    /// [`ArithConfig::n_public_inputs`] specifies the number of public inputs
    /// in the constraint system.
    pub n_public_inputs: usize,

    /// [`ArithConfig::n_witnesses`] specifies the number of witnesses in the
    /// constraint system.
    pub n_witnesses: usize,
}

impl ArithConfig {
    /// [`ArithConfig::log_constraints`] returns the base-2 logarithm of the
    /// number of constraints in the constraint system.
    pub fn log_constraints(&self) -> usize {
        log2(self.n_constraints) as usize
    }
}

/// [`Arith`] is a trait for constraint systems (R1CS, CCS, etc.), where we
/// define methods to get and set configuration about the constraint system.
/// In addition to the configuration, the implementor of this trait may also
/// store the actual constraints and other information.
pub trait Arith: Clone + Default + Send + Sync + CanonicalSerialize + CanonicalDeserialize {
    /// [`Arith::config`] returns the configuration of the constraint system.
    fn config(&self) -> ArithConfig;
}

pub trait ArithGadget: AllocVar<Self::Widget, Self::ConstraintField> {
    type ConstraintField: Field;

    type Widget: Arith;
}

/// [`ArithRelation`] treats a constraint system as a relation between a witness
/// of type `W` and an instance of type `U`, and in this trait, we separate the
/// relation check into two steps: evaluating the constraint system and checking
/// the evaluation result.
///
/// Note that `W` and `U` are part of the trait parameters instead of associated
/// types, because the same constraint system may support different types of `W`
/// and `U`, and the satisfiability check may vary.
/// This "same constraint system, different witness-instance pair" abstraction
/// turns out to be very flexible, as one constraint system struct now can have
/// many different relation checks depending on the context.
///
/// For example, some folding schemes consider a variant of R1CS known as
/// relaxed R1CS, which is also represented by the `A`, `B`, and `C` matrices
/// but has a different relation check compared to plain R1CS.
/// We handle their similarities and differences in the following way:
/// - Since the structure of relaxed R1CS is exactly the same as plain R1CS, we
///   use a single R1CS struct to represent both of them.
/// - To distinguish their relation checks, we instead use distinct types of `W`
///   and `U`.
///     - For plain R1CS, we use plain witness `W = w` and instance `U = x` that
///       are simply vectors of field elements.
///       The implementation of `ArithRelation` for such `W` and `U` then checks
///       if `Az ∘ Bz = Cz`, where `z = [1, x, w]`.
///     - For relaxed R1CS, we use relaxed witness `W` and relaxed instance `U`
///       that contain extra data such as the error or slack terms, e.g.,
///         - In Nova, `W = (w, e, ...)`, `U = (u, x, ...)`.
///           The implementation of `ArithRelation` for such `W` and `U` checks
///           if `Az ∘ Bz = uCz + e`, where `z = [u, x, w]`.
///         - In ProtoGalaxy, `W = (w, ...)`, `U = (x, e, β, ...)`.
///           The implementation of `ArithRelation` for such `W` and `U` checks
///           if `e = Σ pow_i(β) v_i`, where `v = Az ∘ Bz - Cz`,`z = [1, x, w]`.
///
/// This is also the case for CCS, where `W` and `U` may be vectors of field
/// elements or running / incoming witness-instance pairs of different folding
/// schemes such as HyperNova.
pub trait ArithRelation<W: ?Sized, U: ?Sized>: Arith {
    /// [`ArithRelation::Evaluation`] defines the type of the evaluation result
    /// returned by [`ArithRelation::eval_relation`], and consumed by
    /// [`ArithRelation::check_evaluation`].
    ///
    /// The evaluation result is usually a vector of field elements.
    /// However, we use an associated type to represent the evaluation result
    /// for future extensions.
    type Evaluation;

    /// [`ArithRelation::eval_relation`] evaluates the constraint system at
    /// witness `w` and instance `u`. It returns the evaluation result.
    ///
    /// For instance:
    /// - Evaluating the plain R1CS at `W = w` and `U = x` returns
    ///   `Az ∘ Bz - Cz`, where `z = [1, x, w]`.
    /// - Evaluating the relaxed R1CS in Nova at `W = (w, e, ...)` and
    ///   `U = (u, x, ...)` returns `Az ∘ Bz - uCz`, where `z = [u, x, w]`.
    /// - Evaluating the relaxed R1CS in ProtoGalaxy at `W = (w, ...)` and
    ///   `U = (x, e, β, ...)` returns `Az ∘ Bz - Cz`, where `z = [1, x, w]`.
    fn eval_relation(&self, w: &W, u: &U) -> Result<Self::Evaluation, Error>;

    /// [`ArithRelation::check_evaluation`] checks if the evaluation result is
    /// valid. The witness `w` and instance `u` are also parameters, because the
    /// validity check may need information contained in `w` and/or `u`.
    ///
    /// For instance:
    /// - The evaluation `v` of plain R1CS at satisfying `W` and `U` should be
    ///   an all-zero vector.
    /// - The evaluation `v` of relaxed R1CS in Nova at satisfying `W` and `U`
    ///   should be equal to the error term `e` in `W`.
    /// - The evaluation `v` of relaxed R1CS in ProtoGalaxy at satisfying `W`
    ///   and `U` should satisfy `e = Σ pow_i(β) v_i`, where `e` is the error
    ///   term in `U`.
    fn check_evaluation(w: &W, u: &U, v: Self::Evaluation) -> Result<(), Error>;
}

impl<W, U, A: ArithRelation<W, U>> Relation<W, U> for A {
    type Error = Error;

    fn check_relation(&self, w: &W, u: &U) -> Result<(), Self::Error> {
        // `check_relation` is implemented by combining `eval_relation` and
        // `check_evaluation`.
        let e = self.eval_relation(w, u)?;
        Self::check_evaluation(w, u, e)
    }
}

/// [`ArithRelationGadget`] defines the in-circuit gadget for constraint system
/// operations in the same way as [`ArithRelation`].
pub trait ArithRelationGadget<WVar, UVar>: ArithGadget {
    /// [`ArithRelationGadget::Evaluation`] defines the type of the evaluation
    /// result returned by [`ArithRelationGadget::eval_relation`], and consumed
    /// by [`ArithRelationGadget::check_evaluation`].
    type Evaluation;

    /// [`ArithRelationGadget::eval_relation`] evaluates the constraint system
    /// at witness `w` and instance `u`. It returns the evaluation result.
    fn eval_relation(&self, w: &WVar, u: &UVar) -> Result<Self::Evaluation, SynthesisError>;

    /// [`ArithRelationGadget::check_evaluation`] checks if the evaluation
    /// result is valid under the help of the witness `w` and instance `u`.
    fn check_evaluation(w: &WVar, u: &UVar, e: Self::Evaluation) -> Result<(), SynthesisError>;
}

impl<WVar, UVar, A: ArithRelationGadget<WVar, UVar>> RelationGadget<WVar, UVar> for A {
    fn check_relation(&self, w: &WVar, u: &UVar) -> Result<(), SynthesisError> {
        // `check_relation` is implemented by combining `eval_relation` and
        // `check_evaluation`.
        let e = self.eval_relation(w, u)?;
        Self::check_evaluation(w, u, e)
    }
}
