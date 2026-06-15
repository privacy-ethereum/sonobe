#![warn(missing_docs)]

//! Incremental Verifiable Computation (IVC) abstractions.
//!
//! This crate provides the [`IVC`] trait, which describes the common
//! interface for all IVC constructions, and [compilers] that turn a folding
//! scheme into a full IVC scheme.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::SerializationError;
use ark_std::{error::Error as ErrorTrait, rand::RngCore};
use sonobe_fs::Error as FoldingError;
use sonobe_primitives::{arithmetizations::Error as ArithError, circuits::FCircuit, traits::Dummy};
use thiserror::Error;

pub mod compilers;

/// [`Error`] enumerates possible errors during the IVC operations.
#[derive(Debug, Error)]
pub enum Error {
    /// [`Error::ArithError`] indicates an error from the underlying constraint
    /// system.
    #[error(transparent)]
    ArithError(#[from] ArithError),
    /// [`Error::SerializationError`] indicates an error during serialization.
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    /// [`Error::FoldingError`] indicates an error from the underlying folding
    /// scheme.
    #[error(transparent)]
    FoldingError(#[from] FoldingError),
    /// [`Error::SynthesisError`] indicates an error during constraint
    /// synthesis.
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    /// [`Error::IVCVerificationFail`] indicates that the IVC verification has
    /// failed.
    #[error("IVC verification failed")]
    IVCVerificationFail,
}

/// [`IVCTypes`] defines the associated types for an IVC scheme.
pub trait IVCTypes {
    /// [`IVCTypes::Field`] defines the field over which the IVC scheme operates.
    type Field: PrimeField;

    /// [`IVCTypes::Config`] defines the configuration of IVC.
    ///
    /// ### Examples
    ///
    /// In folding-based IVC schemes, this is usually the configuration of the
    /// underlying folding scheme.
    type Config;

    /// [`IVCTypes::PublicParam`] defines the public parameters of IVC.
    type PublicParam;

    /// [`IVCTypes::ProverKey`] defines the prover key of IVC.
    ///
    /// ### Design Rationale
    ///
    /// It is parameterized by the step circuit type `FC`, because the one
    /// prover key can only be used for one step circuit, and different step
    /// circuits require different prover keys.
    /// With `FC`, we can prevent the misuse of keys on the type level.
    type ProverKey<FC>;

    /// [`IVCTypes::VerifierKey`] defines the verifier key of IVC.
    ///
    /// ### Design Rationale
    ///
    /// It is parameterized by the step circuit type `FC`, because the one
    /// verifier key can only be used for one step circuit, and different step
    /// circuits require different verifier keys.
    /// With `FC`, we can prevent the misuse of keys on the type level.
    type VerifierKey<FC>;

    /// [`IVCTypes::Proof`] defines the proof of IVC.
    ///
    /// ### Design Rationale
    ///
    /// It is parameterized by the step circuit type `FC`, because it might be
    /// problematic if the prover generates a proof for one step circuit but the
    /// verifier expects a proof for another step circuit.
    /// With `FC`, we can prevent such inconsistencies on the type level.
    ///
    /// It should also implement `Dummy`, so that we can generate an initial
    /// proof from the prover key in a uniform way across different IVC schemes.
    type Proof<FC>: for<'a> Dummy<&'a Self::ProverKey<FC>>;
}

/// [`IVCPreprocessor`] defines the preprocessing algorithm of IVC.
pub trait IVCPreprocessor: IVCTypes {
    /// [`IVCPreprocessor::preprocess`] is a randomized algorithm that generates
    /// public parameters for the IVC scheme under a given configuration.
    ///
    /// ### Function Signature
    ///
    /// [`IVCPreprocessor::preprocess`] takes as input
    /// - `config`: the configuration for the IVC scheme, and
    /// - `rng`: the randomness source.
    ///
    /// It returns
    /// - an error if the preprocessing fails, or
    /// - `Ok(pp)` otherwise, where
    ///   - `pp`: the public parameters.
    ///
    /// ### Usage
    ///
    /// See [`IVC`] for an example of how to use this method in the context of a
    /// full IVC workflow.
    ///
    /// ### Notes
    ///
    /// - The security parameter is implicitly specified by the underlying
    ///   mathematical structures (e.g., field/group orders) and the algorithms
    ///   involved in the implementation.
    /// - This is usually called once for one configuration
    /// - The same public parameters can be reused for different step circuits,
    ///   as long as they conform to the configuration.
    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;
}

/// [`IVCKeyGenerator`] defines the key generation algorithm of IVC.
pub trait IVCKeyGenerator: IVCTypes {
    /// [`IVCKeyGenerator::generate_keys`] is a deterministic algorithm that
    /// generates a pair of prover and verifier keys for a given step circuit.
    ///
    /// ### Function Signature
    ///
    /// [`IVCKeyGenerator::generate_keys`] takes as input
    /// - `pp`: the public parameters, and
    /// - `step_circuit`: the step circuit.
    ///
    /// It outputs
    /// - an error if the key generation fails, or
    /// - `Ok((pk, vk))` otherwise, where
    ///   - `pk`: the prover key, and
    ///   - `vk`: the verifier key.
    ///
    /// ### Usage
    ///
    /// See [`IVC`] for an example of how to use this method in the context of a
    /// full IVC workflow.
    ///
    /// ### Notes
    ///
    /// - This is usually called once for one step circuit.
    /// - The same prover and verifier keys can be reused for different initial
    ///   states and external inputs, as long as the step circuit is the same.
    #[allow(clippy::type_complexity)]
    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        pp: Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), Error>;
}

/// [`IVCProver`] defines the proof generation algorithm of IVC.
pub trait IVCProver: IVCTypes {
    /// [`IVCProver::prove`] is a (probably) randomized algorithm that proves
    /// the (next) state is correctly derived from the initial state after
    /// invoking the step circuit for the claimed number of steps.
    /// Proof generation is done by executing the step circuit on the current
    /// state to obtain the next state, and then updating an existing proof for
    /// the current state to a new proof for the next state.
    ///
    /// ### Function Signature
    ///
    /// [`IVCProver::prove`] takes as input
    /// - `pk`: the prover key,
    /// - `step_circuit`: the step circuit,
    /// - `i`: the current step,
    /// - `initial_state`: the initial state,
    /// - `current_state`: the current state,
    /// - `external_inputs`: the external inputs,
    /// - `current_proof`: the current proof attesting that `current_state` is
    ///   correctly derived from `initial_state` after `i` executions of
    ///   `step_circuit`, and
    /// - `rng`: the randomness source.
    ///
    /// It outputs
    /// - an error if the proof generation fails, or
    /// - `Ok((next_state, external_outputs, next_proof))` otherwise, where
    ///   - `next_state`: the next state,
    ///   - `external_outputs`: the external outputs, and
    ///   - `next_proof`: the next proof attesting that `next_state` is
    ///     correctly derived from `initial_state` after `i+1` executions of
    ///     `step_circuit`.
    ///
    /// ### Usage
    ///
    /// See [`IVC`] for an example of how to use this method in the context of a
    /// full IVC workflow.
    ///
    /// ### Design Rationale
    ///
    /// `external_inputs` is needed by [`IVCProver::prove`] since it is one of
    /// the inputs to [`FCircuit::synthesize_step`].
    ///
    /// Similarly, [`FCircuit::synthesize_step`] returns `external_outputs`, and
    /// it needs to be returned by [`IVCProver::prove`] so that the caller can
    /// use it.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn prove<FC: FCircuit<Field = Self::Field>>(
        pk: &Self::ProverKey<FC>,
        step_circuit: &FC,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        external_inputs: FC::ExternalInputs,
        current_proof: &Self::Proof<FC>,
        rng: impl RngCore,
    ) -> Result<(FC::State, FC::ExternalOutputs, Self::Proof<FC>), Error>;
}

/// [`IVCVerifier`] defines the proof verification algorithm of IVC.
pub trait IVCVerifier: IVCTypes {
    /// [`IVCVerifier::verify`] is a deterministic algorithm that checks the
    /// current state is correctly derived from the initial state after invoking
    /// the step circuit for the claimed number of steps, by verifying the IVC
    /// proof.
    ///
    /// ### Function Signature
    ///
    /// [`IVCVerifier::verify`] takes as input
    /// - `vk`: the verifier key,
    /// - `i`: the current step,
    /// - `initial_state`: the initial state,
    /// - `current_state`: the current state, and
    /// - `proof`: the proof.
    ///
    /// It outputs
    /// - an error if the proof is invalid, or
    /// - `Ok(())` otherwise.
    ///
    /// ### Usage
    ///
    /// See [`IVC`] for an example of how to use this method in the context of a
    /// full IVC workflow.
    fn verify<FC: FCircuit<Field = Self::Field>>(
        vk: &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        proof: &Self::Proof<FC>,
    ) -> Result<(), Error>;
}

/// [`IVCOps`] is a convenience super-trait bundling all algorithms.
pub trait IVCOps: IVCPreprocessor + IVCKeyGenerator + IVCProver + IVCVerifier {}

impl<I: IVCPreprocessor + IVCKeyGenerator + IVCProver + IVCVerifier> IVCOps for I {}

/// [`IVC`] is the main trait for an Incrementally Verifiable Computation (IVC)
/// scheme, which includes the type definitions and all the algorithms.
///
/// ### Usage
///
/// A concrete IVC scheme `I` that implements [`IVC`] can usually be used in the
/// following way:
///
/// ```rust
/// use ark_std::rand::Rng;
/// use sonobe_ivc::{Error, IVC};
/// use sonobe_primitives::{circuits::FCircuit, traits::Dummy};
///
/// fn ivc_usage<I: IVC, F: FCircuit<Field = I::Field>>(
///     config: I::Config,
///     step_circuit: F,
///     initial_state: F::State,
///     external_inputs_vec: Vec<F::ExternalInputs>,
///     mut rng: impl Rng,
/// ) -> Result<(), Error> {
///     let n_steps = external_inputs_vec.len();
///
///     // 1. Generate public parameters.
///     let pp = I::preprocess(config, &mut rng)?;
///
///     // 2. Generate prover key and verifier key for the step circuit.
///     let (pk, vk) = I::generate_keys(pp, &step_circuit)?;
///
///     let mut current_state = initial_state.clone();
///     let mut current_proof = I::Proof::dummy(&pk);
///
///     for (i, external_inputs) in external_inputs_vec.into_iter().enumerate() {
///         // 3. Generate the new state and proof from the current state and
///         //    proof.
///         let (next_state, external_outputs, next_proof) = I::prove(
///             &pk,
///             &step_circuit,
///             i,
///             &initial_state,
///             &current_state,
///             external_inputs,
///             &current_proof,
///             &mut rng,
///         )?;
///         current_state = next_state;
///         current_proof = next_proof;
///     }
///
///     // 4. Verify the final state and proof.
///     I::verify(&vk, n_steps, &initial_state, &current_state, &current_proof)?;
///
///     Ok(())
/// }
/// ```
pub trait IVC: IVCTypes + IVCOps {}

impl<I: IVCTypes + IVCOps> IVC for I {}

pub trait IVCTypesGadget {
    type Widget: IVCTypes;

    type VerifierKey<FC>;

    type ProofVar;
}

/// [`IVCVerifier`] defines the proof verification algorithm of IVC.
pub trait IVCVerifierGadget: IVCTypesGadget {
    fn verify<FC: FCircuit>(
        vk: &Self::VerifierKey<FC>,
        i: FpVar<FC::Field>,
        initial_state: &FC::StateVar,
        current_state: &FC::StateVar,
        proof: &Self::ProofVar,
    ) -> Result<(), Error>;
}

/// [`IVCStatefulProver`] is a convenience struct that implements a stateful IVC
/// prover who maintains running state across iterations, so that the user does
/// not need to manually track and pass in the current state and proof at each
/// step.
///
/// ### Usage
///
/// With [`IVCStatefulProver`], the IVC workflow can be simplified as follows:
///
/// ```rust
/// use ark_std::rand::Rng;
/// use sonobe_ivc::{Error, IVC, IVCStatefulProver};
/// use sonobe_primitives::{circuits::FCircuit, traits::Dummy};
///
/// fn ivc_usage<I: IVC, F: FCircuit<Field = I::Field>>(
///     config: I::Config,
///     step_circuit: F,
///     initial_state: F::State,
///     external_inputs_vec: Vec<F::ExternalInputs>,
///     mut rng: impl Rng,
/// ) -> Result<(), Error> {
///     let n_steps = external_inputs_vec.len();
///
///     // 1. Generate public parameters.
///     let pp = I::preprocess(config, &mut rng)?;
///
///     // 2. Generate prover key and verifier key for the step circuit.
///     let (pk, vk) = I::generate_keys(pp, &step_circuit)?;
///
///     let mut prover = IVCStatefulProver::<_, I>::new(&pk, &step_circuit, initial_state)?;
///
///     for external_inputs in external_inputs_vec {
///         // 3. Generate the new state and proof from the current state and
///         //    proof.
///         prover.prove_step(external_inputs, &mut rng)?;
///     }
///
///     // 4. Verify the final state and proof.
///     I::verify(
///         &vk,
///         prover.i,
///         &prover.initial_state,
///         &prover.current_state,
///         &prover.current_proof,
///     )?;
///
///     Ok(())
/// }
/// ```
pub struct IVCStatefulProver<'a, FC: FCircuit, I: IVC> {
    pk: &'a I::ProverKey<FC>,
    step_circuit: &'a FC,
    pub i: usize,
    pub initial_state: FC::State,
    pub current_state: FC::State,
    pub current_proof: I::Proof<FC>,
}

impl<'a, FC: FCircuit<Field = I::Field>, I: IVC> IVCStatefulProver<'a, FC, I> {
    /// [`IVCStatefulProver::new`] creates a new stateful IVC prover with the
    /// given prover key `pk`, step circuit `step_circuit`, and initial state
    /// `initial_state`.
    pub fn new(
        pk: &'a I::ProverKey<FC>,
        step_circuit: &'a FC,
        initial_state: FC::State,
    ) -> Result<Self, Error> {
        Ok(Self {
            step_circuit,
            i: 0,
            current_state: initial_state.clone(),
            initial_state,
            current_proof: I::Proof::dummy(pk),
            pk,
        })
    }

    /// [`IVCStatefulProver::prove_step`] performs one step of proving, updating
    /// the internal state and proof, and returning the external outputs.
    pub fn prove_step(
        &mut self,
        external_inputs: FC::ExternalInputs,
        rng: impl RngCore,
    ) -> Result<FC::ExternalOutputs, Error> {
        let (next_state, external_outputs, next_proof) = I::prove(
            self.pk,
            self.step_circuit,
            self.i,
            &self.initial_state,
            &self.current_state,
            external_inputs,
            &self.current_proof,
            rng,
        )?;
        self.i += 1;
        self.current_state = next_state;
        self.current_proof = next_proof;
        Ok(external_outputs)
    }
}

pub trait IVCProofCompressor {
    /// [`IVCProofCompressor::IVC`] defines the underlying IVC scheme that the decider
    /// compiles.
    type IVC: IVC;

    /// [`IVCProofCompressor::ProverKey`] defines the prover key type for the decider.
    type ProverKey<FC>;
    /// [`IVCProofCompressor::VerifierKey`] defines the verifier key type for the decider.
    type VerifierKey<FC>;
    type CompressedProof<FC>;

    type Error: ErrorTrait + 'static;

    fn preprocess_and_generate_keys<FC: FCircuit<Field = <Self::IVC as IVCTypes>::Field>>(
        circuit: &FC,
        ivc_pk: <Self::IVC as IVCTypes>::ProverKey<FC>,
        ivc_vk: <Self::IVC as IVCTypes>::VerifierKey<FC>,
        rng: impl RngCore,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), Self::Error>;

    fn prove<FC: FCircuit<Field = <Self::IVC as IVCTypes>::Field>>(
        pk: &Self::ProverKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        proof: &<Self::IVC as IVCTypes>::Proof<FC>,
        rng: impl RngCore,
    ) -> Result<Self::CompressedProof<FC>, Self::Error>;

    fn verify<FC: FCircuit<Field = <Self::IVC as IVCTypes>::Field>>(
        vk: &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        compressed_proof: &Self::CompressedProof<FC>,
    ) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use ark_std::{error::Error, rand::Rng};

    use super::*;

    fn test_manual_state_management<I: IVC, F: FCircuit<Field = I::Field>>(
        pk: &I::ProverKey<F>,
        vk: &I::VerifierKey<F>,
        step_circuit: &F,
        initial_state: F::State,
        external_inputs_vec: Vec<F::ExternalInputs>,
        mut rng: impl Rng,
    ) -> Result<(F::State, I::Proof<F>), Box<dyn Error>> {
        let mut current_state = initial_state.clone();
        let mut current_proof = I::Proof::dummy(pk);

        I::verify(vk, 0, &initial_state, &current_state, &current_proof)?;

        for (i, external_inputs) in external_inputs_vec.into_iter().enumerate() {
            let (next_state, _, next_proof) = I::prove(
                pk,
                step_circuit,
                i,
                &initial_state,
                &current_state,
                external_inputs,
                &current_proof,
                &mut rng,
            )?;
            current_state = next_state;
            current_proof = next_proof;

            I::verify(vk, i + 1, &initial_state, &current_state, &current_proof)?;
        }

        Ok((current_state, current_proof))
    }

    fn test_auto_state_management<I: IVC, F: FCircuit<Field = I::Field>>(
        pk: &I::ProverKey<F>,
        vk: &I::VerifierKey<F>,
        step_circuit: &F,
        initial_state: F::State,
        external_inputs_vec: Vec<F::ExternalInputs>,
        mut rng: impl Rng,
    ) -> Result<(F::State, I::Proof<F>), Box<dyn Error>> {
        let mut prover = IVCStatefulProver::<_, I>::new(pk, step_circuit, initial_state)?;

        I::verify(
            vk,
            prover.i,
            &prover.initial_state,
            &prover.current_state,
            &prover.current_proof,
        )?;

        for external_inputs in external_inputs_vec {
            prover.prove_step(external_inputs, &mut rng)?;

            I::verify(
                vk,
                prover.i,
                &prover.initial_state,
                &prover.current_state,
                &prover.current_proof,
            )?;
        }

        Ok((prover.current_state, prover.current_proof))
    }

    pub fn test_ivc<I: IVC, F: FCircuit<Field = I::Field, ExternalInputs: Clone>>(
        config: I::Config,
        step_circuit: F,
        external_inputs_vec: Vec<F::ExternalInputs>,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>> {
        let pp = I::preprocess(config, &mut rng)?;

        let (pk, vk) = I::generate_keys(pp, &step_circuit)?;

        let initial_state = step_circuit.dummy_state();

        test_auto_state_management::<I, F>(
            &pk,
            &vk,
            &step_circuit,
            initial_state.clone(),
            external_inputs_vec.clone(),
            &mut rng,
        )?;

        test_manual_state_management::<I, F>(
            &pk,
            &vk,
            &step_circuit,
            initial_state,
            external_inputs_vec,
            &mut rng,
        )?;

        Ok(())
    }

    pub fn test_ivc_decider<
        D: IVCProofCompressor,
        F: FCircuit<Field = <D::IVC as IVCTypes>::Field, ExternalInputs: Clone>,
    >(
        config: <D::IVC as IVCTypes>::Config,
        step_circuit: F,
        external_inputs_vec: Vec<F::ExternalInputs>,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>> {
        let pp = D::IVC::preprocess(config, &mut rng)?;

        let (pk, vk) = D::IVC::generate_keys(pp, &step_circuit)?;

        let initial_state = step_circuit.dummy_state();

        let (current_state, current_proof) = test_auto_state_management::<D::IVC, F>(
            &pk,
            &vk,
            &step_circuit,
            initial_state.clone(),
            external_inputs_vec.clone(),
            &mut rng,
        )?;

        let (pk, vk) = D::preprocess_and_generate_keys(&step_circuit, pk, vk, &mut rng)?;

        let proof = D::prove(
            &pk,
            external_inputs_vec.len(),
            &initial_state,
            &current_state,
            &current_proof,
            &mut rng,
        )?;

        D::verify(
            &vk,
            external_inputs_vec.len(),
            &initial_state,
            &current_state,
            &proof,
        )?;

        Ok(())
    }
}
