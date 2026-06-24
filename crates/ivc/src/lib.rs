#![warn(missing_docs)]

//! Incremental Verifiable Computation (IVC) abstractions.
//!
//! This crate provides the [`IVC`] trait, which describes the common
//! interface for all IVC constructions, and [compilers] that turn a folding
//! scheme into a full IVC scheme.

use ark_ff::PrimeField;
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::SerializationError;
use ark_std::rand::RngCore;
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

/// [`IVC`] defines the interface of Incremental Verifiable Computation schemes.
/// It follows the general definition of proof/argument systems, with
/// preprocessing, key generation, proving, and verification algorithms.
pub trait IVC {
    /// [`IVC::Field`] defines the field over which the IVC scheme operates.
    type Field: PrimeField;

    /// [`IVC::Config`] defines the configuration (e.g., the size of public
    /// parameters) for the IVC scheme.
    type Config;
    /// [`IVC::PublicParam`] defines the public parameters produced by
    /// preprocessing.
    type PublicParam;
    /// [`IVC::ProverKey`] defines the prover key type for the IVC scheme.
    /// We parameterize it by the step circuit type `FC`, so that a prover key
    /// for one step circuit cannot be used for another step circuit.
    type ProverKey<FC: FCircuit>;
    /// [`IVC::VerifierKey`] defines the verifier key type for the IVC scheme.
    /// We parameterize it by the step circuit type `FC`, so that a verifier key
    /// for one step circuit cannot be used for another step circuit.
    type VerifierKey<FC: FCircuit>;
    /// [`IVC::Proof`] defines the proof type for the IVC scheme.
    /// We parameterize it by the step circuit type `FC`, so that a proof for
    /// one step circuit cannot be used for another step circuit.
    type Proof<FC: FCircuit>: for<'a> Dummy<&'a Self::ProverKey<FC>>;

    /// [`IVC::preprocess`] defines the preprocessing algorithm, which is a
    /// randomized algorithm that takes as input the config / parameterization
    /// `config` of the IVC scheme and outputs the public parameters.
    ///
    /// Here, the randomness source is controlled by `rng`.
    ///
    /// The security parameter is implicitly specified by the size of underlying
    /// fields and groups.
    ///
    /// This is usually called once for the given configuration and can be
    /// reused for generating multiple keys for different step circuits, as long
    /// as the step circuits conform to the configuration.
    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;

    /// [`IVC::generate_keys`] defines the key generation algorithm, which is a
    /// deterministic algorithm that takes as input the public parameters `pp`
    /// and the step circuit `step_circuit`, and outputs a prover key and a
    /// verifier key.
    #[allow(clippy::type_complexity)]
    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        pp: Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), Error>;

    /// [`IVC::prove`] defines the proof updating algorithm, which is a
    /// (probably) randomized algorithm that takes as input the prover key `pk`,
    /// the step circuit `step_circuit`, the current step `i`, the initial state
    /// `initial_state`, the current state `current_state`, the external inputs
    /// `external_inputs`, and the current proof `current_proof`.
    /// It executes the step circuit on the current state and external inputs,
    /// and outputs its returned next state and external outputs, along with the
    /// new proof.
    ///
    /// Here, `current_proof` attests that `current_state` is correctly derived
    /// from `initial_state` after `i` steps of executing `step_circuit`, and
    /// the returned next proof attests that the next state is correctly derived
    /// from `initial_state` after `i+1` steps with the given `external_inputs`.
    ///
    /// The prover may further use `rng` as the randomness source.
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

    /// [`IVC::verify`] defines the proof verification algorithm, which is a
    /// deterministic algorithm that takes as input the verifier key `vk`, the
    /// current step `i`, the initial state `initial_state`, the current state
    /// `current_state`, and the proof `proof`, and outputs `Ok(())` if the
    /// proof is valid, or an error otherwise.
    fn verify<FC: FCircuit<Field = Self::Field>>(
        vk: &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        proof: &Self::Proof<FC>,
    ) -> Result<(), Error>;
}

/// [`IVCStatefulProver`] is a convenience struct that implements a stateful IVC
/// prover who maintains running state across iterations, so that the user does
/// not need to manually track and pass in the current state and proof at each
/// step.
pub struct IVCStatefulProver<'a, FC: FCircuit<Field = I::Field>, I: IVC> {
    pk: &'a I::ProverKey<FC>,
    step_circuit: &'a FC,
    i: usize,
    initial_state: FC::State,
    current_state: FC::State,
    current_proof: I::Proof<FC>,
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

/// [`Decider`] defines a decider / proof-compression SNARK, which produces a
/// final succinct zero-knowledge proof from an IVC proof.
// TODO (@winderica): Still WIP
pub trait Decider {
    /// [`Decider::IVC`] defines the underlying IVC scheme that the decider
    /// compiles.
    type IVC: IVC;

    /// [`Decider::ProverKey`] defines the prover key type for the decider.
    type ProverKey;
    /// [`Decider::VerifierKey`] defines the verifier key type for the decider.
    type VerifierKey;
    /// [`Decider::Instance`] defines the instance type for the decider.
    type Instance;
    /// [`Decider::Witness`] defines the witness type for the decider.
    type Witness;
    /// [`Decider::Proof`] defines the proof type for the decider.
    type Proof;

    /// [`Decider::preprocess_and_generate_keys`] preprocesses the IVC prover
    /// key `ivc_pk` and generates the decider's prover key and verifier key.
    ///
    /// This can be seen as a SNARK with circuit-specific setup.
    // TODO (@winderica): consider universal/transparent setup
    fn preprocess_and_generate_keys<FC: FCircuit<Field = <Self::IVC as IVC>::Field>>(
        ivc_pk: &<Self::IVC as IVC>::ProverKey<FC>,
        rng: impl RngCore,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), Error>;

    /// [`Decider::prove`] generates a decider proof from the given IVC proof
    /// and instance/witness.
    fn prove(
        pk: &Self::ProverKey,
        w: &Self::Witness,
        x: &Self::Instance,
        rng: impl RngCore,
    ) -> Result<Self::Proof, Error>;

    /// [`Decider::verify`] verifies the decider proof against the given
    /// instance.
    fn verify(vk: &Self::VerifierKey, x: &Self::Instance, proof: &Self::Proof)
    -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use ark_std::{error::Error, rand::Rng};

    use super::*;

    pub fn test_ivc<I: IVC, F: FCircuit<Field = I::Field>>(
        config: I::Config,
        step_circuit: F,
        external_inputs_vec: Vec<F::ExternalInputs>,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>> {
        let pp = I::preprocess(config, &mut rng)?;

        let (pk, vk) = I::generate_keys(pp, &step_circuit)?;

        let initial_state = step_circuit.dummy_state();

        let mut prover = IVCStatefulProver::<_, I>::new(&pk, &step_circuit, initial_state)?;

        for external_inputs in external_inputs_vec {
            prover.prove_step(external_inputs, &mut rng)?;

            I::verify(
                &vk,
                prover.i,
                &prover.initial_state,
                &prover.current_state,
                &prover.current_proof,
            )?;
        }

        Ok(())
    }
}
