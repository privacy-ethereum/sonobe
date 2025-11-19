use ark_ff::PrimeField;
use ark_relations::gr1cs::SynthesisError;
use ark_std::rand::RngCore;
use sonobe_primitives::{circuits::FCircuit, traits::Dummy};
use thiserror::Error;

pub mod compilers;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    ArithError(#[from] sonobe_primitives::arithmetizations::Error),
    #[error(transparent)]
    FoldingError(#[from] sonobe_fs::Error),
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    #[error("IVC verification failed")]
    IVCVerificationFail,
}

pub trait IVC {
    type Field: PrimeField;

    type Config;
    type PublicParam;
    type ProverKey;
    type VerifierKey;
    type Proof: for<'a> Dummy<&'a Self::ProverKey>;

    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;

    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        pp: Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), Error>;

    fn prove<FC: FCircuit<Field = Self::Field>>(
        pk: &Self::ProverKey,
        step_circuit: &FC,
        i: usize,
        initial_state: &[Self::Field],
        current_state: &[Self::Field],
        external_inputs: FC::ExternalInputs,
        current_proof: &Self::Proof,
        rng: impl RngCore,
    ) -> Result<(Vec<Self::Field>, Self::Proof), Error>;

    fn verify(
        vk: &Self::VerifierKey,
        i: usize,
        initial_state: &[Self::Field],
        current_state: &[Self::Field],
        proof: &Self::Proof,
    ) -> Result<(), Error>;
}

pub struct IVCStatefulProver<FC: FCircuit, I: IVC> {
    pub pk: I::ProverKey,
    pub step_circuit: FC,
    pub i: usize,
    pub initial_state: Vec<FC::Field>,
    pub current_state: Vec<FC::Field>,
    pub current_proof: I::Proof,
}

impl<FC: FCircuit<Field = I::Field>, I: IVC> IVCStatefulProver<FC, I> {
    pub fn new(
        pk: I::ProverKey,
        step_circuit: FC,
        initial_state: Vec<FC::Field>,
    ) -> Result<Self, Error> {
        Ok(Self {
            step_circuit,
            i: 0,
            current_state: initial_state.clone(),
            initial_state,
            current_proof: I::Proof::dummy(&pk),
            pk,
        })
    }

    pub fn prove_step(
        &mut self,
        external_inputs: FC::ExternalInputs,
        rng: impl RngCore,
    ) -> Result<(), Error> {
        let (next_state, next_proof) = I::prove(
            &self.pk,
            &self.step_circuit,
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
        Ok(())
    }
}

pub trait Decider {
    type IVC: IVC;

    type ProverKey;
    type VerifierKey;
    type Instance;
    type Witness;
    type Proof;

    fn preprocess_and_generate_keys(
        ivc_pk: &<Self::IVC as IVC>::ProverKey,
        rng: impl RngCore,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), Error>;

    fn prove(
        pk: &Self::ProverKey,
        w: &Self::Witness,
        x: &Self::Instance,
        rng: impl RngCore,
    ) -> Result<Self::Proof, Error>;

    fn verify(vk: &Self::VerifierKey, x: &Self::Instance, proof: &Self::Proof)
        -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
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

        let initial_state = vec![UniformRand::rand(&mut rng); step_circuit.state_len()];

        let mut prover = IVCStatefulProver::<_, I>::new(pk, step_circuit, initial_state)?;

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
