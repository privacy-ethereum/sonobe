use ark_ff::PrimeField;
use ark_std::rand::RngCore;
use thiserror::Error;

use sonobe_primitives::circuits::FCircuit;

pub mod compilers;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Arithmetization error: {0}")]
    ArithError(#[from] sonobe_primitives::arithmetizations::Error),
    #[error("Folding error: {0}")]
    FoldingError(#[from] sonobe_fs::Error),
}

pub trait IVC {
    type Field: PrimeField;

    type Config;
    type PublicParam;
    type ProverKey<FC: FCircuit>;
    type VerifierKey<FC: FCircuit>;
    type Proof;

    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;

    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        pp: &Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), Error>;

    fn prove<FC: FCircuit<Field = Self::Field>>(
        pk: &Self::ProverKey<FC>,
        step_circuit: &FC,
        i: usize,
        initial_state: &[Self::Field],
        current_state: &[Self::Field],
        external_inputs: FC::ExternalInputs,
        current_proof: &Self::Proof,
        rng: impl RngCore,
    ) -> Result<(Vec<FC::Field>, Self::Proof), Error>;

    fn verify<FC: FCircuit<Field = Self::Field>>(
        vk: &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &[Self::Field],
        current_state: &[Self::Field],
        proof: &Self::Proof,
    ) -> Result<(), Error>;
}

pub struct IVCStatefulProver<FC: FCircuit, I: IVC> {
    pub pk: I::ProverKey<FC>,
    pub step_circuit: FC,
    pub i: usize,
    pub initial_state: Vec<FC::Field>,
    pub current_state: Vec<FC::Field>,
    pub current_proof: I::Proof,
}

impl<FC: FCircuit<Field = I::Field>, I: IVC> IVCStatefulProver<FC, I> {
    pub fn new(
        pk: I::ProverKey<FC>,
        step_circuit: FC,
        initial_state: Vec<FC::Field>,
        initial_proof: I::Proof,
    ) -> Result<Self, Error> {
        Ok(Self {
            pk,
            step_circuit,
            i: 0,
            current_state: initial_state.clone(),
            initial_state,
            current_proof: initial_proof,
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
