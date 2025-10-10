use ark_std::marker::PhantomData;

use sonobe_fs::FoldingScheme;
use sonobe_primitives::{circuits::FCircuit, commitments::VectorCommitment};

use crate::IVC;

pub struct CycleFoldBasedIVC<FS: FoldingScheme> {
    _fs: PhantomData<FS>,
}

impl<FS: FoldingScheme> IVC for CycleFoldBasedIVC<FS> {
    type Field = <FS::VC as VectorCommitment>::Scalar;

    type Config = ();

    type PublicParam = ();

    type ProverKey<FC> = ();

    type VerifierKey<FC> = ();

    type Proof = ();

    fn preprocess(
        rng: impl ark_std::rand::RngCore,
        config: &Self::Config,
    ) -> Result<Self::PublicParam, crate::Error> {
        todo!()
    }

    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        pp: &Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), crate::Error> {
        todo!()
    }

    fn prove<FC: FCircuit<Field = Self::Field>>(
        pk: &Self::ProverKey<FC>,
        step_circuit: &FC,
        i: usize,
        initial_state: &[FC::Field],
        current_state: &[FC::Field],
        external_inputs: FC::ExternalInputs,
        current_proof: &Self::Proof,
    ) -> Result<(Vec<FC::Field>, Self::Proof), crate::Error> {
        todo!()
    }

    fn verify<FC: FCircuit<Field = Self::Field>>(
        vk: &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &[FC::Field],
        current_state: &[FC::Field],
        proof: &Self::Proof,
    ) -> Result<(), crate::Error> {
        todo!()
    }
}
