use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_ff::Zero;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::{marker::PhantomData, rand::RngCore};

use sonobe_fs::{FoldingScheme, FoldingSchemeFullGadget, FoldingSchemePartialGadget};
use sonobe_primitives::circuits::ConstraintSystemExt;
use sonobe_primitives::relations::WitnessInstanceSampler;
use sonobe_primitives::traits::SonobeField;
use sonobe_primitives::transcripts::Transcript;
use sonobe_primitives::{circuits::FCircuit, commitments::VectorCommitment};

pub struct AugmentedCircuit<'a, FC: FCircuit, FS1, FS2> {
    poseidon_config: PoseidonConfig<FC::Field>,
    step_circuit: &'a FC,
    _fs1: PhantomData<FS1>,
    _fs2: PhantomData<FS2>,
}

impl<'a, FC: FCircuit, FS1, FS2> AugmentedCircuit<'a, FC, FS1, FS2>
where
    FS1: FoldingSchemePartialGadget<
        1,
        1,
    >,
    FS2: FoldingSchemeFullGadget<1, 1>,
{
    fn compute_next_state(
        self,
        cs: ConstraintSystemRef<FC::Field>,
        pp_hash: FC::Field,
        i: usize,
        initial_state: Vec<FC::Field>,
        current_state: Vec<FC::Field>,
        external_inputs: FC::ExternalInputs,
        U: FS1::RU,
        u: FS1::IU,
        hint: FS1::Hint,
    ) -> Result<Vec<FC::Field>, SynthesisError> {
        todo!()
    }
}

impl<'a, FC: FCircuit, FS1, FS2> ConstraintSynthesizer<FC::Field>
    for AugmentedCircuit<'a, FC, FS1, FS2>
where
    FS1: FoldingSchemePartialGadget<
        1,
        1,
    >,
    FS2: FoldingSchemeFullGadget<1, 1>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<FC::Field>,
    ) -> Result<(), SynthesisError> {
        let state_len = self.step_circuit.state_len();
        self.compute_next_state(
            cs,
            Default::default(),
            0,
            vec![Default::default(); state_len],
            vec![Default::default(); state_len],
            todo!(),
            todo!(),
            todo!(),
            todo!(),
        )
        .map(|_| ())
    }
}
