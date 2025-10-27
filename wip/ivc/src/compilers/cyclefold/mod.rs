use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::{marker::PhantomData, rand::RngCore};
use sonobe_fs::{FoldingInstance, FoldingInstanceVar, FoldingScheme, FoldingSchemePartialGadget};
use sonobe_primitives::{
    circuits::{ConstraintSystemExt, FCircuit},
    commitments::{VectorCommitment, VectorCommitmentGadget},
    relations::WitnessInstanceSampler,
    traits::SonobeField,
    transcripts::Transcript,
};

use crate::IVC;

mod circuits;

pub trait FoldingSchemeCycleFoldGadget<const M: usize, const N: usize>: FoldingSchemePartialGadget<M, N> {
    type CFScalarVar;

    fn to_cyclefold_inputs(
        U: Self::RU,
        u: Self::IU,
        UU: Self::RU,
        rho: Self::Challenge,
    ) -> Result<Vec<Vec<Self::CFScalarVar>>, SynthesisError>;
}

pub struct CycleFoldBasedIVC<FS1, FS2> {
    _fs1: PhantomData<FS1>,
    _fs2: PhantomData<FS2>,
}

pub struct ProverKey<FC: FCircuit> {
    poseidon_config: PoseidonConfig<FC::Field>,
    pp_hash: FC::Field,
}

impl<FS1, FS2> IVC for CycleFoldBasedIVC<FS1, FS2>
where
    FS1: FoldingScheme<
        1,
        1,
        VC: VectorCommitment<Scalar = <FS1 as FoldingScheme<1, 1>>::TranscriptField>,
    >,
    FS2: FoldingScheme<1, 1>,
{
    type Field = <FS1::VC as VectorCommitment>::Scalar;

    type Config = (FS1::Config, FS2::Config);

    type PublicParam = (FS1::PublicParam, FS2::PublicParam);

    type ProverKey<FC: FCircuit> = (
        FS1::ProverKey,
        FS1::DeciderKey,
        FS2::ProverKey,
        FS2::DeciderKey,
        ProverKey<FC>,
    );

    type VerifierKey<FC: FCircuit> = ();

    type Proof = (FS1::RW, FS1::RU, FS1::IW, FS1::IU, FS2::RW, FS2::RU);

    fn preprocess(
        config: Self::Config,
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, crate::Error> {
        Ok((
            FS1::preprocess(config.0, &mut rng)?,
            FS2::preprocess(config.1, &mut rng)?,
        ))
    }

    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        pp: &Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), crate::Error> {
        todo!()
    }

    fn prove<FC: FCircuit<Field = Self::Field>>(
        (pk_fs1, dk_fs1, pk_fs2, dk_fs2, pk): &Self::ProverKey<FC>,
        step_circuit: &FC,
        i: usize,
        initial_state: &[FC::Field],
        current_state: &[FC::Field],
        external_inputs: FC::ExternalInputs,
        (W, U, w, u, cfW, cfU): &Self::Proof,
        mut rng: impl RngCore,
    ) -> Result<(Vec<FC::Field>, Self::Proof), crate::Error> {
        let poseidon = PoseidonSponge::new_with_pp_hash(&pk.poseidon_config, pk.pp_hash);
        let sponge = poseidon.separate_domain("sponge".as_ref());
        let mut transcript = poseidon.separate_domain("transcript".as_ref());

        let (WW, UU, proof, challenge) =
            FS1::prove(pk_fs1, &mut transcript, &[W], &[U], &[w], &[u], &mut rng)?;

        if i == 0 {
        } else {
        }

        let cs = ConstraintSystem::<Self::Field>::new_ref();

        let assignments = cs.into_inner().unwrap().assignments()?;
        let (ww, uu) =
            WitnessInstanceSampler::<FS1::IW, FS1::IU>::sample(dk_fs1, assignments, &mut rng)?;

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
