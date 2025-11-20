use ark_ff::{PrimeField, Zero};
use ark_relations::gr1cs::{ConstraintSystem, SynthesisError, SynthesisMode};
use ark_std::{borrow::Borrow, marker::PhantomData, rand::RngCore, sync::Arc};
use sonobe_fs::{
    DeciderKey, FoldingInstance, FoldingScheme, FoldingSchemeFullGadget,
    FoldingSchemePartialGadget, GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary,
};
use sonobe_primitives::{
    algebra::field::emulated::EmulatedFieldVar,
    arithmetizations::{Arith, ArithConfig},
    circuits::{ConstraintSystemBuilder, ConstraintSystemExt, FCircuit},
    commitments::VectorCommitment,
    relations::WitnessInstanceSampler,
    traits::{Dummy, SonobeCurve, CF1, CF2},
    transcripts::Transcript,
};

use crate::{
    compilers::cyclefold::circuits::{AugmentedCircuit, CycleFoldCircuit, CycleFoldConfig},
    Error, IVC,
};

pub mod adapters;
pub mod circuits;

pub trait FoldingSchemeCycleFoldExt<const M: usize, const N: usize>:
    GroupBasedFoldingSchemePrimary<M, N>
{
    type CFConfig: CycleFoldConfig<C = <Self::VC as VectorCommitment>::Commitment>;

    const N_CYCLEFOLDS: usize;

    fn to_cyclefold_configs(
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof,
        rho: Self::Challenge,
    ) -> Vec<Self::CFConfig>;

    fn to_cyclefold_inputs(
        Us: [<Self::Gadget as FoldingSchemePartialGadget<M, N>>::RU; M],
        us: [<Self::Gadget as FoldingSchemePartialGadget<M, N>>::IU; N],
        UU: <Self::Gadget as FoldingSchemePartialGadget<M, N>>::RU,
        proof: <Self::Gadget as FoldingSchemePartialGadget<M, N>>::Proof,
        rho: <Self::Gadget as FoldingSchemePartialGadget<M, N>>::Challenge,
    ) -> Result<
        Vec<
            Vec<
                EmulatedFieldVar<
                    <Self::VC as VectorCommitment>::Scalar,
                    CF2<<Self::VC as VectorCommitment>::Commitment>,
                >,
            >,
        >,
        SynthesisError,
    >;
}

pub struct Key<FS1: FoldingScheme<1, 1>, FS2: FoldingScheme<1, 1>, T>(
    pub FS1::DeciderKey,
    pub FS2::DeciderKey,
    pub T,
);

pub struct Proof<FS1: FoldingScheme<1, 1>, FS2: FoldingScheme<1, 1>>(
    pub FS1::RW,
    pub FS1::RU,
    pub FS1::IW,
    pub FS1::IU,
    pub FS2::RW,
    pub FS2::RU,
);

impl<FS1: FoldingScheme<1, 1>, FS2: FoldingScheme<1, 1>, T> Dummy<&Key<FS1, FS2, T>>
    for Proof<FS1, FS2>
{
    fn dummy(pk: &Key<FS1, FS2, T>) -> Self {
        let cfg1 = pk.0.to_arith_config();
        let cfg2 = pk.1.to_arith_config();
        Self(
            FS1::RW::dummy(cfg1),
            FS1::RU::dummy(cfg1),
            FS1::IW::dummy(cfg1),
            FS1::IU::dummy(cfg1),
            FS2::RW::dummy(cfg2),
            FS2::RU::dummy(cfg2),
        )
    }
}

pub struct CycleFoldBasedIVC<FS1, FS2, T> {
    _d: PhantomData<(FS1, FS2, T)>,
}

impl<FS1, FS2, T> IVC for CycleFoldBasedIVC<FS1, FS2, T>
where
    FS1: FoldingSchemeCycleFoldExt<
        1,
        1,
        Arith: From<ConstraintSystem<CF1<<FS1::VC as VectorCommitment>::Commitment>>>,
        Gadget: FoldingSchemePartialGadget<1, 1, VerifierKey = ()>,
        VC: VectorCommitment<
            Commitment: SonobeCurve<BaseField = <FS2::VC as VectorCommitment>::Scalar>,
        >,
    >,
    FS2: GroupBasedFoldingSchemeSecondary<
        1,
        1,
        Arith: From<ConstraintSystem<CF1<<FS2::VC as VectorCommitment>::Commitment>>>,
        Gadget: FoldingSchemeFullGadget<1, 1, VerifierKey = ()>,
        VC: VectorCommitment<
            Commitment: SonobeCurve<BaseField = <FS1::VC as VectorCommitment>::Scalar>,
        >,
    >,
    T: Transcript<CF1<<FS1::VC as VectorCommitment>::Commitment>>,
{
    type Field = <FS1::VC as VectorCommitment>::Scalar;

    type Config = (FS1::Config, FS2::Config, T::Config);

    type PublicParam = (FS1::PublicParam, FS2::PublicParam, T::Config);

    type ProverKey<FC> = Key<FS1, FS2, (T::Config, Self::Field)>;

    type VerifierKey<FC> = Key<FS1, FS2, (T::Config, Self::Field)>;

    type Proof<FC> = Proof<FS1, FS2>;

    fn preprocess(
        (cfg1, cfg2, hash_config): Self::Config,
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, Error> {
        Ok((
            FS1::preprocess(cfg1, &mut rng)?,
            FS2::preprocess(cfg2, &mut rng)?,
            hash_config,
        ))
    }

    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        (pp1, pp2, hash_config): Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), Error> {
        let cyclefold_circuit = CycleFoldCircuit::<FS1::CFConfig>::default();

        let cs = ConstraintSystemBuilder::new()
            .with_setup_mode()
            .with_circuit(cyclefold_circuit)
            .synthesize()?;
        let arith2 = FS2::Arith::from(cs);

        let mut arith1 = FS1::Arith::default();

        loop {
            let augmented_circuit = AugmentedCircuit::<FS1, FS2, FC, T> {
                hash_config: hash_config.clone(),
                arith1_config: arith1.config(),
                arith2_config: arith2.config(),
                step_circuit,
            };
            let cs = ConstraintSystemBuilder::new()
                .with_setup_mode()
                .with_circuit(augmented_circuit)
                .synthesize()?;
            let new_arith1 = FS1::Arith::from(cs);
            if new_arith1.config() == arith1.config() {
                break;
            }
            arith1 = new_arith1;
        }

        let dk1 = FS1::generate_keys(pp1, arith1)?;
        let dk2 = FS2::generate_keys(pp2, arith2)?;

        let pp_hash = Zero::zero(); // TODO

        Ok((
            Key(dk1.clone(), dk2.clone(), (hash_config.clone(), pp_hash)),
            Key(dk1, dk2, (hash_config, pp_hash)),
        ))
    }

    fn prove<FC: FCircuit<Field = Self::Field>>(
        Key(dk1, dk2, (hash_config, pp_hash)): &Self::ProverKey<FC>,
        step_circuit: &FC,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        external_inputs: FC::ExternalInputs,
        Proof(W, U, w, u, cf_W, cf_U): &Self::Proof<FC>,
        mut rng: impl RngCore,
    ) -> Result<(FC::State, Self::Proof<FC>), Error> {
        let mode = SynthesisMode::Prove {
            construct_matrices: false,
            generate_lc_assignments: false,
        };

        let hash = T::new_with_pp_hash(hash_config, *pp_hash);
        let mut transcript = hash.separate_domain("transcript".as_ref());

        let arith1_config = dk1.to_arith_config();
        let arith2_config = dk2.to_arith_config();
        let augmented_circuit = AugmentedCircuit::<FS1, FS2, FC, T> {
            hash_config: hash_config.clone(),
            arith1_config,
            arith2_config,
            step_circuit,
        };

        let mut WW = Dummy::dummy(arith1_config);
        let mut UU = Dummy::dummy(arith1_config);
        let mut proof = Dummy::dummy(arith1_config);
        let mut cf_us = vec![Dummy::dummy(arith2_config); FS1::N_CYCLEFOLDS];
        let mut cf_proofs = vec![Dummy::dummy(arith2_config); FS1::N_CYCLEFOLDS];
        let mut cf_UU = Dummy::dummy(arith2_config);
        let mut cf_WW = Dummy::dummy(arith2_config);

        if i != 0 {
            let challenge;
            (WW, UU, proof, challenge) = FS1::prove(
                dk1.to_pk(),
                &mut transcript,
                &[W],
                &[U],
                &[w],
                &[u],
                &mut rng,
            )?;

            let cf_configs = FS1::to_cyclefold_configs(&[U], &[u], &proof, challenge);
            for (i, cfg) in cf_configs.iter().enumerate() {
                let cs = ConstraintSystem::new_ref();
                cs.set_mode(mode);
                cfg.verify_point_rlc(cs.clone())?;

                let (cf_w, cf_u) = dk2.sample(cs.assignments()?, &mut rng)?;

                (cf_WW, cf_UU, cf_proofs[i], _) = FS2::prove(
                    dk2.to_pk(),
                    &mut transcript,
                    &[if i == 0 { cf_W } else { &cf_WW }],
                    &[if i == 0 { cf_U } else { &cf_UU }],
                    &[&cf_w],
                    &[&cf_u],
                    &mut rng,
                )?;
                cf_us[i] = cf_u;
            }
        }

        let cs = ConstraintSystem::new_ref();
        cs.set_mode(mode);
        let next_state = augmented_circuit.compute_next_state(
            cs.clone(),
            *pp_hash,
            i,
            initial_state,
            current_state,
            external_inputs,
            U,
            u,
            proof,
            cf_U,
            cf_us,
            cf_proofs,
        )?;

        let (ww, uu) = dk1.sample(cs.assignments()?, &mut rng)?;

        Ok((next_state, Proof(WW, UU, ww, uu, cf_WW, cf_UU)))
    }

    fn verify<FC: FCircuit<Field = Self::Field>>(
        Key(dk1, dk2, (hash_config, pp_hash)): &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        Proof(W, U, w, u, cf_W, cf_U): &Self::Proof<FC>,
    ) -> Result<(), Error> {
        if i == 0 {
            return (initial_state == current_state)
                .then_some(())
                .ok_or(Error::IVCVerificationFail);
        }

        let hash = T::new_with_pp_hash(hash_config, *pp_hash);
        let mut sponge = hash.separate_domain("sponge".as_ref());

        let u_x = sponge
            .add(&i)
            .add(initial_state)
            .add(current_state)
            .add(U)
            .add(cf_U)
            .get_field_element();

        if u.public_inputs() != [u_x] {
            return Err(Error::IVCVerificationFail);
        }

        FS1::decide_running(dk1, W, U)?;
        FS1::decide_incoming(dk1, w, u)?;
        FS2::decide_running(dk2, cf_W, cf_U)?;

        Ok(())
    }
}
