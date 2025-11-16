use ark_ff::{PrimeField, Zero};
use ark_relations::gr1cs::{ConstraintSystem, SynthesisError, SynthesisMode};
use ark_std::{borrow::Borrow, marker::PhantomData, rand::RngCore, sync::Arc};
use sonobe_fs::{
    FoldingInstance, FoldingScheme, FoldingSchemeFullGadget, FoldingSchemePartialGadget,
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary,
};
use sonobe_primitives::{
    algebra::field::emulated::EmulatedFieldVar,
    arithmetizations::{Arith, ArithConfig},
    circuits::{ConstraintSystemBuilder, ConstraintSystemExt, FCircuit},
    commitments::VectorCommitment,
    relations::WitnessInstanceSampler,
    traits::{Dummy, SonobeCurve, CF1, CF2},
    transcripts::{
        griffin::{sponge::GriffinSponge, GriffinParams},
        Transcript,
    },
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
                    true,
                >,
            >,
        >,
        SynthesisError,
    >;
}

pub struct ProverKey<F: PrimeField, FS1: FoldingScheme<1, 1>, FS2: FoldingScheme<1, 1>>(
    FS1::ProverKey,
    FS1::DeciderKey,
    FS2::ProverKey,
    FS2::DeciderKey,
    Arc<GriffinParams<F>>,
    F,
    <FS1::Arith as Arith>::Config,
    <FS2::Arith as Arith>::Config,
);

pub struct Proof<FS1: FoldingScheme<1, 1>, FS2: FoldingScheme<1, 1>>(
    FS1::RW,
    FS1::RU,
    FS1::IW,
    FS1::IU,
    FS2::RW,
    FS2::RU,
);

impl<F: PrimeField, FS1: FoldingScheme<1, 1>, FS2: FoldingScheme<1, 1>>
    Dummy<&ProverKey<F, FS1, FS2>> for Proof<FS1, FS2>
{
    fn dummy(pk: &ProverKey<F, FS1, FS2>) -> Self {
        let cfg1 = &pk.6;
        let cfg2 = &pk.7;

        let W = FS1::RW::dummy(cfg1);
        let U = FS1::RU::dummy(cfg1);
        let w = FS1::IW::dummy(cfg1);
        let u = FS1::IU::dummy(cfg1);
        let cf_W = FS2::RW::dummy(cfg2);
        let cf_U = FS2::RU::dummy(cfg2);

        Self(W, U, w, u, cf_W, cf_U)
    }
}

pub struct CycleFoldBasedIVC<FS1, FS2> {
    _d: PhantomData<(FS1, FS2)>,
}

impl<FS1, FS2> IVC for CycleFoldBasedIVC<FS1, FS2>
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
{
    type Field = <FS1::VC as VectorCommitment>::Scalar;

    type Config = (FS1::Config, FS2::Config, Arc<GriffinParams<Self::Field>>);

    type PublicParam = (
        FS1::PublicParam,
        FS2::PublicParam,
        Arc<GriffinParams<Self::Field>>,
    );

    type ProverKey = ProverKey<Self::Field, FS1, FS2>;

    type VerifierKey = (
        FS1::DeciderKey,
        FS2::DeciderKey,
        Arc<GriffinParams<Self::Field>>,
        Self::Field,
    );

    type Proof = Proof<FS1, FS2>;

    fn preprocess(
        (cfg1, cfg2, griffin_config): Self::Config,
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, Error> {
        Ok((
            FS1::preprocess(cfg1, &mut rng)?,
            FS2::preprocess(cfg2, &mut rng)?,
            griffin_config,
        ))
    }

    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        (pp1, pp2, griffin_config): Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), Error> {
        let mut arith2 = FS2::Arith::empty();
        arith2
            .config_mut()
            .set_n_public_inputs(FS1::CFConfig::IO_LEN);

        loop {
            let cyclefold_circuit = CycleFoldCircuit::<FS1::CFConfig>::default();

            let cs = ConstraintSystemBuilder::new()
                .with_setup_mode()
                .with_circuit(cyclefold_circuit)
                .synthesize()?;
            let new_arith2 = FS2::Arith::from(cs);
            if new_arith2.config() == arith2.config() {
                break;
            }
            arith2 = new_arith2;
        }

        let mut arith1 = FS1::Arith::empty();
        arith1.config_mut().set_n_public_inputs(2);

        loop {
            let augmented_circuit = AugmentedCircuit::<FS1, FS2, _> {
                griffin_config: griffin_config.clone(),
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

        let arith1_config = arith1.config().clone();
        let arith2_config = arith2.config().clone();

        let (pk1, _, dk1) = FS1::generate_keys(pp1, arith1)?;
        let (pk2, _, dk2) = FS2::generate_keys(pp2, arith2)?;

        let pp_hash = Zero::zero(); // TODO

        Ok((
            ProverKey(
                pk1,
                dk1.clone(),
                pk2,
                dk2.clone(),
                griffin_config.clone(),
                pp_hash,
                arith1_config,
                arith2_config,
            ),
            (dk1, dk2, griffin_config, pp_hash),
        ))
    }

    fn prove<FC: FCircuit<Field = Self::Field>>(
        ProverKey(pk1, dk1, pk2, dk2, griffin_config, pp_hash, arith1_config, arith2_config): &Self::ProverKey,
        step_circuit: &FC,
        i: usize,
        initial_state: &[FC::Field],
        current_state: &[FC::Field],
        external_inputs: FC::ExternalInputs,
        Proof(W, U, w, u, cf_W, cf_U): &Self::Proof,
        mut rng: impl RngCore,
    ) -> Result<(Vec<FC::Field>, Self::Proof), Error> {
        let mode = SynthesisMode::Prove {
            construct_matrices: false,
            generate_lc_assignments: false,
        };

        let hash = GriffinSponge::new_with_pp_hash(&griffin_config, *pp_hash);
        let mut transcript = hash.separate_domain("transcript".as_ref());

        let augmented_circuit = AugmentedCircuit::<FS1, FS2, _> {
            griffin_config: griffin_config.clone(),
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
            cf_us.clear();
            cf_proofs.clear();

            let challenge;
            (WW, UU, proof, challenge) =
                FS1::prove(pk1, &mut transcript, &[W], &[U], &[w], &[u], &mut rng)?;

            let cf_configs = FS1::to_cyclefold_configs(&[U], &[u], &proof, challenge);
            for (i, cfg) in cf_configs.iter().enumerate() {
                let cs = ConstraintSystem::new_ref();
                cs.set_mode(mode);
                cfg.verify_point_rlc(cs.clone())?;

                let (cf_w, cf_u) = dk2.sample(cs.into_inner().unwrap().assignments()?, &mut rng)?;

                let cf_proof;
                (cf_WW, cf_UU, cf_proof, _) = FS2::prove(
                    pk2,
                    &mut transcript,
                    &[if i == 0 { cf_W } else { &cf_WW }],
                    &[if i == 0 { cf_U } else { &cf_UU }],
                    &[&cf_w],
                    &[&cf_u],
                    &mut rng,
                )?;
                cf_us.push(cf_u);
                cf_proofs.push(cf_proof);
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

        let (ww, uu) = dk1.sample(cs.into_inner().unwrap().assignments()?, &mut rng)?;

        Ok((next_state, Proof(WW, UU, ww, uu, cf_WW, cf_UU)))
    }

    fn verify(
        (dk1, dk2, griffin_config, pp_hash): &Self::VerifierKey,
        i: usize,
        initial_state: &[Self::Field],
        current_state: &[Self::Field],
        Proof(W, U, w, u, cf_W, cf_U): &Self::Proof,
    ) -> Result<(), Error> {
        if i == 0 {
            return (initial_state == current_state)
                .then_some(())
                .ok_or(Error::IVCVerificationFail);
        }

        let griffin = GriffinSponge::new_with_pp_hash(griffin_config, *pp_hash);
        let mut sponge = griffin.separate_domain("sponge".as_ref());

        let u_x = sponge
            .add(&i)
            .add(initial_state)
            .add(current_state)
            .add(U)
            .add(cf_U)
            .get_field_elements(2);

        if u.public_inputs() != &u_x[..] {
            return Err(Error::IVCVerificationFail);
        }

        FS1::decide_running(&dk1, &W, &U)?;
        FS1::decide_incoming(&dk1, &w, &u)?;
        FS2::decide_running(&dk2, &cf_W, &cf_U)?;

        Ok(())
    }
}
