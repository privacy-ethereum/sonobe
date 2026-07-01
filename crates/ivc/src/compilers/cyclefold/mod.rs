//! Implementation of the CycleFold-based IVC compiler as described in this
//! [paper].
//!
//! It turns any compatible folding scheme into a full IVC scheme by running the
//! primary circuit on one curve and a "CycleFold" circuit on the secondary
//! curve to handle emulated elliptic curve operations.
//!
//! [paper]: https://eprint.iacr.org/2023/1192.pdf

use ark_ec::CurveGroup;
use ark_ff::field_hashers::hash_to_field;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    any::TypeId,
    borrow::Borrow,
    io::{Error as IoError, Write},
    marker::PhantomData,
    rand::RngCore,
};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update},
};
use sonobe_fs::{
    DeciderKey, FoldingInstance, FoldingInstanceVar, FoldingSchemeDef, FoldingSchemeDefGadget,
    FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget,
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary,
    definitions::circuits::FoldingSchemeDeciderGadget,
};
#[cfg(feature = "evm")]
use sonobe_primitives::utils::evm::serialize::EVMSerialize;
use sonobe_primitives::{
    algebra::{
        field::emulated::EmulatedFieldVar,
        group::{CF1, CF2, SonobeCurve},
    },
    arithmetizations::{Arith, ArithConfig},
    circuits::{
        ArithExtractor, AssignmentsExtractor, FCircuit, WitnessToPublic,
        cache::{CommitmentKeyCache, CommittedCache, RandomnessCache, UsizeSet},
        inputize::Inputize,
    },
    commitments::{CommitmentDef, CommitmentDefGadget},
    relations::WitnessInstanceSampler,
    transcripts::{
        Transcript, TranscriptGadget,
        recording::{RecordingTranscript, RecordingTranscriptVar},
        replay::{ReplayTranscript, ReplayTranscriptVar},
    },
    utils::dummy::Dummy,
};
use sonobe_snarks::cp::CPSNARK;

use crate::{
    Error, IVCKeyGenerator, IVCPreprocessor, IVCProofCompressor, IVCProver, IVCTypes, IVCVerifier,
    compilers::cyclefold::circuits::{AugmentedCircuit, CycleFoldCircuit},
};
#[cfg(feature = "evm")]
use crate::{IVCProofCompressorEVMExt, compilers::cyclefold::evm_verifier::FoldingSchemeEVMExt};

pub mod adapters;
pub mod circuits;
#[cfg(feature = "evm")]
pub mod evm_verifier;

/// [`FoldingSchemeCycleFoldExt`] is the extension trait that a folding scheme
/// must implement to be used with the CycleFold compiler.
pub trait FoldingSchemeCycleFoldExt<const M: usize, const N: usize>:
    GroupBasedFoldingSchemePrimary<M, N>
{
    /// [`FoldingSchemeCycleFoldExt::CFCircuit`] is the CycleFold circuit type
    /// associated with the folding scheme.
    type CFCircuit: CycleFoldCircuit<CF2<<Self::CM as CommitmentDef>::Commitment>>;

    /// [`FoldingSchemeCycleFoldExt::N_CYCLEFOLDS`] specifies how many CycleFold
    /// operations are needed to verify the primary folding scheme's proof.
    const N_CYCLEFOLDS: usize;

    /// [`FoldingSchemeCycleFoldExt::to_cyclefold_circuits`] creates CycleFold
    /// circuits for verifying the point RLCs needed by the folding scheme.
    #[allow(non_snake_case)]
    fn to_cyclefold_circuits(
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<M, N>,
        transcript: ReplayTranscript<CF1<<Self::CM as CommitmentDef>::Commitment>>,
    ) -> Vec<Self::CFCircuit>;

    /// [`FoldingSchemeCycleFoldExt::to_cyclefold_inputs`] computes the inputs
    /// to CycleFold circuits.
    ///
    /// This will be called by the augmented circuit on the primary curve.
    #[allow(non_snake_case, clippy::type_complexity)]
    fn to_cyclefold_inputs(
        Us: [<Self::Gadget as FoldingSchemeDefGadget>::RU; M],
        us: [<Self::Gadget as FoldingSchemeDefGadget>::IU; N],
        UU: <Self::Gadget as FoldingSchemeDefGadget>::RU,
        proof: <Self::Gadget as FoldingSchemeDefGadget>::Proof<M, N>,
        transcript: ReplayTranscriptVar<CF1<<Self::CM as CommitmentDef>::Commitment>>,
    ) -> Result<
        Vec<
            Vec<
                EmulatedFieldVar<
                    <Self::CM as CommitmentDef>::Scalar,
                    CF2<<Self::CM as CommitmentDef>::Commitment>,
                >,
            >,
        >,
        SynthesisError,
    >;
}

/// [`Key`] is the prover / verifier key for the CycleFold-based IVC scheme.
#[derive(Clone)]
pub struct Key<DK1: Clone, DK2: Clone, T: Clone>(pub DK1, pub DK2, pub T);

/// [`Proof`] is the proof produced by the CycleFold compiler.
pub struct Proof<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef>(
    pub FS1::RW,
    pub FS1::RU,
    pub FS1::IW,
    pub FS1::IU,
    pub FS2::RW,
    pub FS2::RU,
);

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef, T: Clone>
    Dummy<&Key<FS1::DeciderKey, FS2::DeciderKey, T>> for Proof<FS1, FS2>
{
    fn dummy(pk: &Key<FS1::DeciderKey, FS2::DeciderKey, T>) -> Self {
        let cfg1 = &pk.0.to_arith_config();
        let cfg2 = &pk.1.to_arith_config();
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

/// [`CycleFoldBasedIVC`] is the main implementation of the IVC compiler based
/// on CycleFold.
///
/// We consider two folding schemes `FS1` and `FS2`, where `FS1` is the folding
/// scheme on the primary curve and `FS2` is the folding scheme on the secondary
/// curve.
/// The user's step circuit is proven using `FS1`, and part of the verification
/// of `FS1`'s proof is offloaded to `FS2` using CycleFold.
///
/// `T` is the transcript type used by the IVC prover and verifier.
pub struct CycleFoldBasedIVC<FS1, FS2, T> {
    _d: PhantomData<(FS1, FS2, T)>,
}

impl<FS1, FS2, T> IVCTypes for CycleFoldBasedIVC<FS1, FS2, T>
where
    FS1: FoldingSchemeCycleFoldExt<1, 1>,
    FS2: GroupBasedFoldingSchemeSecondary<1, 1>,
    T: Transcript<CF1<<FS1::CM as CommitmentDef>::Commitment>>,
{
    type Field = <FS1::CM as CommitmentDef>::Scalar;

    type Config = (FS1::Config, FS2::Config, T::Config);

    type PublicParam = (FS1::PublicParam, FS2::PublicParam, T::Config);

    type ProverKey<FC: FCircuit> =
        Key<FS1::DeciderKey, FS2::DeciderKey, (T::Config, Self::Field, FC::State)>;

    type VerifierKey<FC: FCircuit> =
        Key<FS1::DeciderKey, FS2::DeciderKey, (T::Config, Self::Field, FC::State)>;

    type Proof<FC: FCircuit> = Proof<FS1, FS2>;
}

impl<FS1, FS2, T> IVCPreprocessor for CycleFoldBasedIVC<FS1, FS2, T>
where
    FS1: FoldingSchemeCycleFoldExt<1, 1>,
    FS2: GroupBasedFoldingSchemeSecondary<1, 1>,
    T: Transcript<CF1<<FS1::CM as CommitmentDef>::Commitment>>,
{
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
}

impl<FS1, FS2, T> IVCKeyGenerator for CycleFoldBasedIVC<FS1, FS2, T>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS1::CM as CommitmentDef>::Commitment>>>,
            // TODO (@winderica):
            // All folding schemes we currently support have an empty verifier
            // key, so I used `()` here, but this should be generalized in the
            // future.
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS2::CM as CommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    T: Transcript<CF1<<FS1::CM as CommitmentDef>::Commitment>, Config: CanonicalSerialize>,
    T::Gadget: TranscriptGadget<CF1<<FS1::CM as CommitmentDef>::Commitment>, Config = T::Config>,
{
    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        (pp1, pp2, hash_config): Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), Error> {
        // Run the CycleFold circuit to extract the arithmetization on the
        // secondary curve.
        let arith2 = {
            let mut cs = ArithExtractor::new();
            cs.execute_fn(|cs| FS1::CFCircuit::default().verify_point_rlc(cs))?;
            cs.arith::<FS2::Arith>()?
        };

        // The augmented circuit depends on the configuration of itself.
        // For instance, we are not aware of the number of constraints in the
        // augmented circuit until we fix `arith1_config`, which requires us to
        // provide the number of constraints in the augmented circuit.
        //
        // To break this circular dependency, we use a fixed-point iteration
        // where we start from a default arithmetization and repeatedly update
        // it until its configuration stabilizes.
        let mut arith1_config = ArithConfig {
            n_public_inputs: 1,
            ..Default::default()
        };
        let arith2_config = &arith2.config();

        let arith1;
        loop {
            let new_arith1 = {
                let mut cs = ArithExtractor::new();
                cs.execute_synthesizer(AugmentedCircuit::<FS1, FS2, FC, T::Gadget>::new(
                    &hash_config,
                    &arith1_config,
                    arith2_config,
                    step_circuit,
                ))?;
                cs.arith::<FS1::Arith>()?
            };
            let new_arith1_config = new_arith1.config();
            if new_arith1_config == arith1_config {
                arith1 = new_arith1;
                break;
            }
            arith1_config = new_arith1_config;
        }

        let dk1 = FS1::generate_keys(pp1, arith1)?;
        let dk2 = FS2::generate_keys(pp2, arith2)?;

        struct HashMarshaller<'a>(&'a mut Shake128);

        impl Write for HashMarshaller<'_> {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
                self.0.update(buf);
                Ok(buf.len())
            }

            #[inline]
            fn flush(&mut self) -> Result<(), IoError> {
                Ok(())
            }
        }

        let pp_hash = {
            let mut shake = Shake128::default();
            dk1.serialize_compressed(HashMarshaller(&mut shake))?;
            dk2.serialize_compressed(HashMarshaller(&mut shake))?;
            hash_config.serialize_compressed(HashMarshaller(&mut shake))?;
            hash_to_field::<_, _, 128>(&mut shake.finalize_xof())
        };
        let reference_state = step_circuit.dummy_state();
        let key = Key(dk1, dk2, (hash_config, pp_hash, reference_state));

        Ok((key.clone(), key))
    }
}

impl<FS1, FS2, T> IVCProver for CycleFoldBasedIVC<FS1, FS2, T>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            // TODO (@winderica):
            // All folding schemes we currently support have an empty verifier
            // key, so I used `()` here, but this should be generalized in the
            // future.
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    T: Transcript<CF1<<FS1::CM as CommitmentDef>::Commitment>>,
    T::Gadget: TranscriptGadget<CF1<<FS1::CM as CommitmentDef>::Commitment>, Config = T::Config>,
{
    #[allow(non_snake_case)]
    fn prove<FC: FCircuit<Field = Self::Field>>(
        Key(dk1, dk2, (hash_config, pp_hash, _)): &Self::ProverKey<FC>,
        step_circuit: &FC,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        external_inputs: FC::ExternalInputs,
        Proof(W, U, w, u, cf_W, cf_U): &Self::Proof<FC>,
        mut rng: impl RngCore,
    ) -> Result<(FC::State, FC::ExternalOutputs, Self::Proof<FC>), Error> {
        let hash = T::new_with_pp_hash(hash_config.clone(), *pp_hash);
        let mut transcript = RecordingTranscript::new(hash.separate_domain("transcript".as_ref()));

        let arith1_config = &dk1.to_arith_config();
        let arith2_config = &dk2.to_arith_config();

        let (mut WW, mut UU) = (Dummy::dummy(arith1_config), Dummy::dummy(arith1_config));
        let mut proof = Dummy::dummy(arith1_config);
        let mut cf_us = vec![Dummy::dummy(arith2_config); FS1::N_CYCLEFOLDS];
        let mut cf_proofs = vec![Dummy::dummy(arith2_config); FS1::N_CYCLEFOLDS];
        let (mut cf_UU, mut cf_WW) = (Dummy::dummy(arith2_config), Dummy::dummy(arith2_config));

        if i != 0 {
            (WW, UU, proof) = FS1::prove(
                dk1.to_pk(),
                &mut transcript,
                &[W],
                &[U],
                &[w],
                &[u],
                &mut rng,
            )?;

            let cf_circuits =
                FS1::to_cyclefold_circuits(&[U], &[u], &proof, transcript.clone().into());
            for (i, cf_circuit) in cf_circuits.into_iter().enumerate() {
                let mut cs = AssignmentsExtractor::new();
                cs.execute_fn(|cs| cf_circuit.verify_point_rlc(cs))?;

                let (cf_w, cf_u) = dk2.sample(cs.assignments()?, &mut rng)?;

                (cf_WW, cf_UU, cf_proofs[i]) = FS2::prove(
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

        let mut cs = AssignmentsExtractor::new();
        let (next_state, external_outputs) = cs.execute_fn(|cs| {
            let augmented_circuit = AugmentedCircuit::<FS1, FS2, FC, T::Gadget>::new(
                hash_config,
                arith1_config,
                arith2_config,
                step_circuit,
            );
            augmented_circuit.compute_next_state(
                cs,
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
            )
        })?;

        let (ww, uu) = dk1.sample(cs.assignments()?, &mut rng)?;

        Ok((
            next_state,
            external_outputs,
            Proof(WW, UU, ww, uu, cf_WW, cf_UU),
        ))
    }
}

impl<FS1, FS2, T> IVCVerifier for CycleFoldBasedIVC<FS1, FS2, T>
where
    FS1: FoldingSchemeCycleFoldExt<1, 1>,
    FS2: GroupBasedFoldingSchemeSecondary<1, 1>,
    T: Transcript<CF1<<FS1::CM as CommitmentDef>::Commitment>>,
{
    #[allow(non_snake_case)]
    fn verify<FC: FCircuit<Field = Self::Field>>(
        Key(dk1, dk2, (hash_config, pp_hash, reference_state)): &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        Proof(W, U, w, u, cf_W, cf_U): &Self::Proof<FC>,
    ) -> Result<(), Error> {
        // Ensure the prover supplied `initial_state` and `current_state` have
        // the same shape as `reference_state`'s, which is exactly what the
        // augmented circuit was synthesized for.
        //
        // A state that merely re-groups the same flattened field elements (e.g.
        // `[[x, y], []]` vs `[[x], [y]]`) has a different shape and is rejected
        // here.
        if !FC::same_state_shape(reference_state, initial_state)
            || !FC::same_state_shape(reference_state, current_state)
        {
            return Err(Error::IVCVerificationFail);
        }

        if i == 0 {
            return (initial_state == current_state)
                .then_some(())
                .ok_or(Error::IVCVerificationFail);
        }

        let hash = T::new_with_pp_hash(hash_config.clone(), *pp_hash);
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

pub struct CycleFoldBasedIVCDecider<FS1, FS2, T, S> {
    _p: PhantomData<(FS1, FS2, T, S)>,
}

impl<
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS1::CM as CommitmentDef>::Commitment>>>,
            // TODO (@winderica):
            // All folding schemes we currently support have an empty verifier
            // key, so I used `()` here, but this should be generalized in the
            // future.
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>
                        + FoldingSchemeDeciderGadget,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS2::CM as CommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>
                        + FoldingSchemeDeciderGadget,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    T: Transcript<
            CF1<<FS1::CM as CommitmentDef>::Commitment>,
            Config: CanonicalSerialize,
            Gadget: TranscriptGadget<
                CF1<<FS1::CM as CommitmentDef>::Commitment>,
                Config = T::Config,
            >,
        >,
    S: CPSNARK<
            Field = <FS1::CM as CommitmentDef>::Scalar,
            Relation = (FS1::Arith, UsizeSet),
            CommitmentKey = <FS1::CM as CommitmentDef>::Key,
            Commitment = <<FS1::CM as CommitmentDef>::Commitment as CurveGroup>::Affine,
            CommitmentOpening = <FS1::CM as CommitmentDef>::Scalar,
            Error = SynthesisError,
        >,
> IVCProofCompressor for CycleFoldBasedIVCDecider<FS1, FS2, T, S>
{
    type IVC = CycleFoldBasedIVC<FS1, FS2, T>;

    type ProverKey<FC: FCircuit> = (S::ProverKey, <Self::IVC as IVCTypes>::VerifierKey<FC>);

    type VerifierKey<FC: FCircuit> = (
        S::VerifierKey,
        <FS1::DeciderKey as DeciderKey>::VerifierKey,
        T::Config,
        <Self::IVC as IVCTypes>::Field,
        FC::State,
    );

    type CompressedProof<FC: FCircuit> = (
        S::Proof,
        FS1::RU,
        FS1::IU,
        FS1::Proof<1, 1>,
        Vec<<Self::IVC as IVCTypes>::Field>,
    );

    type Error = Error;

    fn preprocess_and_generate_keys<FC: FCircuit<Field = <Self::IVC as IVCTypes>::Field>>(
        circuit: &FC,
        ivc_vk: <Self::IVC as IVCTypes>::VerifierKey<FC>,
        rng: impl RngCore,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), Self::Error> {
        let cfg1 = &ivc_vk.0.to_arith_config();
        let cfg2 = &ivc_vk.1.to_arith_config();

        let mut cs = ArithExtractor::new();
        {
            let mut cache = cs.cache_map.borrow_mut();
            cache.insert(
                TypeId::of::<CommittedCache>(),
                Box::new(UsizeSet::default()),
            );
            cache.insert(
                TypeId::of::<CommitmentKeyCache>(),
                Box::new(Vec::<<FS1::CM as CommitmentDef>::Key>::new()),
            );
        }

        cs.execute_synthesizer(CycleFoldBasedIVCDeciderCircuit::<FS1, FS2, T, FC> {
            vk: &ivc_vk,
            i: 0,
            initial_state: &circuit.dummy_state(),
            current_state: &circuit.dummy_state(),
            proof: &Dummy::dummy(cfg1),
            WW: &Dummy::dummy(cfg1),
            U: &Dummy::dummy(cfg1),
            u: &Dummy::dummy(cfg1),
            cf_W: &Dummy::dummy(cfg2),
            cf_U: &Dummy::dummy(cfg2),
        })?;
        let (committed_variable_indices, ck) = {
            let mut cache = cs.cache_map.borrow_mut();
            let committed_variable_indices = *cache
                .remove(&TypeId::of::<CommittedCache>())
                .ok_or(SynthesisError::AssignmentMissing)?
                .downcast::<UsizeSet>()
                .map_err(|_| SynthesisError::AssignmentMissing)?;
            let ck = *cache
                .remove(&TypeId::of::<CommitmentKeyCache>())
                .ok_or(SynthesisError::AssignmentMissing)?
                .downcast::<Vec<<FS1::CM as CommitmentDef>::Key>>()
                .map_err(|_| SynthesisError::AssignmentMissing)?;

            (committed_variable_indices, ck)
        };

        let (pk, vk) = S::generate_keys((cs.arith()?, committed_variable_indices), &ck, rng)?;

        let vk = (
            vk,
            ivc_vk.0.to_vk().clone(),
            ivc_vk.2.0.clone(),
            ivc_vk.2.1,
            ivc_vk.2.2.clone(),
        );

        Ok(((pk, ivc_vk), vk))
    }

    fn prove<FC: FCircuit<Field = <Self::IVC as IVCTypes>::Field>>(
        (pk, ivc_vk): &Self::ProverKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        Proof(W, U, w, u, cf_W, cf_U): &<Self::IVC as IVCTypes>::Proof<FC>,
        mut rng: impl RngCore,
    ) -> Result<Self::CompressedProof<FC>, Self::Error> {
        let hash = T::new_with_pp_hash(ivc_vk.2.0.clone(), ivc_vk.2.1);
        // Record the transcript so the cached challenges can be returned in the
        // compressed proof.
        let mut transcript = RecordingTranscript::new(hash.separate_domain("transcript".as_ref()));

        let (WW, _, folding_proof) = FS1::prove(
            ivc_vk.0.to_pk(),
            &mut transcript,
            &[W],
            &[U],
            &[w],
            &[u],
            &mut rng,
        )?;

        let mut cs = AssignmentsExtractor::new();
        {
            let mut cache = cs.cache_map.borrow_mut();
            cache.insert(
                TypeId::of::<CommittedCache>(),
                Box::new(UsizeSet::default()),
            );
            cache.insert(
                TypeId::of::<RandomnessCache>(),
                Box::new(Vec::<<Self::IVC as IVCTypes>::Field>::new()),
            );
        }

        cs.execute_synthesizer(CycleFoldBasedIVCDeciderCircuit::<FS1, FS2, T, FC> {
            vk: ivc_vk,
            i,
            initial_state,
            current_state,
            proof: &folding_proof,
            WW: &WW,
            U,
            u,
            cf_W,
            cf_U,
        })?;
        let w = &cs.assignments.witness_assignment;
        let x = &cs.assignments.instance_assignment;
        let mut cache = cs.cache_map.borrow_mut();
        let o = *cache
            .remove(&TypeId::of::<RandomnessCache>())
            .ok_or(SynthesisError::AssignmentMissing)?
            .downcast::<Vec<<Self::IVC as IVCTypes>::Field>>()
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        let compressed_proof = S::prove(pk, &x[1..], w, &o, &mut rng)?;

        Ok((
            compressed_proof,
            U.clone(),
            u.clone(),
            folding_proof,
            transcript.cached_challenges,
        ))
    }

    fn verify<FC: FCircuit<Field = <Self::IVC as IVCTypes>::Field>>(
        (vk, folding_vk, hash_config, pp_hash, reference_state): &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        (compressed_proof, U, u, folding_proof, challenges): &Self::CompressedProof<FC>,
    ) -> Result<(), Self::Error> {
        if !FC::same_state_shape(reference_state, initial_state)
            || !FC::same_state_shape(reference_state, current_state)
        {
            return Err(Error::IVCVerificationFail);
        }

        if i == 0 {
            return (initial_state == current_state)
                .then_some(())
                .ok_or(Error::IVCVerificationFail);
        }

        let hash = T::new_with_pp_hash(hash_config.clone(), *pp_hash);
        let mut transcript = hash.separate_domain("transcript".as_ref());

        let UU = FS1::verify(folding_vk, &mut transcript, &[U], &[u], folding_proof)?;
        let commitments = UU.commitments();

        let x = &[
            vec![<Self::IVC as IVCTypes>::Field::from(i as u64)],
            FC::StateVar::inputize(initial_state),
            FC::StateVar::inputize(current_state),
            challenges.clone(),
            commitments.iter().flat_map(<<FS1::Gadget as FoldingSchemeDefGadget>::CM as CommitmentDefGadget>::CommitmentVar::inputize).collect::<Vec<_>>()
        ]
        .concat();
        let c = CurveGroup::normalize_batch(&commitments);

        S::verify(vk, x, &c, compressed_proof)?;

        Ok(())
    }
}

#[cfg(feature = "evm")]
impl<
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS1::CM as CommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>
                        + FoldingSchemeDeciderGadget,
            CM: CommitmentDef<
                Scalar: EVMSerialize,
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        > + FoldingSchemeEVMExt<1, 1>,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS2::CM as CommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>
                        + FoldingSchemeDeciderGadget,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    T: Transcript<
            CF1<<FS1::CM as CommitmentDef>::Commitment>,
            Config: CanonicalSerialize,
            Gadget: TranscriptGadget<
                CF1<<FS1::CM as CommitmentDef>::Commitment>,
                Config = T::Config,
            >,
        >,
    S: CPSNARK<
            Field = <FS1::CM as CommitmentDef>::Scalar,
            Relation = (FS1::Arith, UsizeSet),
            CommitmentKey = <FS1::CM as CommitmentDef>::Key,
            Commitment = <<FS1::CM as CommitmentDef>::Commitment as CurveGroup>::Affine,
            CommitmentOpening = <FS1::CM as CommitmentDef>::Scalar,
            Proof: EVMSerialize,
            Error = SynthesisError,
        >,
> IVCProofCompressorEVMExt for CycleFoldBasedIVCDecider<FS1, FS2, T, S>
{
    fn verify_calldata<FC: FCircuit<Field = <Self::IVC as IVCTypes>::Field>>(
        (_vk, _folding_vk, _hash_config, _pp_hash, _reference_state): &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        (compressed_proof, U, u, folding_proof, challenges): &Self::CompressedProof<FC>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok((
            vec![<Self::IVC as IVCTypes>::Field::from(i as u64)],
            FC::StateVar::inputize(initial_state),
            FC::StateVar::inputize(current_state),
            &challenges,
            FS1::verify_calldata(&[U], &[u], folding_proof)?,
            compressed_proof,
        )
            .to_calldata())
    }
}

pub struct CycleFoldBasedIVCDeciderCircuit<
    'a,
    FS1: FoldingSchemeDef,
    FS2: FoldingSchemeDef,
    T: Transcript<FC::Field>,
    FC: FCircuit,
> {
    vk: &'a Key<FS1::DeciderKey, FS2::DeciderKey, (T::Config, FC::Field, FC::State)>,
    i: usize,
    initial_state: &'a FC::State,
    current_state: &'a FC::State,
    proof: &'a FS1::Proof<1, 1>,
    WW: &'a FS1::RW,
    U: &'a FS1::RU,
    u: &'a FS1::IU,
    cf_W: &'a FS2::RW,
    cf_U: &'a FS2::RU,
}

impl<
    'a,
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>
                        + FoldingSchemeDeciderGadget,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Gadget: FoldingSchemeDeciderGadget,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    T: Transcript<
            CF1<<FS1::CM as CommitmentDef>::Commitment>,
            Gadget: TranscriptGadget<
                CF1<<FS1::CM as CommitmentDef>::Commitment>,
                Config = T::Config,
            >,
        >,
    FC: FCircuit<Field = CF1<<FS1::CM as CommitmentDef>::Commitment>>,
> ConstraintSynthesizer<FC::Field> for CycleFoldBasedIVCDeciderCircuit<'a, FS1, FS2, T, FC>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<FC::Field>,
    ) -> Result<(), SynthesisError> {
        let i = FpVar::new_input(cs.clone(), || Ok(FC::Field::from(self.i as u64)))?;
        let initial_state = FC::StateVar::new_input(cs.clone(), || Ok(self.initial_state))?;
        let current_state = FC::StateVar::new_input(cs.clone(), || Ok(self.current_state))?;

        let Key(dk1, dk2, (hash_config, pp_hash, _)) = &self.vk;
        let dk1 = AllocVar::new_constant(cs.clone(), dk1)?;
        let dk2 = AllocVar::new_constant(cs.clone(), dk2)?;
        let pp_hash = FpVar::new_constant(cs.clone(), pp_hash)?;

        let WW = AllocVar::new_witness(cs.clone(), || Ok(self.WW))?;
        let U = AllocVar::new_witness(cs.clone(), || Ok(self.U))?;
        let u = AllocVar::new_witness(cs.clone(), || Ok(self.u))?;
        let cf_W = AllocVar::new_witness(cs.clone(), || Ok(self.cf_W))?;
        let cf_U = AllocVar::new_witness(cs.clone(), || Ok(self.cf_U))?;
        let proof = AllocVar::new_witness(cs.clone(), || Ok(self.proof))?;

        i.enforce_not_equal(&FpVar::zero())?;

        let hash = T::Gadget::new_with_pp_hash(hash_config.clone(), &pp_hash)?;
        let mut sponge = hash.separate_domain("sponge".as_ref())?;
        let mut transcript =
            RecordingTranscriptVar::new(hash.separate_domain("transcript".as_ref())?);

        let UU = FS1::Gadget::verify_hinted(&(), &mut transcript, [&U], [&u], &proof)?;

        transcript.cached_challenges.mark_as_public()?;

        FS1::Gadget::decide_running(&dk1, &WW, &UU)?;
        FS2::Gadget::decide_running(&dk2, &cf_W, &cf_U)?;

        let u_x = sponge
            .add(&i)?
            .add(&initial_state)?
            .add(&current_state)?
            .add(&U)?
            .add(&cf_U)?
            .get_field_element()?;

        u.public_inputs().enforce_equal(&vec![u_x])?;

        Ok(())
    }
}
