//! Implementation of the CycleFold-based IVC compiler as described in this
//! [paper].
//!
//! It turns any compatible folding scheme into a full IVC scheme by running the
//! primary circuit on one curve and a "CycleFold" circuit on the secondary
//! curve to handle emulated elliptic curve operations.
//!
//! [paper]: https://eprint.iacr.org/2023/1192.pdf

use ark_ff::field_hashers::hash_to_field;
use ark_relations::gr1cs::{ConstraintSystem, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::{
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
    DeciderKey, FoldingInstance, FoldingSchemeDef, FoldingSchemeDefGadget,
    FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget,
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary,
};
use sonobe_primitives::{
    algebra::field::emulated::EmulatedFieldVar,
    arithmetizations::{Arith, ArithConfig},
    circuits::{ArithExtractor, AssignmentsExtractor, FCircuit},
    commitments::CommitmentDef,
    relations::WitnessInstanceSampler,
    traits::{CF1, CF2, Dummy, SonobeCurve},
    transcripts::{
        Transcript, TranscriptGadget,
        recording::RecordingTranscript,
        replay::{ReplayTranscript, ReplayTranscriptVar},
    },
};

use crate::{
    Error, IVC,
    compilers::cyclefold::circuits::{AugmentedCircuit, CycleFoldCircuit},
};

pub mod adapters;
pub mod circuits;

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

impl<FS1, FS2, T> IVC for CycleFoldBasedIVC<FS1, FS2, T>
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
    type Field = <FS1::CM as CommitmentDef>::Scalar;

    type Config = (FS1::Config, FS2::Config, T::Config);

    type PublicParam = (FS1::PublicParam, FS2::PublicParam, T::Config);

    type ProverKey<FC: FCircuit> =
        Key<FS1::DeciderKey, FS2::DeciderKey, (T::Config, Self::Field, FC::State)>;

    type VerifierKey<FC: FCircuit> =
        Key<FS1::DeciderKey, FS2::DeciderKey, (T::Config, Self::Field, FC::State)>;

    type Proof<FC: FCircuit> = Proof<FS1, FS2>;

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
        // Run the CycleFold circuit to extract the arithmetization on the
        // secondary curve.
        let arith2 = {
            let cs = ArithExtractor::new();
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
                let cs = ArithExtractor::new();
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
                let cs = AssignmentsExtractor::new();
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

        let cs = AssignmentsExtractor::new();
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

    #[allow(non_snake_case)]
    fn verify<FC: FCircuit<Field = Self::Field>>(
        Key(dk1, dk2, (hash_config, pp_hash, reference_state)): &Self::VerifierKey<FC>,
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
