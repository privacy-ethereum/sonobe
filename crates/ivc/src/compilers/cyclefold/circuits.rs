//! Augmented and CycleFold circuits for the CycleFold-based IVC compiler.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    convert::ToConstraintFieldGadget,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use sonobe_fs::{
    FoldingInstanceVar, FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget,
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary,
};
use sonobe_primitives::{
    arithmetizations::Arith,
    circuits::FCircuit,
    commitments::CommitmentDef,
    traits::{Dummy, SonobeCurve},
    transcripts::{Transcript, TranscriptGadget},
};

use crate::compilers::cyclefold::FoldingSchemeCycleFoldExt;

/// [`AugmentedCircuit`] defines an augmented version of the user's step circuit
/// which additionally verifies the folding proofs in-circuit.
pub struct AugmentedCircuit<
    'a,
    FS1: GroupBasedFoldingSchemePrimary<1, 1>,
    FS2: GroupBasedFoldingSchemeSecondary<1, 1>,
    FC: FCircuit,
    T: Transcript<FC::Field>,
> {
    pub(super) hash_config: T::Config,
    pub(super) arith1_config: &'a <FS1::Arith as Arith>::Config,
    pub(super) arith2_config: &'a <FS2::Arith as Arith>::Config,
    pub(super) step_circuit: &'a FC,
}

impl<'a, FS1, FS2, FC, T> AugmentedCircuit<'a, FS1, FS2, FC, T>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
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
    FC: FCircuit<Field = <FS1::CM as CommitmentDef>::Scalar>,
    T: Transcript<FC::Field>,
{
    /// [`AugmentedCircuit::compute_next_state`] invokes the step circuit on the
    /// current state and external inputs to compute the next state and external
    /// outputs, and it additionally verifies the folding proofs in-circuit.
    #[allow(non_snake_case, clippy::too_many_arguments)]
    pub fn compute_next_state(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        pp_hash: FC::Field,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        external_inputs: FC::ExternalInputs,
        U: &FS1::RU,
        u: &FS1::IU,
        proof: FS1::Proof<1, 1>,
        cf_U: &FS2::RU,
        cf_us: Vec<FS2::IU>,
        cf_proofs: Vec<FS2::Proof<1, 1>>,
    ) -> Result<(FC::State, FC::ExternalOutputs), SynthesisError> {
        let hash = T::Gadget::new_with_pp_hash(
            &self.hash_config,
            &FpVar::new_witness(cs.clone(), || Ok(pp_hash))?,
        )?;
        let sponge = hash.separate_domain("sponge".as_ref())?;
        let mut transcript = hash.separate_domain("transcript".as_ref())?;

        let i = FpVar::new_witness(cs.clone(), || Ok(FC::Field::from(i as u64)))?;
        let ii = &i + FpVar::one();

        let is_basecase = i.is_zero()?;

        let initial_state = FC::StateVar::new_witness(cs.clone(), || Ok(initial_state))?;
        let current_state = FC::StateVar::new_witness(cs.clone(), || Ok(current_state))?;

        let U_dummy = AllocVar::new_constant(cs.clone(), FS1::RU::dummy(self.arith1_config))?;
        let U = AllocVar::new_witness(cs.clone(), || Ok(U))?;
        let proof = AllocVar::new_witness(cs.clone(), || Ok(proof))?;

        let cf_U_dummy = AllocVar::new_constant(cs.clone(), FS2::RU::dummy(self.arith2_config))?;
        let cf_U = AllocVar::new_witness(cs.clone(), || Ok(cf_U))?;
        let cf_proofs = Vec::new_witness(cs.clone(), || Ok(cf_proofs))?;

        // 1. Fold primary instances.
        // 1.a. Derive the public input to the primary (augmented) circuit in
        //      the `i-1`-th step, which is `u.x = H(i, z_0, z_i, U, cf_U)`.
        let u_x = sponge
            .clone()
            .add(&i)?
            .add(&initial_state)?
            .add(&current_state)?
            .add(&U)?
            .add(&cf_U)?
            .get_field_element()?;
        // 1.b. Construct the incoming instance `u` representing the `i-1`-th
        //      execution of primary (augmented) circuit with the derived public
        //      input.
        let u = FoldingInstanceVar::new_witness_with_public_inputs(cs.clone(), u, vec![u_x])?;
        // 1.c. Fold the primary running instance `U` and incoming instance `u`
        //      using the provided proof to obtain the next running instance
        //      `UU`.
        let step = FS1::Gadget::verify_hinted(&(), &mut transcript, [&U], [&u], &proof)?;
        let UU = step.next_running_instance;
        let rho = step.challenge;
        // 1.d. If this is the base case (`i = 0`), then we should instead use
        //      the dummy running instance as the next running instance.
        let actual_UU = is_basecase.select(&U_dummy, &UU)?;

        // 2. Fold secondary instances.
        let mut cf_UU = cf_U;
        for ((cf_u, cf_u_x), cf_proof) in cf_us
            .iter()
            // 2.a. Derive the public inputs to the secondary (CycleFold)
            //      circuits in the `i`-th step, which are obtained by calling
            //      the implementation of `FoldingSchemeCycleFoldExt`.
            .zip(FS1::to_cyclefold_inputs([U], [u], UU, proof, rho)?)
            .zip(&cf_proofs)
        {
            // 2.b. Construct the incoming instance `cf_u` representing the
            //      corresponding execution of secondary (CycleFold) circuit
            //      with the derived public inputs.
            let cf_u =
                FoldingInstanceVar::new_witness_with_public_inputs(cs.clone(), cf_u, cf_u_x)?;
            // 2.c. Fold the secondary incoming instance `cf_u` into the running
            //      instance `cf_UU` using the provided proof.
            cf_UU = FS2::Gadget::verify(&(), &mut transcript, [&cf_UU], [&cf_u], cf_proof)?;
        }
        // 2.d. If this is the base case (`i = 0`), then we should instead use
        //      the dummy running instance as the next running instance.
        let actual_cf_UU = is_basecase.select(&cf_U_dummy, &cf_UU)?;

        // 3. Update state by invoking the step circuit.
        let (next_state, external_outputs) =
            self.step_circuit
                .generate_step_constraints(i, current_state, external_inputs)?;

        // 4. Compute public input `uu.x = H(i+1, z_0, z_{i+1}, UU, cf_UU)`.
        let uu_x = sponge
            .clone()
            .add(&ii)?
            .add(&initial_state)?
            .add(&next_state)?
            .add(&actual_UU)?
            .add(&actual_cf_UU)?
            .get_field_element()?;
        // This line "converts" `uu_x` from witnesses to public inputs.
        // Instead of directly modifying the constraint system, we explicitly
        // allocate a public input and enforce that its value is indeed `uu_x`.
        // While comparing `uu_x` with itself seems redundant, this is necessary
        // because:
        // - `.value()` allows an honest prover to extract public inputs without
        //   computing them outside the circuit.
        // - `.enforce_equal()` prevents a malicious prover from claiming wrong
        //   public inputs that are not the honest `uu_x` computed in-circuit.
        uu_x.enforce_equal(&FpVar::new_input(cs.clone(), || {
            Ok(uu_x.value().unwrap_or_default())
        })?)?;

        if cs.is_in_setup_mode() {
            Ok((self.step_circuit.dummy_state(), external_outputs))
        } else {
            Ok((next_state.value()?, external_outputs))
        }
    }
}

impl<'a, FS1, FS2, FC, T> ConstraintSynthesizer<FC::Field> for AugmentedCircuit<'a, FS1, FS2, FC, T>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
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
    FC: FCircuit<Field = <FS1::CM as CommitmentDef>::Scalar>,
    T: Transcript<FC::Field>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<FC::Field>,
    ) -> Result<(), SynthesisError> {
        self.compute_next_state(
            cs,
            Default::default(),
            0,
            &self.step_circuit.dummy_state(),
            &self.step_circuit.dummy_state(),
            self.step_circuit.dummy_external_inputs(),
            &Dummy::dummy(self.arith1_config),
            &Dummy::dummy(self.arith1_config),
            Dummy::dummy(self.arith1_config),
            &Dummy::dummy(self.arith2_config),
            vec![Dummy::dummy(self.arith2_config); FS1::N_CYCLEFOLDS],
            vec![Dummy::dummy(self.arith2_config); FS1::N_CYCLEFOLDS],
        )
        .map(|_| ())
    }
}

/// [`CycleFoldCircuit`] is the trait describing the deferred verification of
/// the folding proofs which is now expressed as a circuit on the secondary
/// curve.
pub trait CycleFoldCircuit<F: PrimeField>: Sized + Default {
    /// [`CycleFoldCircuit::mark_point_as_public`] marks a point as public.
    ///
    /// The final vector of public inputs is shorter than the result of calling
    /// [`AllocVar::new_input`], because we only need the x and y coordinates of
    /// the point, but the `infinity` flag is not necessary.
    fn mark_point_as_public<V: ToConstraintFieldGadget<F>>(
        point: &V,
    ) -> Result<(), SynthesisError> {
        for x in &point.to_constraint_field()?[..2] {
            // This line "converts" `x` from a witness to a public input.
            // Instead of directly modifying the constraint system, we explicitly
            // allocate a public input and enforce that its value is indeed `x`.
            // While comparing `x` with itself seems redundant, this is necessary
            // because:
            // - `.value()` allows an honest prover to extract public inputs without
            //   computing them outside the circuit.
            // - `.enforce_equal()` prevents a malicious prover from claiming wrong
            //   public inputs that are not the honest `x` computed in-circuit.
            FpVar::new_input(x.cs(), || x.value())?.enforce_equal(x)?;
        }
        Ok(())
    }

    /// [`CycleFoldCircuit::verify_point_rlc`] verifies the deferred folding
    /// proof in-circuit on the secondary curve, which is done by checking the
    /// random linear combination of the commitments contained in the folding
    /// instances.
    fn verify_point_rlc(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError>;
}
