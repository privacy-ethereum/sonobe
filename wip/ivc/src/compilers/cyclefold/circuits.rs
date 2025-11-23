use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToConstraintFieldGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use sonobe_fs::{
    FoldingInstanceVar, FoldingSchemeGadgetOpsFull, FoldingSchemeGadgetOpsPartial, GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary
};
use sonobe_primitives::{
    algebra::Val,
    arithmetizations::Arith,
    circuits::FCircuit,
    commitments::VectorCommitmentDef,
    traits::{Dummy, SonobeCurve, CF2},
    transcripts::{Transcript, TranscriptVar},
};

use crate::compilers::cyclefold::FoldingSchemeCycleFoldExt;

pub struct AugmentedCircuit<
    'a,
    FS1: GroupBasedFoldingSchemePrimary<1, 1>,
    FS2: GroupBasedFoldingSchemeSecondary<1, 1>,
    FC: FCircuit,
    T: Transcript<FC::Field>,
> {
    pub hash_config: T::Config,
    pub arith1_config: &'a <FS1::Arith as Arith>::Config,
    pub arith2_config: &'a <FS2::Arith as Arith>::Config,
    pub step_circuit: &'a FC,
}

impl<'a, FS1, FS2, FC, T> AugmentedCircuit<'a, FS1, FS2, FC, T>
where
    FS1: FoldingSchemeCycleFoldExt<
        1,
        1,
        Gadget: FoldingSchemeGadgetOpsPartial<1, 1, VerifierKey = ()>,
        VC: VectorCommitmentDef<
            Commitment: SonobeCurve<BaseField = <FS2::VC as VectorCommitmentDef>::Scalar>,
        >,
    >,
    FS2: GroupBasedFoldingSchemeSecondary<
        1,
        1,
        Gadget: FoldingSchemeGadgetOpsFull<1, 1, VerifierKey = ()>,
        VC: VectorCommitmentDef<
            Commitment: SonobeCurve<BaseField = <FS1::VC as VectorCommitmentDef>::Scalar>,
        >,
    >,
    FC: FCircuit<Field = <FS1::VC as VectorCommitmentDef>::Scalar>,
    T: Transcript<FC::Field>,
{
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
    ) -> Result<FC::State, SynthesisError> {
        let hash = T::Var::new_with_pp_hash(
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

        let u_x = sponge
            .clone()
            .add(&i)?
            .add(&initial_state)?
            .add(&current_state)?
            .add(&U)?
            .add(&cf_U)?
            .get_field_element()?;
        let u = FoldingInstanceVar::new_witness_with_public_inputs(cs.clone(), u, vec![u_x])?;
        let (UU, rho) = FS1::Gadget::verify_hinted(&(), &mut transcript, [&U], [&u], &proof)?;
        let actual_UU = is_basecase.select(&U_dummy, &UU)?;

        let mut cf_UU = cf_U;
        for ((cf_u, cf_u_x), cf_proof) in cf_us
            .iter()
            .zip(FS1::to_cyclefold_inputs([U], [u], UU, proof, rho)?)
            .zip(&cf_proofs)
        {
            let cf_u =
                FoldingInstanceVar::new_witness_with_public_inputs(cs.clone(), cf_u, cf_u_x)?;
            cf_UU = FS2::Gadget::verify(&(), &mut transcript, [&cf_UU], [&cf_u], cf_proof)?;
        }
        let actual_cf_UU = is_basecase.select(&cf_U_dummy, &cf_UU)?;

        let next_state = self.step_circuit.generate_step_constraints(
            cs.clone(),
            i,
            current_state,
            external_inputs,
        )?;

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
            Ok(self.step_circuit.dummy_state())
        } else {
            next_state.value()
        }
    }
}

impl<'a, FS1, FS2, FC, T> ConstraintSynthesizer<FC::Field> for AugmentedCircuit<'a, FS1, FS2, FC, T>
where
    FS1: FoldingSchemeCycleFoldExt<
        1,
        1,
        Gadget: FoldingSchemeGadgetOpsPartial<1, 1, VerifierKey = ()>,
        VC: VectorCommitmentDef<
            Commitment: SonobeCurve<BaseField = <FS2::VC as VectorCommitmentDef>::Scalar>,
        >,
    >,
    FS2: GroupBasedFoldingSchemeSecondary<
        1,
        1,
        Gadget: FoldingSchemeGadgetOpsFull<1, 1, VerifierKey = ()>,
        VC: VectorCommitmentDef<
            Commitment: SonobeCurve<BaseField = <FS1::VC as VectorCommitmentDef>::Scalar>,
        >,
    >,
    FC: FCircuit<Field = <FS1::VC as VectorCommitmentDef>::Scalar>,
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

/// [`CycleFoldConfig`] controls the behavior of [`CycleFoldCircuit`].
///
/// Looking ahead, the circuit computes the random linear combination of points,
/// which is essentially done by iteratively computing `P = (P + p_i) * r_i`,
/// where `P` is the folded point, `p_i` is the input point, and `r_i` is the
/// randomness.
pub trait CycleFoldConfig: Sized + Default {
    type C: SonobeCurve;

    /// `mark_point_as_public` marks a point as public.
    ///
    /// The final vector of public inputs is shorter than the result of calling
    /// [`AllocVar::new_input`], because we only need the x and y coordinates of
    /// the point, but the `infinity` flag is not necessary.
    fn mark_point_as_public(point: &<Self::C as Val>::Var) -> Result<(), SynthesisError> {
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

    fn verify_point_rlc(&self, cs: ConstraintSystemRef<CF2<Self::C>>)
        -> Result<(), SynthesisError>;
}

#[derive(Debug, Clone, Default)]
pub struct CycleFoldCircuit<Cfg> {
    _cfg: PhantomData<Cfg>,
}

impl<Cfg: CycleFoldConfig> ConstraintSynthesizer<CF2<Cfg::C>> for CycleFoldCircuit<Cfg> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CF2<Cfg::C>>,
    ) -> Result<(), SynthesisError> {
        Cfg::default().verify_point_rlc(cs)
    }
}
