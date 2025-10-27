use ark_crypto_primitives::sponge::poseidon::{
    constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge,
};
use ark_ff::Zero;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    GR1CSVar,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::{marker::PhantomData, rand::RngCore};
use sonobe_fs::{
    FoldingInstance, FoldingInstanceVar, FoldingScheme, FoldingSchemeFullGadget,
    FoldingSchemePartialGadget,
};
use sonobe_primitives::{
    arithmetizations::Arith,
    circuits::{var::Var, ConstraintSystemExt, FCircuit},
    commitments::{VectorCommitment, VectorCommitmentGadget},
    relations::WitnessInstanceSampler,
    traits::{Dummy, SonobeField},
    transcripts::{Transcript, TranscriptVar},
};

use crate::compilers::cyclefold::FoldingSchemeCycleFoldGadget;

pub struct AugmentedCircuit<
    'a,
    FC: FCircuit,
    FS1: FoldingSchemePartialGadget<1, 1>,
    FS2: FoldingSchemeFullGadget<1, 1>,
> {
    poseidon_config: PoseidonConfig<FC::Field>,
    arith1_config: <<FS1::Native as FoldingScheme<1, 1>>::Arith as Arith>::Config,
    arith2_config: <<FS2::Native as FoldingScheme<1, 1>>::Arith as Arith>::Config,
    vk1: FS1::VerifierKey,
    vk2: FS2::VerifierKey,
    step_circuit: &'a FC,
    _fs1: PhantomData<FS1>,
    _fs2: PhantomData<FS2>,
}

impl<'a, FC: FCircuit, FS1, FS2> AugmentedCircuit<'a, FC, FS1, FS2>
where
    FS1: FoldingSchemeCycleFoldGadget<
        1,
        1,
        VC: VectorCommitmentGadget<ConstraintField = FC::Field, ScalarVar = FpVar<FC::Field>>,
        CFScalarVar = <FS2::VC as VectorCommitmentGadget>::ScalarVar,
    >,
    FS2: FoldingSchemeFullGadget<1, 1, VC: VectorCommitmentGadget<ConstraintField = FC::Field>>,
{
    pub fn compute_next_state(
        self,
        cs: ConstraintSystemRef<FC::Field>,
        pp_hash: FC::Field,
        i: usize,
        initial_state: &[FC::Field],
        current_state: &[FC::Field],
        external_inputs: FC::ExternalInputs,
        U: <FS1::RU as Var<FC::Field>>::Native,
        u: <FS1::IU as Var<FC::Field>>::Native,
        proof: <FS1::Proof as Var<FC::Field>>::Native,
        hint: <FS1::Hint as Var<FC::Field>>::Native,
        cf_U: <FS2::RU as Var<FC::Field>>::Native,
        cf_us: Vec<<FS2::IU as Var<FC::Field>>::Native>,
        cf_proofs: Vec<<FS2::Proof as Var<FC::Field>>::Native>,
    ) -> Result<Vec<FC::Field>, SynthesisError> {
        let poseidon = PoseidonSpongeVar::new_with_pp_hash(
            &self.poseidon_config,
            &FpVar::new_witness(cs.clone(), || Ok(pp_hash))?,
        )?;
        let sponge = poseidon.separate_domain("sponge".as_ref())?;
        let mut transcript = poseidon.separate_domain("transcript".as_ref())?;

        let i = FpVar::new_witness(cs.clone(), || Ok(FC::Field::from(i as u64)))?;
        let ii = &i + FpVar::one();

        let is_basecase = i.is_zero()?;

        let initial_state = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(initial_state))?;
        let current_state = Vec::new_witness(cs.clone(), || Ok(current_state))?;

        let U_dummy = FS1::RU::new_witness(cs.clone(), || {
            Ok(<FS1::RU as Var<_>>::Native::dummy(&self.arith1_config))
        })?;
        let U = FS1::RU::new_witness(cs.clone(), || Ok(U))?;
        let u = FS1::IU::new_witness(cs.clone(), || Ok(u))?;
        let proof = FS1::Proof::new_witness(cs.clone(), || Ok(proof))?;
        let hint = FS1::Hint::new_witness(cs.clone(), || Ok(hint))?;

        let cf_U_dummy = FS2::RU::new_witness(cs.clone(), || {
            Ok(<FS2::RU as Var<_>>::Native::dummy(&self.arith2_config))
        })?;
        let cf_U = FS2::RU::new_witness(cs.clone(), || Ok(cf_U))?;
        let cf_us = Vec::new_witness(cs.clone(), || Ok(cf_us))?;
        let cf_proofs = Vec::new_witness(cs.clone(), || Ok(cf_proofs))?;

        let u_x = {
            let mut sponge = sponge.clone();
            sponge.add(&i)?;
            sponge.add(&initial_state)?;
            sponge.add(&current_state)?;
            sponge.add(&U)?;
            sponge.add(&cf_U)?;
            sponge.get_field_elements(2)?
        };

        let next_state = self.step_circuit.generate_step_constraints(
            cs.clone(),
            i,
            current_state,
            external_inputs,
        )?;

        let (UU, rho) = FS1::verify_hinted(&self.vk1, &mut transcript, &[&U], &[&u], &proof, hint)?;

        let mut cf_UU = cf_U;
        for (cf_u, cf_proof) in cf_us.iter().zip(&cf_proofs) {
            cf_UU = FS2::verify(&self.vk2, &mut transcript, &[cf_UU], &[cf_u], cf_proof)?;
        }

        let uu_x = {
            let mut sponge = sponge.clone();
            sponge.add(&ii)?;
            sponge.add(&initial_state)?;
            sponge.add(&next_state)?;
            sponge.add(&is_basecase.select(&U_dummy, &UU)?)?;
            sponge.add(&is_basecase.select(&cf_U_dummy, &cf_UU)?)?;
            sponge.get_field_elements(2)?
        };
        // This line "converts" `uu_x` from witnesses to public inputs.
        // Instead of directly modifying the constraint system, we explicitly
        // allocate a public input and enforce that its value is indeed `uu_x`.
        // While comparing `uu_x` with itself seems redundant, this is necessary
        // because:
        // - `.value()` allows an honest prover to extract public inputs without
        //   computing them outside the circuit.
        // - `.enforce_equal()` prevents a malicious prover from claiming wrong
        //   public inputs that are not the honest `uu_x` computed in-circuit.
        uu_x.enforce_equal(&Vec::new_input(cs.clone(), || uu_x.value())?)?;

        u.public_inputs().enforce_equal(&u_x)?;

        cf_us
            .iter()
            .zip(FS1::to_cyclefold_inputs(U, u, UU, rho)?)
            .try_for_each(|(cf_u, cf_u_x)| cf_u.public_inputs().enforce_equal(&cf_u_x))?;

        next_state.value()
    }
}

impl<'a, FC: FCircuit, FS1, FS2> ConstraintSynthesizer<FC::Field>
    for AugmentedCircuit<'a, FC, FS1, FS2>
where
    FS1: FoldingSchemeCycleFoldGadget<
        1,
        1,
        VC: VectorCommitmentGadget<ConstraintField = FC::Field, ScalarVar = FpVar<FC::Field>>,
        CFScalarVar = <FS2::VC as VectorCommitmentGadget>::ScalarVar,
    >,
    FS2: FoldingSchemeFullGadget<1, 1, VC: VectorCommitmentGadget<ConstraintField = FC::Field>>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<FC::Field>,
    ) -> Result<(), SynthesisError> {
        let state_len = self.step_circuit.state_len();
        let external_inputs = self.step_circuit.dummy_external_inputs();
        let U = <FS1::RU as Var<FC::Field>>::Native::dummy(&self.arith1_config);
        let u = Dummy::dummy(&self.arith1_config);
        let proof = Dummy::dummy(&self.arith1_config);
        let hint = Default::default();
        let cf_U = Dummy::dummy(&self.arith2_config);
        let cf_us = vec![Dummy::dummy(&self.arith2_config); U.commitments().len()];
        let cf_proofs = vec![Dummy::dummy(&self.arith2_config); U.commitments().len()];
        self.compute_next_state(
            cs,
            Default::default(),
            0,
            &vec![Default::default(); state_len],
            &vec![Default::default(); state_len],
            external_inputs,
            U,
            u,
            proof,
            hint,
            cf_U,
            cf_us,
            cf_proofs,
        )
        .map(|_| ())
    }
}
