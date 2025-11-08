use ark_ff::{BigInteger, Field, One, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToConstraintFieldGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
    prelude::Boolean,
    GR1CSVar,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::{marker::PhantomData, rand::RngCore, sync::Arc};
use sonobe_fs::{
    FoldingInstance, FoldingInstanceVar, FoldingScheme, FoldingSchemeFullGadget,
    FoldingSchemePartialGadget,
};
use sonobe_primitives::{
    arithmetizations::Arith,
    circuits::{var::Var, ConstraintSystemExt, FCircuit},
    commitments::{VectorCommitment, VectorCommitmentGadget},
    relations::WitnessInstanceSampler,
    traits::{Dummy, SonobeCurve, SonobeField, CF1, CF2},
    transcripts::{
        griffin::{params::GriffinParams, sponge::GriffinSpongeVar},
        Transcript, TranscriptVar,
    },
};

use crate::compilers::cyclefold::FoldingSchemeCycleFoldGadget;

pub struct AugmentedCircuit<
    'a,
    FS1: FoldingSchemePartialGadget<1, 1, VerifierKey = ()>,
    FS2: FoldingSchemeFullGadget<1, 1, VerifierKey = ()>,
    FC: FCircuit,
> {
    pub griffin_config: Arc<GriffinParams<FC::Field>>,
    pub arith1_config: &'a <<FS1::Native as FoldingScheme<1, 1>>::Arith as Arith>::Config,
    pub arith2_config: &'a <<FS2::Native as FoldingScheme<1, 1>>::Arith as Arith>::Config,
    pub step_circuit: &'a FC,
}

impl<'a, FS1, FS2, FC: FCircuit> AugmentedCircuit<'a, FS1, FS2, FC>
where
    FS1: FoldingSchemeCycleFoldGadget<
        1,
        1,
        VerifierKey = (),
        VC: VectorCommitmentGadget<ConstraintField = FC::Field, ScalarVar = FpVar<FC::Field>>,
        CFScalarVar = <FS2::VC as VectorCommitmentGadget>::ScalarVar,
    >,
    FS2: FoldingSchemeFullGadget<
        1,
        1,
        VerifierKey = (),
        VC: VectorCommitmentGadget<ConstraintField = FC::Field>,
    >,
{
    pub fn compute_next_state(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        pp_hash: FC::Field,
        i: usize,
        initial_state: &[FC::Field],
        current_state: &[FC::Field],
        external_inputs: FC::ExternalInputs,
        U: &<FS1::RU as Var<FC::Field>>::Native,
        u: &<FS1::IU as Var<FC::Field>>::Native,
        proof: <FS1::Proof as Var<FC::Field>>::Native,
        cf_U: &<FS2::RU as Var<FC::Field>>::Native,
        cf_us: Vec<<FS2::IU as Var<FC::Field>>::Native>,
        cf_proofs: Vec<<FS2::Proof as Var<FC::Field>>::Native>,
    ) -> Result<Vec<FC::Field>, SynthesisError> {
        let hash = GriffinSpongeVar::new_with_pp_hash(
            &self.griffin_config,
            &FpVar::new_witness(cs.clone(), || Ok(pp_hash))?,
        )?;
        let sponge = hash.separate_domain("sponge".as_ref())?;
        let mut transcript = hash.separate_domain("transcript".as_ref())?;

        let i = FpVar::new_witness(cs.clone(), || Ok(FC::Field::from(i as u64)))?;
        let ii = &i + FpVar::one();

        let is_basecase = i.is_zero()?;

        let initial_state = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(initial_state))?;
        let current_state = Vec::new_witness(cs.clone(), || Ok(current_state))?;

        let U_dummy = FS1::RU::new_constant(
            cs.clone(),
            <FS1::RU as Var<_>>::Native::dummy(self.arith1_config),
        )?;
        let U = FS1::RU::new_witness(cs.clone(), || Ok(U))?;
        let proof = FS1::Proof::new_witness(cs.clone(), || Ok(proof))?;

        let cf_U_dummy = FS2::RU::new_constant(
            cs.clone(),
            <FS2::RU as Var<_>>::Native::dummy(self.arith2_config),
        )?;
        let cf_U = FS2::RU::new_witness(cs.clone(), || Ok(cf_U))?;
        let cf_proofs = Vec::new_witness(cs.clone(), || Ok(cf_proofs))?;

        println!("{}", cs.num_constraints());

        let u_x = sponge
            .clone()
            .add(&i)?
            .add(&initial_state)?
            .add(&current_state)?
            .add(&U)?
            .add(&cf_U)?
            .get_field_elements(2)?;
        let u = FS1::IU::new_witness_with_public_inputs(cs.clone(), u, u_x)?;
        let (UU, rho) = FS1::verify_hinted(&(), &mut transcript, &[&U], &[&u], &proof)?;
        let actual_UU = is_basecase.select(&U_dummy, &UU)?;

        println!("{}", cs.num_constraints());

        let mut cf_UU = cf_U;
        for ((cf_u, cf_u_x), cf_proof) in cf_us
            .iter()
            .zip(FS1::to_cyclefold_inputs(U, u, UU, proof, rho)?)
            .zip(&cf_proofs)
        {
            let cf_u = FS2::IU::new_witness_with_public_inputs(cs.clone(), cf_u, cf_u_x)?;
            cf_UU = FS2::verify(&(), &mut transcript, &[cf_UU], &[cf_u], cf_proof)?;
        }
        let actual_cf_UU = is_basecase.select(&cf_U_dummy, &cf_UU)?;

        println!("{}", cs.num_constraints());

        let next_state = self.step_circuit.generate_step_constraints(
            cs.clone(),
            i,
            current_state,
            external_inputs,
        )?;

        println!("{}", cs.num_constraints());

        let uu_x = sponge
            .clone()
            .add(&ii)?
            .add(&initial_state)?
            .add(&next_state)?
            .add(&actual_UU)?
            .add(&actual_cf_UU)?
            .get_field_elements(2)?;
        // This line "converts" `uu_x` from witnesses to public inputs.
        // Instead of directly modifying the constraint system, we explicitly
        // allocate a public input and enforce that its value is indeed `uu_x`.
        // While comparing `uu_x` with itself seems redundant, this is necessary
        // because:
        // - `.value()` allows an honest prover to extract public inputs without
        //   computing them outside the circuit.
        // - `.enforce_equal()` prevents a malicious prover from claiming wrong
        //   public inputs that are not the honest `uu_x` computed in-circuit.
        uu_x.enforce_equal(&Vec::new_input(cs.clone(), || {
            Ok(uu_x.value().unwrap_or(vec![Default::default(); uu_x.len()]))
        })?)?;

        println!("{}", cs.num_constraints());

        Ok(next_state
            .value()
            .unwrap_or(vec![Default::default(); self.step_circuit.state_len()]))
    }
}

impl<'a, FS1, FS2, FC: FCircuit> ConstraintSynthesizer<FC::Field>
    for AugmentedCircuit<'a, FS1, FS2, FC>
where
    FS1: FoldingSchemeCycleFoldGadget<
        1,
        1,
        VerifierKey = (),
        VC: VectorCommitmentGadget<ConstraintField = FC::Field, ScalarVar = FpVar<FC::Field>>,
        CFScalarVar = <FS2::VC as VectorCommitmentGadget>::ScalarVar,
    >,
    FS2: FoldingSchemeFullGadget<
        1,
        1,
        VerifierKey = (),
        VC: VectorCommitmentGadget<ConstraintField = FC::Field>,
    >,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<FC::Field>,
    ) -> Result<(), SynthesisError> {
        self.compute_next_state(
            cs,
            Default::default(),
            0,
            &Vec::dummy(self.step_circuit.state_len()),
            &Vec::dummy(self.step_circuit.state_len()),
            self.step_circuit.dummy_external_inputs(),
            &Dummy::dummy(self.arith1_config),
            &Dummy::dummy(self.arith1_config),
            Dummy::dummy(self.arith1_config),
            &Dummy::dummy(self.arith2_config),
            vec![Dummy::dummy(self.arith2_config); <FS1::RU as Var<_>>::Native::N_COMMITMENTS],
            vec![Dummy::dummy(self.arith2_config); <FS1::RU as Var<_>>::Native::N_COMMITMENTS],
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

    /// `N_INPUT_POINTS` specifies the number of input points that are folded in
    /// [`CycleFoldCircuit`] via random linear combinations.
    const N_INPUT_POINTS: usize;
    /// `N_UNIQUE_RANDOMNESSES` specifies the number of *unique* randomnesses
    /// allocated in [`CycleFoldCircuit`]. Although the linear combination in
    /// general consists of multiple randomnesses, some folding schemes (such as
    /// Nova and HyperNova) only need a single one. Thus, by setting this value,
    /// the circuit can learn how many randomnesses are used and how long the
    /// public inputs vector should be.
    const N_UNIQUE_RANDOMNESSES: usize;
    /// `RANDOMNESS_BIT_LENGTH` is the maximum bit length of a randomness `r_i`.
    const RANDOMNESS_BIT_LENGTH: usize;
    /// `FIELD_CAPACITY` is the maximum number of bits that can be stored in a
    /// field element.
    ///
    /// By default, `FIELD_CAPACITY` is set to `MODULUS_BIT_SIZE - 1`.
    ///
    /// Given a randomness `r_i` with `RANDOMNESS_BIT_LENGTH` bits, we need
    /// `RANDOMNESS_BIT_LENGTH / FIELD_CAPACITY` field elements to represent it
    /// *compactly* in-circuit.
    const FIELD_CAPACITY: usize = CF2::<Self::C>::MODULUS_BIT_SIZE as usize - 1;

    /// Public inputs length for the [`CycleFoldCircuit`], which depends on the
    /// above constants defined by the concrete folding scheme. For example:
    /// * In Nova, this is `|r| + |p_1| + |p_2| + |P|`
    /// * In HyperNova, this is `|r| + |p_i| * n_points + |P|`.
    /// * In ProtoGalaxy, this is `|[..., r_i, ...]| + |p_i| * n_points + |P|`.
    ///
    /// As explained above, `|r|` (i.e., the length of a single randomness) is
    /// `RANDOMNESS_BIT_LENGTH / FIELD_CAPACITY`.
    /// When there are multiple randomnesses, the length of `|[..., r_i, ...]|`
    /// is `RANDOMNESS_BIT_LENGTH * N_UNIQUE_RANDOMNESSES / FIELD_CAPACITY`, as
    /// the bits of all randomnesses are concatenated before being packed into
    /// field elements.
    /// The length of a point `p_i` when treated as public inputs is 2, as we
    /// only need the `x` and `y` coordinates of the point.
    ///
    /// Thus, `IO_LEN` is `RANDOMNESS_BIT_LENGTH * N_UNIQUE_RANDOMNESSES / FIELD_CAPACITY + 2 * (N_INPUT_POINTS + 1)`.
    const IO_LEN: usize = {
        (Self::RANDOMNESS_BIT_LENGTH * Self::N_UNIQUE_RANDOMNESSES).div_ceil(Self::FIELD_CAPACITY)
            + 2 * (Self::N_INPUT_POINTS + 1)
    };

    /// `alloc_points` allocates the points that are going to be folded in the
    /// [`CycleFoldCircuit`] via random linear combinations.
    ///
    /// The implementation must allocate the points as *witness* variables (i.e.
    /// by calling [`AllocVar::new_witness`]) first, then mark them as public
    /// inputs by calling [`CycleFoldConfig::mark_point_as_public`], and finally
    /// return the allocated witness variables.
    ///
    /// While it is possible to allocate the points as public inputs directly,
    /// we do not use this approach because this will create a longer vector of
    /// public inputs, which is not ideal for the augmented step circuit on the
    /// primary curve.
    fn alloc_points(
        &self,
        cs: ConstraintSystemRef<CF2<Self::C>>,
    ) -> Result<Vec<<Self::C as SonobeCurve>::Var>, SynthesisError>;

    /// `alloc_randomnesses` allocates the randomnesses used as coefficients of
    /// the random linear combinations in the `CycleFoldCircuit`.
    ///
    /// The implementation must allocate the randomnesses as *witness* variables
    /// (i.e. by calling [`AllocVar::new_witness`]) first, then mark them as
    /// public inputs by calling [`CycleFoldConfig::mark_point_as_public`], and
    /// finally return the allocated witness variables.
    ///
    /// See [`CycleFoldConfig::alloc_points`] for the reason why they need to be
    /// allocated as witness variables first and converted to public later.
    ///
    /// In addition, because the circuit computes `P = (P + p_i) * r_i` for each
    /// `i` from `N_INPUT_POINTS - 1` down to `0`, the actual linear combination
    /// is `P = r_0 * p_0 + (r_0 r_1) * p_1 + (r_0 r_1 r_2) * p_2 + ...`. Thus,
    /// to compute `P = R_0 p_0 + R_1 p_1 + R_2 p_2 + ...`, the implementation
    /// should return `r_0 = R_0, r_1 = R_1 / R_0, ..., r_i = R_i / R_{i - 1}`.
    /// A special case is `R_i = R^i`, where the allocated randomnesses become
    /// `r_0 = 1, r_1 = r_2 = ... = R`.
    fn alloc_randomnesses(
        &self,
        cs: ConstraintSystemRef<CF2<Self::C>>,
    ) -> Result<Vec<Vec<Boolean<CF2<Self::C>>>>, SynthesisError>;

    /// `mark_point_as_public` marks a point as public.
    ///
    /// The final vector of public inputs is shorter than the result of calling
    /// [`AllocVar::new_input`], because we only need the x and y coordinates of
    /// the point, but the `infinity` flag is not necessary.
    fn mark_point_as_public(point: &<Self::C as SonobeCurve>::Var) -> Result<(), SynthesisError> {
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
            FpVar::new_input(x.cs().clone(), || x.value())?.enforce_equal(x)?;
        }
        Ok(())
    }

    /// `mark_randomness_as_public` marks randomness as public.
    ///
    /// The final vector of public inputs is shorter than the result of calling
    /// [`AllocVar::new_input`], because we pack the bits of randomness into
    /// a compact field elements.
    fn mark_randomness_as_public(r: &[Boolean<CF2<Self::C>>]) -> Result<(), SynthesisError> {
        for bits in r.chunks(Self::FIELD_CAPACITY) {
            let x = Boolean::le_bits_to_fp(bits)?;
            FpVar::new_input(x.cs().clone(), || x.value())?.enforce_equal(&x)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CycleFoldCircuit<Cfg> {
    _cfg: PhantomData<Cfg>,
}

impl<Cfg: CycleFoldConfig> CycleFoldCircuit<Cfg> {
    pub fn fold_points(
        &self,
        cs: ConstraintSystemRef<CF2<Cfg::C>>,
        cfg: Cfg,
    ) -> Result<(), SynthesisError> {
        let rs = cfg.alloc_randomnesses(cs.clone())?;
        let points = cfg.alloc_points(cs.clone())?;

        #[cfg(test)]
        {
            assert_eq!(Cfg::N_INPUT_POINTS, points.len());
            assert_eq!(Cfg::N_INPUT_POINTS, rs.len());
            for r in &rs {
                assert_eq!(Cfg::RANDOMNESS_BIT_LENGTH, r.len());
            }
        }

        // A slightly optimized version of `scalar_mul_le`.
        fn point_mul<C: SonobeCurve>(
            point: &C::Var,
            r: &[Boolean<CF2<C>>],
        ) -> Result<C::Var, SynthesisError> {
            if r.is_constant() {
                let r = CF1::<C>::from(<CF1<C> as PrimeField>::BigInt::from_bits_le(&r.value()?));
                if r.is_one() {
                    return Ok(point.clone());
                }
            }
            point.scalar_mul_le(r.iter())
        }

        // Given a vector of points (over the primary curve) that are obtained
        // from the instances of the folding scheme, we fold them *natively* in
        // the CycleFold circuit (over the secondary curve).
        // * In Nova, we need to compute P = p_0 + R * p_1.
        //   - for the cmW we're computing: U_i1.cmW = U_i.cmW + R * u_i.cmW
        //   - for the cmE we're computing: U_i1.cmE = U_i.cmE + R * cmT + R^2 * u_i.cmE, where u_i.cmE
        //     is assumed to be 0, so, U_i1.cmE = U_i.cmE + R * cmT
        // * In HyperNova, we need to compute P = p_0 + R * p_1 + R^2 * p_2 + ... + R^{n-1} * p_{n-1}.
        // * In ProtoGalaxy, we need to compute P = R_0 * p_0 + R_1 * p_1 + R_2 * p_2 + ... + R_{n-1} * p_{n-1}.
        //
        // To handle HyperNova more efficiently (with less constraints), we do
        // P = ((((p_{n-1} * R) + p_{n-2}) * R + p_{n-3}) * R + ...) * R + p_0.
        // This can be done iteratively by computing P = (P + p_i) * R.
        //
        // We further generalize this to support ProtoGalaxy, which now becomes
        // P = (((((p_{n-1} * r_{n-1}) + p_{n-2}) * r_{n-2} + p_{n-3}) * r_{n-3} + ...) * r_1 + p_0) * r_0
        //
        // Here, r_0 = 1, r_1 = r_2 = ... = r_{n-1} = R for Nova and HyperNova,
        // and r_i = R_i / R_{i - 1} for ProtoGalaxy.
        let mut p_folded = point_mul::<Cfg::C>(
            &points[Cfg::N_INPUT_POINTS - 1],
            &rs[Cfg::N_INPUT_POINTS - 1],
        )?;
        for i in (0..Cfg::N_INPUT_POINTS - 1).rev() {
            p_folded = point_mul::<Cfg::C>(&(p_folded + &points[i]), &rs[i])?;
        }

        Cfg::mark_point_as_public(&p_folded)?;

        Ok(())
    }
}

impl<Cfg: CycleFoldConfig> ConstraintSynthesizer<CF2<Cfg::C>> for CycleFoldCircuit<Cfg> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CF2<Cfg::C>>,
    ) -> Result<(), SynthesisError> {
        self.fold_points(cs, Cfg::default())
    }
}
