//! This module implements the Mova folding scheme, which is introduced in this
//! [paper].
//!
//! [paper]: https://eprint.iacr.org/2024/1220.pdf

use ark_ff::{Field, Zero};
use ark_poly::{DenseMultilinearExtension as MLE, Polynomial};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{UniformRand, borrow::Borrow, marker::PhantomData, rand::RngCore, sync::Arc};
use sonobe_primitives::{
    algebra::ops::poly::MLEHelper,
    arithmetizations::{
        Arith, ArithConfig, ArithRelation,
        r1cs::{R1CS, RelaxedInstance, RelaxedWitness},
    },
    circuits::AssignmentsOwned,
    commitments::{CommitmentDef, CommitmentDefGadget, CommitmentOps, GroupBasedCommitment},
    relations::{Relation, WitnessInstanceSampler},
    traits::{CF1, Dummy, SonobeCurve},
};

use self::{
    instances::{RunningInstance as RU, circuits::RunningInstanceVar as RUVar},
    witnesses::RunningWitness as RW,
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeDefGadget, GroupBasedFoldingSchemePrimaryDef,
    PlainInstance as IU, PlainInstanceVar as IUVar, PlainWitness as IW,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

/// [`MovaKey`] is Mova's decider key.
#[derive(Clone)]
pub struct MovaKey<A, CM: CommitmentDef> {
    arith: Arc<A>,
    ck: Arc<CM::Key>,
}

impl<A: Arith, CM: CommitmentDef> DeciderKey for MovaKey<A, CM> {
    type ProverKey = Self;
    type VerifierKey = ();
    type ArithConfig = A::Config;

    fn to_pk(&self) -> &Self::ProverKey {
        self
    }

    fn to_vk(&self) -> &Self::VerifierKey {
        &()
    }

    fn to_arith_config(&self) -> &Self::ArithConfig {
        self.arith.config()
    }
}

impl<A, CM> Relation<RW<CM>, RU<CM>> for MovaKey<A, CM>
where
    A: for<'a> ArithRelation<
            RelaxedWitness<&'a [CM::Scalar]>,
            RelaxedInstance<&'a [CM::Scalar]>,
            Evaluation = Vec<CM::Scalar>,
        >,
    CM: CommitmentOps<Scalar: Field>,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<CM>, u: &RU<CM>) -> Result<(), Self::Error> {
        self.arith.check_relation(
            &RelaxedWitness { w: &w.w, e: &w.e },
            &RelaxedInstance { x: &u.x, u: &u.u },
        )?;
        CM::open(&self.ck, &w.w, &w.r_w, &u.cm_w)?;

        (MLE::from_evaluations(&w.e).evaluate(&u.r_e) == u.v)
            .then_some(())
            .ok_or_else(|| {
                Error::UnsatisfiedRelation("Error term does not evaluate to claimed value".into())
            })
    }
}

impl<A, CM> Relation<IW<CM::Scalar>, IU<CM::Scalar>> for MovaKey<A, CM>
where
    A: ArithRelation<Vec<CM::Scalar>, Vec<CM::Scalar>>,
    CM: CommitmentDef,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<CM::Scalar>, u: &IU<CM::Scalar>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        Ok(())
    }
}

impl<A, CM: CommitmentDef> WitnessInstanceSampler<IW<CM::Scalar>, IU<CM::Scalar>>
    for MovaKey<A, CM>
{
    type Source = AssignmentsOwned<CM::Scalar>;
    type Error = Error;

    fn sample(
        &self,
        z: Self::Source,
        _rng: impl RngCore,
    ) -> Result<(IW<CM::Scalar>, IU<CM::Scalar>), Error> {
        Ok((z.private.into(), z.public.into()))
    }
}

impl<A, CM> WitnessInstanceSampler<RW<CM>, RU<CM>> for MovaKey<A, CM>
where
    A: for<'a> ArithRelation<
            RelaxedWitness<&'a [CM::Scalar]>,
            RelaxedInstance<&'a [CM::Scalar]>,
            Evaluation = Vec<CM::Scalar>,
        >,
    CM: CommitmentOps<Scalar: Field>,
{
    type Source = ();
    type Error = Error;

    fn sample(&self, _: Self::Source, mut rng: impl RngCore) -> Result<(RW<CM>, RU<CM>), Error> {
        let cfg = self.arith.config();

        let u = CM::Scalar::rand(&mut rng);
        let x = (0..cfg.n_public_inputs())
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let w = (0..cfg.n_witnesses())
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let e = self.arith.eval_relation(
            &RelaxedWitness { w: &w, e: &[] },
            &RelaxedInstance { x: &x, u: &u },
        )?;

        let (cm_w, r_w) = CM::commit(&self.ck, &w, &mut rng)?;

        let r_e = (0..cfg.log_constraints())
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let v = MLE::from_evaluations(&e).evaluate(&r_e);

        Ok((RW { w, r_w, e }, RU { x, cm_w, u, r_e, v }))
    }
}

/// [`MovaProof`] is Mova's proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MovaProof<C: SonobeCurve> {
    /// [`MovaProof::h1_coeffs`] is the `h_1` polynomial.
    pub h1_coeffs: Vec<CF1<C>>,
    /// [`MovaProof::t`] is the evaluation of the `T` polynomial's MLE at the
    /// challenge point `r_e`.
    pub t: CF1<C>,
    /// [`MovaProof::cm_w`] is the witness commitment.
    pub cm_w: C,
}

impl<C: SonobeCurve, Cfg: ArithConfig> Dummy<&Cfg> for MovaProof<C> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            h1_coeffs: vec![Zero::zero(); cfg.log_constraints()],
            t: Zero::zero(),
            cm_w: Zero::zero(),
        }
    }
}

/// [`Mova`] implements the Mova folding scheme.
pub struct Mova<CM, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<CM>,
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for Mova<CM, CHALLENGE_BITS>
{
    type CM = CM;
    type RW = RW<CM>;
    type RU = RU<CM>;
    type IW = IW<CM::Scalar>;
    type IU = IU<CM::Scalar>;

    type TranscriptField = CM::Scalar;
    type Arith = R1CS<CM::Scalar>;

    type Config = usize;
    type PublicParam = CM::Key;
    type DeciderKey = MovaKey<Self::Arith, CM>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = MovaProof<CM::Commitment>;
}

/// [`MovaProofVar`] is the in-circuit variable for [`MovaProof`].
#[derive(Clone)]
pub struct MovaProofVar<C: SonobeCurve> {
    /// [`MovaProofVar::h1_coeffs`] is the `h_1` polynomial.
    pub h1_coeffs: Vec<FpVar<CF1<C>>>,
    /// [`MovaProofVar::t`] is the evaluation of the `T` polynomial's MLE at the
    /// challenge point `r_e`.
    pub t: FpVar<CF1<C>>,
    /// [`MovaProofVar::cm_w`] is the witness commitment.
    pub cm_w: C::EmulatedVar<CF1<C>>,
}

impl<C: SonobeCurve> AllocVar<MovaProof<C>, CF1<C>> for MovaProofVar<C> {
    fn new_variable<T: Borrow<MovaProof<C>>>(
        cs: impl Into<Namespace<CF1<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let proof = f()?.borrow().clone();

        Ok(Self {
            h1_coeffs: Vec::new_variable(cs.clone(), || Ok(&proof.h1_coeffs[..]), mode)?,
            t: FpVar::new_variable(cs.clone(), || Ok(proof.t), mode)?,
            cm_w: AllocVar::new_variable(cs.clone(), || Ok(proof.cm_w), mode)?,
        })
    }
}

impl<C: SonobeCurve> GR1CSVar<CF1<C>> for MovaProofVar<C> {
    type Value = MovaProof<C>;

    fn cs(&self) -> ConstraintSystemRef<CF1<C>> {
        self.h1_coeffs.cs().or(self.t.cs()).or(self.cm_w.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(MovaProof {
            h1_coeffs: self.h1_coeffs.value()?,
            t: self.t.value()?,
            cm_w: self.cm_w.value()?,
        })
    }
}

/// [`MovaGadget`] is the in-circuit gadget for [`Mova`].
pub struct MovaGadget<CM, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<CM>,
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeDefGadget
    for MovaGadget<CM, CHALLENGE_BITS>
{
    type Widget = Mova<CM, CHALLENGE_BITS>;

    type CM = CM::Gadget2;
    type RU = RUVar<CM::Gadget2>;
    type IU = IUVar<<CM::Gadget2 as CommitmentDefGadget>::ScalarVar>;
    type VerifierKey = ();
    type Challenge = [Boolean<CM::Scalar>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = MovaProofVar<CM::Commitment>;
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemePrimaryDef
    for Mova<CM, CHALLENGE_BITS>
{
    type Gadget = MovaGadget<CM, CHALLENGE_BITS>;
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective};
    use ark_ff::UniformRand;
    use ark_std::{
        error::Error,
        rand::{Rng, thread_rng},
    };
    use sonobe_primitives::{
        circuits::utils::{CircuitForTest, satisfying_assignments_for_test},
        commitments::pedersen::Pedersen,
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::tests::test_folding_scheme;

    fn test_mova_opt(rounds: usize, mut rng: impl Rng) -> Result<(), Box<dyn Error>> {
        test_folding_scheme::<Mova<Pedersen<G1Projective, true>>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<Mova<Pedersen<G1Projective, false>>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;
        Ok(())
    }

    #[test]
    fn test_mova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        test_mova_opt(10, &mut rng)?;
        Ok(())
    }
}
