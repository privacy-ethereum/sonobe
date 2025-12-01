use ark_ff::{Field, Zero};
use ark_poly::{DenseMultilinearExtension as MLE, Polynomial};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, marker::PhantomData, rand::RngCore, sync::Arc, UniformRand};
use sonobe_primitives::{
    algebra::ops::poly::MLEHelper,
    arithmetizations::{
        r1cs::{RelaxedInstance, RelaxedWitness, R1CS},
        Arith, ArithConfig, ArithRelation,
    },
    circuits::AssignmentsOwned,
    commitments::{
        GroupBasedVectorCommitment, VectorCommitmentDef, VectorCommitmentGadgetDef,
        VectorCommitmentOps,
    },
    relations::{Relation, WitnessInstanceSampler},
    traits::{Dummy, SonobeCurve, CF1},
};

use self::{
    instances::{circuits::RunningInstanceVar as RUVar, RunningInstance as RU},
    witnesses::RunningWitness as RW,
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeGadgetDef, GroupBasedFoldingSchemePrimaryDef,
    PlainInstance as IU, PlainInstanceVar as IUVar, PlainWitness as IW,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

#[derive(Clone)]
pub struct MovaKey<A, VC: VectorCommitmentDef> {
    pub arith: Arc<A>,
    pub ck: Arc<VC::Key>,
}

impl<A: Arith, VC: VectorCommitmentDef> DeciderKey for MovaKey<A, VC> {
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

impl<A, VC> Relation<RW<VC>, RU<VC>> for MovaKey<A, VC>
where
    A: for<'a> ArithRelation<
        RelaxedWitness<&'a [VC::Scalar]>,
        RelaxedInstance<&'a [VC::Scalar]>,
        Evaluation = Vec<VC::Scalar>,
    >,
    VC: VectorCommitmentOps<Scalar: Field>,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(
            &RelaxedWitness { w: &w.w, e: &w.e },
            &RelaxedInstance { x: &u.x, u: &u.u },
        )?;
        VC::open(&self.ck, &w.w, &w.r_w, &u.cm_w)?;

        (MLE::from_evaluations(&w.e).evaluate(&u.r_e) == u.v)
            .then_some(())
            .ok_or_else(|| {
                Error::UnsatisfiedRelation("Error term does not evaluate to claimed value".into())
            })
    }
}

impl<A, VC> Relation<IW<VC::Scalar>, IU<VC::Scalar>> for MovaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitmentDef,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC::Scalar>, u: &IU<VC::Scalar>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        Ok(())
    }
}

impl<A, VC: VectorCommitmentDef> WitnessInstanceSampler<IW<VC::Scalar>, IU<VC::Scalar>>
    for MovaKey<A, VC>
{
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(
        &self,
        z: Self::Source,
        _rng: &mut impl RngCore,
    ) -> Result<(IW<VC::Scalar>, IU<VC::Scalar>), Error> {
        Ok((z.private.into(), z.public.into()))
    }
}

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for MovaKey<A, VC>
where
    A: for<'a> ArithRelation<
        RelaxedWitness<&'a [VC::Scalar]>,
        RelaxedInstance<&'a [VC::Scalar]>,
        Evaluation = Vec<VC::Scalar>,
    >,
    VC: VectorCommitmentOps<Scalar: Field>,
{
    type Source = ();
    type Error = Error;

    fn sample(&self, _: Self::Source, rng: &mut impl RngCore) -> Result<(RW<VC>, RU<VC>), Error> {
        let u = VC::Scalar::rand(rng);
        let x = (0..self.arith.n_public_inputs())
            .map(|_| VC::Scalar::rand(rng))
            .collect::<Vec<_>>();
        let w = (0..self.arith.n_witnesses())
            .map(|_| VC::Scalar::rand(rng))
            .collect::<Vec<_>>();
        let e = self.arith.eval_relation(
            &RelaxedWitness { w: &w, e: &[] },
            &RelaxedInstance { x: &x, u: &u },
        )?;

        let (cm_w, r_w) = VC::commit(&self.ck, &w, rng)?;

        let r_e = (0..self.arith.log_constraints())
            .map(|_| VC::Scalar::rand(rng))
            .collect::<Vec<_>>();
        let v = MLE::from_evaluations(&e).evaluate(&r_e);

        Ok((RW { w, r_w, e }, RU { x, cm_w, u, r_e, v }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MovaProof<C: SonobeCurve> {
    pub h1_coeffs: Vec<CF1<C>>,
    pub t: CF1<C>,
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

pub struct Mova<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for Mova<VC, CHALLENGE_BITS>
{
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = IW<VC::Scalar>;
    type IU = IU<VC::Scalar>;

    type TranscriptField = VC::Scalar;
    type Arith = R1CS<VC::Scalar>;

    type Config = usize;
    type PublicParam = VC::Key;
    type DeciderKey = MovaKey<Self::Arith, VC>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = MovaProof<VC::Commitment>;
}

#[derive(Clone)]
pub struct MovaProofVar<C: SonobeCurve> {
    pub h1_coeffs: Vec<FpVar<CF1<C>>>,
    pub t: FpVar<CF1<C>>,
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

pub struct MovaGadget<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemeGadgetDef
    for MovaGadget<VC, CHALLENGE_BITS>
{
    type Native = Mova<VC, CHALLENGE_BITS>;

    type VC = VC::Gadget2;
    type RU = RUVar<VC::Gadget2>;
    type IU = IUVar<<VC::Gadget2 as VectorCommitmentGadgetDef>::ScalarVar>;
    type VerifierKey = ();
    type Challenge = [Boolean<VC::Scalar>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = MovaProofVar<VC::Commitment>;
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemePrimaryDef
    for Mova<VC, CHALLENGE_BITS>
{
    type Gadget = MovaGadget<VC, CHALLENGE_BITS>;
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective};
    use ark_ff::UniformRand;
    use ark_std::{error::Error, rand::Rng, test_rng};
    use sonobe_primitives::{
        circuits::utils::{satisfying_assignments_for_test, CircuitForTest},
        commitments::pedersen::Pedersen,
    };

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
        let mut rng = test_rng();
        test_mova_opt(10, &mut rng)?;
        Ok(())
    }
}
