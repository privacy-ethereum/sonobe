use ark_r1cs_std::boolean::Boolean;
use ark_std::{marker::PhantomData, rand::RngCore, sync::Arc, UniformRand};
use sonobe_primitives::{
    arithmetizations::{
        r1cs::{RelaxedInstance, RelaxedWitness, R1CS},
        Arith, ArithRelation,
    },
    circuits::AssignmentsOwned,
    commitments::{
        GroupBasedVectorCommitment, VectorCommitmentDef, VectorCommitmentGadgetDef,
        VectorCommitmentOps,
    },
    relations::{Relation, WitnessInstanceSampler},
    traits::{SonobeField, CF2},
};

use self::{
    instances::{
        circuits::{IncomingInstanceVar as IUVar, RunningInstanceVar as RUVar},
        IncomingInstance as IU, RunningInstance as RU,
    },
    witnesses::{IncomingWitness as IW, RunningWitness as RW},
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeGadgetDef, GroupBasedFoldingSchemePrimaryDef,
    GroupBasedFoldingSchemeSecondaryDef, PlainInstance as PU, PlainWitness as PW,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

#[derive(Clone)]
pub struct NovaKey<A, VC: VectorCommitmentDef> {
    arith: Arc<A>,
    ck: Arc<VC::Key>,
}

impl<A: Arith, VC: VectorCommitmentDef> DeciderKey for NovaKey<A, VC> {
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

impl<A, VC> Relation<RW<VC>, RU<VC>> for NovaKey<A, VC>
where
    A: for<'a> ArithRelation<RelaxedWitness<&'a [VC::Scalar]>, RelaxedInstance<&'a [VC::Scalar]>>,
    VC: VectorCommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(
            &RelaxedWitness { w: &w.w, e: &w.e },
            &RelaxedInstance { x: &u.x, u: &u.u },
        )?;
        VC::open(&self.ck, &w.w, &w.r_w, &u.cm_w)?;
        VC::open(&self.ck, &w.e, &w.r_e, &u.cm_e)?;
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC>, IU<VC>> for NovaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC>, u: &IU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(&w.w, &u.x)?;
        VC::open(&self.ck, &w.w, &w.r_w, &u.cm_w)?;
        Ok(())
    }
}

impl<A, VC> Relation<PW<VC::Scalar>, PU<VC::Scalar>> for NovaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitmentDef,
{
    type Error = Error;

    fn check_relation(&self, w: &PW<VC::Scalar>, u: &PU<VC::Scalar>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        Ok(())
    }
}

impl<A, VC: VectorCommitmentOps> WitnessInstanceSampler<IW<VC>, IU<VC>> for NovaKey<A, VC> {
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, rng: impl RngCore) -> Result<(IW<VC>, IU<VC>), Error> {
        let (w, x) = (z.private, z.public);
        let (cm_w, r_w) = VC::commit(&self.ck, &w, rng)?;
        Ok((IW { w, r_w }, IU { cm_w, x }))
    }
}

impl<A, VC: VectorCommitmentDef> WitnessInstanceSampler<PW<VC::Scalar>, PU<VC::Scalar>>
    for NovaKey<A, VC>
{
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(
        &self,
        z: Self::Source,
        _rng: impl RngCore,
    ) -> Result<(PW<VC::Scalar>, PU<VC::Scalar>), Error> {
        Ok((z.private.into(), z.public.into()))
    }
}

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for NovaKey<A, VC>
where
    A: for<'a> ArithRelation<
        RelaxedWitness<&'a [VC::Scalar]>,
        RelaxedInstance<&'a [VC::Scalar]>,
        Evaluation = Vec<VC::Scalar>,
    >,
    VC: VectorCommitmentOps,
{
    type Source = ();
    type Error = Error;

    fn sample(&self, _: Self::Source, mut rng: impl RngCore) -> Result<(RW<VC>, RU<VC>), Error> {
        let u = VC::Scalar::rand(&mut rng);
        let x = (0..self.arith.n_public_inputs())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let w = (0..self.arith.n_witnesses())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let e = self.arith.eval_relation(
            &RelaxedWitness { w: &w, e: &[] },
            &RelaxedInstance { x: &x, u: &u },
        )?;

        let (cm_w, r_w) = VC::commit(&self.ck, &w, &mut rng)?;
        let (cm_e, r_e) = VC::commit(&self.ck, &e, &mut rng)?;
        Ok((RW { w, r_w, e, r_e }, RU { cm_w, x, cm_e, u }))
    }
}

// used for the RO challenges.
// From [Srinath Setty](https://microsoft.com/en-us/research/people/srinath/): In Nova, soundness
// error ≤ 2/|S|, where S is the subset of the field F from which the challenges are drawn. In this
// case, we keep the size of S close to 2^128.
pub struct AbstractNova<VC, TF, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
    _tf: PhantomData<TF>,
}

pub type Nova<VC, const CHALLENGE_BITS: usize = 128> =
    AbstractNova<VC, <VC as VectorCommitmentDef>::Scalar, CHALLENGE_BITS>;

pub type CycleFoldNova<VC, const CHALLENGE_BITS: usize = 128> =
    AbstractNova<VC, CF2<<VC as VectorCommitmentDef>::Commitment>, CHALLENGE_BITS>;

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for AbstractNova<VC, TF, CHALLENGE_BITS>
{
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = IW<VC>;
    type IU = IU<VC>;

    type TranscriptField = TF;
    type Arith = R1CS<VC::Scalar>;

    type Config = usize;
    type PublicParam = VC::Key;
    type DeciderKey = NovaKey<Self::Arith, VC>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = VC::Commitment;
}

// used for the RO challenges.
// From [Srinath Setty](https://microsoft.com/en-us/research/people/srinath/): In Nova, soundness
// error ≤ 2/|S|, where S is the subset of the field F from which the challenges are drawn. In this
// case, we keep the size of S close to 2^128.
// TODO: experimental design
struct AbstractNova2<VC, TF, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
    _tf: PhantomData<TF>,
}

type Nova2<VC, const CHALLENGE_BITS: usize = 128> =
    AbstractNova2<VC, <VC as VectorCommitmentDef>::Scalar, CHALLENGE_BITS>;

type CycleFoldNova2<VC, const CHALLENGE_BITS: usize = 128> =
    AbstractNova2<VC, CF2<<VC as VectorCommitmentDef>::Commitment>, CHALLENGE_BITS>;

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for AbstractNova2<VC, TF, CHALLENGE_BITS>
{
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = PW<VC::Scalar>;
    type IU = PU<VC::Scalar>;

    type TranscriptField = TF;
    type Arith = R1CS<VC::Scalar>;

    type Config = usize;
    type PublicParam = VC::Key;
    type DeciderKey = NovaKey<Self::Arith, VC>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = (VC::Commitment, VC::Commitment);
}

pub struct AbstractNovaGadget<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeGadgetDef
    for AbstractNovaGadget<VC, CHALLENGE_BITS>
where
    VC: VectorCommitmentGadgetDef<Native: GroupBasedVectorCommitment>,
{
    type Native = AbstractNova<VC::Native, VC::ConstraintField, CHALLENGE_BITS>;

    type VC = VC;
    type RU = RUVar<VC>;
    type IU = IUVar<VC>;
    type VerifierKey = ();
    type Challenge = [Boolean<VC::ConstraintField>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = VC::CommitmentVar;
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemePrimaryDef
    for AbstractNova<VC, VC::Scalar, CHALLENGE_BITS>
{
    type Gadget = AbstractNovaGadget<VC::Gadget2, CHALLENGE_BITS>;
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize>
    GroupBasedFoldingSchemeSecondaryDef for AbstractNova<VC, CF2<VC::Commitment>, CHALLENGE_BITS>
{
    type Gadget = AbstractNovaGadget<VC::Gadget1, CHALLENGE_BITS>;
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_ff::UniformRand;
    use ark_std::{error::Error, test_rng};
    use sonobe_primitives::{
        circuits::utils::{satisfying_assignments_for_test, CircuitForTest},
        commitments::pedersen::Pedersen,
    };

    use super::*;
    use crate::tests::test_folding_scheme;

    fn test_nova_opt<TF: SonobeField>(
        rounds: usize,
        mut rng: impl RngCore,
    ) -> Result<(), Box<dyn Error>> {
        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, true>, TF>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, false>, TF>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, true>, TF>, 2, 0>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, false>, TF>, 2, 0>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova2<Pedersen<G1Projective, true>, TF>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova2<Pedersen<G1Projective, false>, TF>, 1, 1>(
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
    fn test_nova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        test_nova_opt::<Fr>(10, &mut rng)?;
        test_nova_opt::<Fq>(10, &mut rng)?;
        Ok(())
    }
}
