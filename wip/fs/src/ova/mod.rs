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
    instances::{circuits::RunningInstanceVar as RUVar, RunningInstance as RU},
    witnesses::RunningWitness as RW,
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeGadgetDef, GroupBasedFoldingSchemePrimaryDef,
    GroupBasedFoldingSchemeSecondaryDef, PlainInstance as IU, PlainInstanceVar as IUVar,
    PlainWitness as IW,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

#[derive(Clone)]
pub struct OvaKey<A, VC: VectorCommitmentDef> {
    pub arith: Arc<A>,
    pub ck: Arc<VC::Key>,
}

impl<A: Arith, VC: VectorCommitmentDef> DeciderKey for OvaKey<A, VC> {
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
impl<A, VC> Relation<RW<VC>, RU<VC>> for OvaKey<A, VC>
where
    A: for<'a> ArithRelation<
        RelaxedWitness<&'a [VC::Scalar]>,
        RelaxedInstance<&'a [VC::Scalar]>,
        Evaluation = Vec<VC::Scalar>,
    >,
    VC: VectorCommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        let e = self.arith.eval_relation(
            &RelaxedWitness { w: &w.w, e: &[] },
            &RelaxedInstance { x: &u.x, u: &u.u },
        )?;
        VC::open(&self.ck, &[&w.w[..], &e].concat(), &w.r, &u.cm)?;
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC::Scalar>, IU<VC::Scalar>> for OvaKey<A, VC>
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
    for OvaKey<A, VC>
{
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(
        &self,
        z: Self::Source,
        _rng: impl RngCore,
    ) -> Result<(IW<VC::Scalar>, IU<VC::Scalar>), Error> {
        Ok((z.private.into(), z.public.into()))
    }
}

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for OvaKey<A, VC>
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

        let (cm, r) = VC::commit(&self.ck, &[&w[..], &e].concat(), &mut rng)?;
        Ok((RW { w, r }, RU { x, cm, u }))
    }
}

pub struct AbstractOva<VC, TF, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
    _tf: PhantomData<TF>,
}

pub type Ova<VC, const CHALLENGE_BITS: usize = 128> =
    AbstractOva<VC, <VC as VectorCommitmentDef>::Scalar, CHALLENGE_BITS>;

pub type CycleFoldOva<VC, const CHALLENGE_BITS: usize = 128> =
    AbstractOva<VC, CF2<<VC as VectorCommitmentDef>::Commitment>, CHALLENGE_BITS>;

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for AbstractOva<VC, TF, CHALLENGE_BITS>
{
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = IW<VC::Scalar>;
    type IU = IU<VC::Scalar>;

    type TranscriptField = TF;
    type Arith = R1CS<VC::Scalar>;

    type Config = (usize, usize);
    type PublicParam = VC::Key;
    type DeciderKey = OvaKey<Self::Arith, VC>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = VC::Commitment;
}

pub struct AbstractOvaGadget<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeGadgetDef
    for AbstractOvaGadget<VC, CHALLENGE_BITS>
where
    VC: VectorCommitmentGadgetDef<Native: GroupBasedVectorCommitment>,
{
    type Native = AbstractOva<VC::Native, VC::ConstraintField, CHALLENGE_BITS>;

    type VC = VC;
    type RU = RUVar<VC>;
    type IU = IUVar<VC::ScalarVar>;
    type VerifierKey = ();
    type Challenge = [Boolean<VC::ConstraintField>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = VC::CommitmentVar;
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemePrimaryDef
    for AbstractOva<VC, VC::Scalar, CHALLENGE_BITS>
{
    type Gadget = AbstractOvaGadget<VC::Gadget2, CHALLENGE_BITS>;
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize>
    GroupBasedFoldingSchemeSecondaryDef for AbstractOva<VC, CF2<VC::Commitment>, CHALLENGE_BITS>
{
    type Gadget = AbstractOvaGadget<VC::Gadget1, CHALLENGE_BITS>;
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

    fn test_ova_opt<TF: SonobeField>(
        rounds: usize,
        mut rng: impl RngCore,
    ) -> Result<(), Box<dyn Error>> {
        let config = (4, 4);

        test_folding_scheme::<AbstractOva<Pedersen<G1Projective, true>, TF>, 1, 1>(
            config,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractOva<Pedersen<G1Projective, false>, TF>, 1, 1>(
            config,
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
    fn test_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        test_ova_opt::<Fr>(10, &mut rng)?;
        test_ova_opt::<Fq>(10, &mut rng)?;
        Ok(())
    }
}
