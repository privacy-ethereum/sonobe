//! This module implements the Ova folding scheme, which is introduced in this
//! [note].
//!
//! [note]: https://hackmd.io/V4838nnlRKal9ZiTHiGYzw

use ark_r1cs_std::boolean::Boolean;
use ark_std::{UniformRand, marker::PhantomData, rand::RngCore, sync::Arc};
use sonobe_primitives::{
    arithmetizations::{
        Arith, ArithConfig, ArithRelation,
        r1cs::{R1CS, RelaxedInstance, RelaxedWitness},
    },
    circuits::AssignmentsOwned,
    commitments::{CommitmentDef, CommitmentDefGadget, CommitmentOps, GroupBasedCommitment},
    relations::{Relation, WitnessInstanceSampler},
    traits::{CF2, SonobeField},
};

use self::{
    instances::{RunningInstance as RU, circuits::RunningInstanceVar as RUVar},
    witnesses::RunningWitness as RW,
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeDefGadget, GroupBasedFoldingSchemePrimaryDef,
    GroupBasedFoldingSchemeSecondaryDef, PlainInstance as IU, PlainInstanceVar as IUVar,
    PlainWitness as IW,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

/// [`OvaKey`] is Ova's decider key.
#[derive(Clone)]
pub struct OvaKey<A, CM: CommitmentDef> {
    arith: Arc<A>,
    ck: Arc<CM::Key>,
}

impl<A: Arith, CM: CommitmentDef> DeciderKey for OvaKey<A, CM> {
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

impl<A, CM> Relation<RW<CM>, RU<CM>> for OvaKey<A, CM>
where
    A: for<'a> ArithRelation<
            RelaxedWitness<&'a [CM::Scalar]>,
            RelaxedInstance<&'a [CM::Scalar]>,
            Evaluation = Vec<CM::Scalar>,
        >,
    CM: CommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<CM>, u: &RU<CM>) -> Result<(), Self::Error> {
        let e = self.arith.eval_relation(
            &RelaxedWitness { w: &w.w, e: &[] },
            &RelaxedInstance { x: &u.x, u: &u.u },
        )?;
        CM::open(&self.ck, &[&w.w[..], &e].concat(), &w.r, &u.cm)?;
        Ok(())
    }
}

impl<A, CM> Relation<IW<CM::Scalar>, IU<CM::Scalar>> for OvaKey<A, CM>
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
    for OvaKey<A, CM>
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

impl<A, CM> WitnessInstanceSampler<RW<CM>, RU<CM>> for OvaKey<A, CM>
where
    A: for<'a> ArithRelation<
            RelaxedWitness<&'a [CM::Scalar]>,
            RelaxedInstance<&'a [CM::Scalar]>,
            Evaluation = Vec<CM::Scalar>,
        >,
    CM: CommitmentOps,
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

        let (cm, r) = CM::commit(&self.ck, &[&w[..], &e].concat(), &mut rng)?;
        Ok((RW { w, r }, RU { x, cm, u }))
    }
}

/// [`AbstractOva`] implements the Ova folding scheme which can operate on
/// both the primary and secondary curves.
pub struct AbstractOva<CM, TF, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<(CM, TF)>,
}

/// [`Ova`] is the main Ova folding scheme on the primary curve.
pub type Ova<CM, const CHALLENGE_BITS: usize = 128> =
    AbstractOva<CM, <CM as CommitmentDef>::Scalar, CHALLENGE_BITS>;

/// [`CycleFoldOva`] is the Ova folding scheme on the secondary curve which can
/// be used as the folding scheme for folding CycleFold instances.
pub type CycleFoldOva<CM, const CHALLENGE_BITS: usize = 128> =
    AbstractOva<CM, CF2<<CM as CommitmentDef>::Commitment>, CHALLENGE_BITS>;

impl<CM: GroupBasedCommitment, TF: SonobeField, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for AbstractOva<CM, TF, CHALLENGE_BITS>
{
    type CM = CM;
    type RW = RW<CM>;
    type RU = RU<CM>;
    type IW = IW<CM::Scalar>;
    type IU = IU<CM::Scalar>;

    type TranscriptField = TF;
    type Arith = R1CS<CM::Scalar>;

    type Config = (usize, usize);
    type PublicParam = CM::Key;
    type DeciderKey = OvaKey<Self::Arith, CM>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = CM::Commitment;
}

/// [`AbstractOvaGadget`] is the in-circuit gadget for [`AbstractOva`].
pub struct AbstractOvaGadget<CM, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<CM>,
}

impl<CM, const CHALLENGE_BITS: usize> FoldingSchemeDefGadget
    for AbstractOvaGadget<CM, CHALLENGE_BITS>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    type Widget = AbstractOva<CM::Widget, CM::ConstraintField, CHALLENGE_BITS>;

    type CM = CM;
    type RU = RUVar<CM>;
    type IU = IUVar<CM::ScalarVar>;
    type VerifierKey = ();
    type Challenge = [Boolean<CM::ConstraintField>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = CM::CommitmentVar;
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemePrimaryDef
    for AbstractOva<CM, CM::Scalar, CHALLENGE_BITS>
{
    type Gadget = AbstractOvaGadget<CM::Gadget2, CHALLENGE_BITS>;
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemeSecondaryDef
    for AbstractOva<CM, CF2<CM::Commitment>, CHALLENGE_BITS>
{
    type Gadget = AbstractOvaGadget<CM::Gadget1, CHALLENGE_BITS>;
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_ff::UniformRand;
    use ark_std::{error::Error, rand::thread_rng};
    use sonobe_primitives::{
        circuits::utils::{CircuitForTest, satisfying_assignments_for_test},
        commitments::pedersen::Pedersen,
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

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
        let mut rng = thread_rng();

        test_ova_opt::<Fr>(10, &mut rng)?;
        test_ova_opt::<Fq>(10, &mut rng)?;
        Ok(())
    }
}
