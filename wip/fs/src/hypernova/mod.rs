use ark_ff::{Field, One, PrimeField};
use ark_poly::MultilinearExtension;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow, cfg_iter, marker::PhantomData, rand::RngCore, sync::Arc, UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    arithmetizations::{
        ccs::{CCSConfig, CCSVariant, CCS},
        r1cs::R1CSConfig,
        Arith, ArithConfig, ArithRelation, Error as ArithError,
    },
    circuits::{Assignments, AssignmentsOwned},
    commitments::{GroupBasedVectorCommitment, VectorCommitmentDef, VectorCommitmentOps},
    relations::{Relation, WitnessInstanceSampler},
    traits::Dummy,
};

use self::{
    instances::{
        circuits::{CCCSInstanceVar as IUVar, LCCCSInstanceVar as RUVar},
        CCCSInstance as IU, LCCCSInstance as RU,
    },
    witnesses::{CCCSWitness as IW, LCCCSWitness as RW},
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeGadgetDef, GroupBasedFoldingSchemePrimaryDef,
    PlainInstance as PU, PlainWitness as PW,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

#[derive(Clone)]
pub struct HyperNovaKey<A, VC: VectorCommitmentDef> {
    arith: Arc<A>,
    ck: Arc<VC::Key>,
}

impl<A: Arith, VC: VectorCommitmentDef> DeciderKey for HyperNovaKey<A, VC> {
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

impl<VC: VectorCommitmentDef<Scalar: Field>, V: CCSVariant> ArithRelation<RW<VC>, RU<VC>>
    for CCS<VC::Scalar, V>
{
    type Evaluation = Vec<VC::Scalar>;

    fn eval_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<Self::Evaluation, ArithError> {
        let z = Assignments::from((u.u, &u.x, &w.w));
        Ok(self
            .mles(z)
            .iter()
            .map(|mle| mle.fix_variables(&u.r_x)[0])
            .collect())
    }

    fn check_evaluation(_w: &RW<VC>, u: &RU<VC>, e: Self::Evaluation) -> Result<(), ArithError> {
        cfg_iter!(e)
            .zip(&u.v)
            .all(|(e, v)| e == v)
            .then_some(())
            .ok_or(ArithError::UnsatisfiedAssignments(
                "Evaluation contains non-zero values".into(),
            ))
    }
}

impl<A, VC> Relation<RW<VC>, RU<VC>> for HyperNovaKey<A, VC>
where
    A: ArithRelation<RW<VC>, RU<VC>>,
    VC: VectorCommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        VC::open(&self.ck, &w.w, &w.r, &u.cm)?;
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC>, IU<VC>> for HyperNovaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC>, u: &IU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(&w.w, &u.x)?;
        VC::open(&self.ck, &w.w, &w.r, &u.cm)?;
        Ok(())
    }
}

impl<A, VC> Relation<PW<VC::Scalar>, PU<VC::Scalar>> for HyperNovaKey<A, VC>
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

impl<A, VC: VectorCommitmentOps> WitnessInstanceSampler<IW<VC>, IU<VC>> for HyperNovaKey<A, VC> {
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, rng: impl RngCore) -> Result<(IW<VC>, IU<VC>), Error> {
        let (w, x) = (z.private, z.public);
        let (cm, r) = VC::commit(&self.ck, &w, rng)?;
        Ok((IW { w, r }, IU { cm, x }))
    }
}

impl<A, VC: VectorCommitmentDef> WitnessInstanceSampler<PW<VC::Scalar>, PU<VC::Scalar>>
    for HyperNovaKey<A, VC>
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

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for HyperNovaKey<A, VC>
where
    A: ArithRelation<RW<VC>, RU<VC>, Evaluation = Vec<VC::Scalar>>,
    VC: VectorCommitmentOps,
{
    type Source = ();
    type Error = Error;

    #[allow(non_snake_case)]
    fn sample(&self, _: Self::Source, mut rng: impl RngCore) -> Result<(RW<VC>, RU<VC>), Error> {
        let u = VC::Scalar::rand(&mut rng);
        let x = (0..self.arith.n_public_inputs())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let w = (0..self.arith.n_witnesses())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let (cm, r) = VC::commit(&self.ck, &w, &mut rng)?;

        let r_x = (0..self.arith.log_constraints())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect();

        let W = RW { w, r };
        let mut U = RU {
            cm,
            x,
            u,
            r_x,
            v: vec![],
        };
        U.v = self.arith.eval_relation(&W, &U)?;

        Ok((W, U))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NIMFSProof<F, const M: usize, const N: usize> {
    pub sc_proof: Vec<Vec<F>>,
    pub sigmas: Vec<F>,
    pub thetas: Vec<F>,
}

impl<F: Field, const M: usize, const N: usize, V: CCSVariant> Dummy<&CCSConfig<V>>
    for NIMFSProof<F, M, N>
{
    fn dummy(cfg: &CCSConfig<V>) -> Self {
        let s = cfg.log_constraints();
        let d = cfg.degree();
        let t = V::n_matrices();
        Self {
            sc_proof: vec![vec![F::zero(); d + 2]; s],
            sigmas: vec![F::zero(); t * M],
            thetas: vec![F::zero(); t * N],
        }
    }
}

pub struct HyperNova<VC, V: CCSVariant = R1CSConfig, const CHALLENGE_BITS: usize = 128> {
    _v: PhantomData<(VC, V)>,
}

impl<VC: GroupBasedVectorCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for HyperNova<VC, V, CHALLENGE_BITS>
{
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = IW<VC>;
    type IU = IU<VC>;

    type TranscriptField = VC::Scalar;
    type Arith = CCS<VC::Scalar, V>;

    type Config = usize;
    type PublicParam = VC::Key;
    type DeciderKey = HyperNovaKey<Self::Arith, VC>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = NIMFSProof<VC::Scalar, M, N>;
}

// TODO: experimental design
struct HyperNova2<VC, V: CCSVariant = R1CSConfig, const CHALLENGE_BITS: usize = 128> {
    _v: PhantomData<(VC, V)>,
}

impl<VC: GroupBasedVectorCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for HyperNova2<VC, V, CHALLENGE_BITS>
{
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = PW<VC::Scalar>;
    type IU = PU<VC::Scalar>;

    type TranscriptField = VC::Scalar;
    type Arith = CCS<VC::Scalar, V>;

    type Config = usize;
    type PublicParam = VC::Key;
    type DeciderKey = HyperNovaKey<Self::Arith, VC>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> =
        ([VC::Commitment; N], NIMFSProof<VC::Scalar, M, N>);
}

#[derive(Clone)]
pub struct NIMFSProofVar<F: PrimeField, const M: usize, const N: usize> {
    pub sc_proof: Vec<Vec<FpVar<F>>>,
    pub sigmas: Vec<FpVar<F>>,
    pub thetas: Vec<FpVar<F>>,
}

impl<F: PrimeField, const M: usize, const N: usize> AllocVar<NIMFSProof<F, M, N>, F>
    for NIMFSProofVar<F, M, N>
{
    fn new_variable<T: Borrow<NIMFSProof<F, M, N>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let proof = f()?.borrow().clone();

        Ok(NIMFSProofVar {
            sc_proof: proof
                .sc_proof
                .iter()
                .map(|v| Vec::new_variable(cs.clone(), || Ok(&v[..]), mode))
                .collect::<Result<Vec<Vec<_>>, SynthesisError>>()?,
            sigmas: Vec::new_variable(cs.clone(), || Ok(&proof.sigmas[..]), mode)?,
            thetas: Vec::new_variable(cs.clone(), || Ok(&proof.thetas[..]), mode)?,
        })
    }
}

impl<F: PrimeField, const M: usize, const N: usize> GR1CSVar<F> for NIMFSProofVar<F, M, N> {
    type Value = NIMFSProof<F, M, N>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.sc_proof
            .iter()
            .fold(ConstraintSystemRef::None, |cs, v| cs.or(v.cs()))
            .or(self.sigmas.cs())
            .or(self.thetas.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(NIMFSProof {
            sc_proof: self
                .sc_proof
                .iter()
                .map(|v| v.value())
                .collect::<Result<Vec<Vec<F>>, SynthesisError>>()?,
            sigmas: self.sigmas.value()?,
            thetas: self.thetas.value()?,
        })
    }
}

pub struct HyperNovaGadget<VC, V: CCSVariant = R1CSConfig, const CHALLENGE_BITS: usize = 128> {
    _v: PhantomData<(VC, V)>,
}

impl<VC: GroupBasedVectorCommitment, V: CCSVariant, const CHALLENGE_BITS: usize>
    FoldingSchemeGadgetDef for HyperNovaGadget<VC, V, CHALLENGE_BITS>
{
    type Native = HyperNova<VC, V, CHALLENGE_BITS>;

    type VC = VC::Gadget2;
    type RU = RUVar<VC::Gadget2>;
    type IU = IUVar<VC::Gadget2>;
    type VerifierKey = ();
    type Challenge = [Boolean<VC::Scalar>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = NIMFSProofVar<VC::Scalar, M, N>;
}

impl<VC: GroupBasedVectorCommitment, V: CCSVariant, const CHALLENGE_BITS: usize>
    GroupBasedFoldingSchemePrimaryDef for HyperNova<VC, V, CHALLENGE_BITS>
{
    type Gadget = HyperNovaGadget<VC, V, CHALLENGE_BITS>;
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

    fn test_hypernova_opt<const M: usize, const N: usize>(
        rounds: usize,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>> {
        test_folding_scheme::<HyperNova<Pedersen<G1Projective, true>>, M, N>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<HyperNova<Pedersen<G1Projective, false>>, M, N>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<HyperNova2<Pedersen<G1Projective, true>>, M, N>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<HyperNova2<Pedersen<G1Projective, false>>, M, N>(
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
    fn test_hypernova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        test_hypernova_opt::<1, 1>(10, &mut rng)?;
        test_hypernova_opt::<1, 3>(10, &mut rng)?;
        test_hypernova_opt::<3, 1>(10, &mut rng)?;
        test_hypernova_opt::<3, 3>(10, &mut rng)?;
        test_hypernova_opt::<0, 5>(10, &mut rng)?;
        test_hypernova_opt::<5, 0>(10, &mut rng)?;
        Ok(())
    }
}
