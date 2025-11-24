use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow, cfg_into_iter, log2, marker::PhantomData, rand::RngCore, sync::Arc,
    UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::
        pow::Pow
    ,
    arithmetizations::{r1cs::R1CS, Arith, ArithConfig, ArithRelation, Error as ArithError},
    circuits::AssignmentsOwned,
    commitments::{
        GroupBasedVectorCommitment, VectorCommitmentDef, VectorCommitmentOps,
    },
    relations::{Relation, WitnessInstanceSampler},
    traits::Dummy,
};

use self::{
    instances::{
        circuits::{IncomingInstanceVar as IUVar, RunningInstanceVar as RUVar},
        IncomingInstance as IU, RunningInstance as RU,
    },
    witnesses::{IncomingWitness as IW, RunningWitness as RW},
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeGadgetDef,
    GroupBasedFoldingSchemePrimaryDef, PlainInstance as PU,
    PlainWitness as PW, TaggedVec,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

#[derive(Clone)]
pub struct ProtoGalaxyKey<A, VC: VectorCommitmentDef> {
    arith: Arc<A>,
    ck: Arc<VC::Key>,
}

impl<A: Arith, VC: VectorCommitmentDef> DeciderKey for ProtoGalaxyKey<A, VC> {
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

impl<VC: VectorCommitmentDef<Scalar: Field>> ArithRelation<RW<VC>, RU<VC>> for R1CS<VC::Scalar> {
    type Evaluation = Vec<VC::Scalar>;

    fn eval_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<Self::Evaluation, ArithError> {
        Self::eval_relation(self, &w.w, &u.x)
    }

    fn check_evaluation(_w: &RW<VC>, u: &RU<VC>, v: Self::Evaluation) -> Result<(), ArithError> {
        if u.betas.len() != log2(v.len()) as usize {
            return Err(ArithError::MalformedAssignments(
                format!("The number of betas in the running instance ({}) does not match the expected length ({}).", u.betas.len(), log2(v.len()))
            ));
        }

        let e = cfg_into_iter!(v)
            .zip(Pow::powers_from_repeated_squares(&u.betas))
            .map(|(x, y)| x * y)
            .sum();

        if u.e != e {
            return Err(ArithError::UnsatisfiedAssignments(
                "Evaluation does not match error term".into(),
            ));
        }
        Ok(())
    }
}

impl<A, VC> Relation<RW<VC>, RU<VC>> for ProtoGalaxyKey<A, VC>
where
    A: ArithRelation<RW<VC>, RU<VC>>,
    VC: VectorCommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        VC::open(&self.ck, &w.w, &w.r, &u.phi)?;
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC>, IU<VC>> for ProtoGalaxyKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC>, u: &IU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(&w.w, &u.x)?;
        VC::open(&self.ck, &w.w, &w.r, &u.phi)?;
        Ok(())
    }
}

impl<A, VC> Relation<PW<VC::Scalar>, PU<VC::Scalar>> for ProtoGalaxyKey<A, VC>
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

impl<A, VC: VectorCommitmentOps> WitnessInstanceSampler<IW<VC>, IU<VC>> for ProtoGalaxyKey<A, VC> {
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, rng: impl RngCore) -> Result<(IW<VC>, IU<VC>), Error> {
        let (w, x) = (z.private, z.public);
        let (phi, r) = VC::commit(&self.ck, &w, rng)?;
        Ok((IW { w, r }, IU { phi, x }))
    }
}

impl<A, VC: VectorCommitmentDef> WitnessInstanceSampler<PW<VC::Scalar>, PU<VC::Scalar>>
    for ProtoGalaxyKey<A, VC>
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

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for ProtoGalaxyKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>, Evaluation = Vec<VC::Scalar>>,
    VC: VectorCommitmentOps<Scalar: Field>,
{
    type Source = ();
    type Error = Error;

    fn sample(&self, _: Self::Source, mut rng: impl RngCore) -> Result<(RW<VC>, RU<VC>), Error> {
        let x = (0..self.arith.n_public_inputs())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let w = (0..self.arith.n_witnesses())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let (phi, r) = VC::commit(&self.ck, &w, &mut rng)?;

        let betas = (0..self.arith.log_constraints())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();

        let v = self.arith.eval_relation(&w, &x)?;

        let e = cfg_into_iter!(v)
            .zip(Pow::powers_from_repeated_squares(&betas))
            .map(|(x, y)| x * y)
            .sum();

        Ok((RW { w, r }, RU { phi, x, e, betas }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoGalaxyProof<F, const N: usize> {
    pub f_coeffs: Vec<F>,
    pub k_coeffs: Vec<F>,
}

impl<F: Field, Cfg: ArithConfig, const N: usize> Dummy<&Cfg> for ProtoGalaxyProof<F, N> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            f_coeffs: vec![Default::default(); cfg.log_constraints()],
            k_coeffs: vec![Default::default(); cfg.degree() * N + 1],
        }
    }
}

pub struct ProtoGalaxy<VC> {
    _vc: PhantomData<VC>,
}

impl<VC: GroupBasedVectorCommitment> FoldingSchemeDef for ProtoGalaxy<VC> {
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = IW<VC>;
    type IU = IU<VC>;

    type TranscriptField = VC::Scalar;
    type Arith = R1CS<VC::Scalar>;

    type Config = usize;
    type PublicParam = VC::Key;
    type DeciderKey = ProtoGalaxyKey<Self::Arith, VC>;
    type Challenge = TaggedVec<VC::Scalar, 'c'>;
    type Proof<const M: usize, const N: usize> = ProtoGalaxyProof<VC::Scalar, N>;
}

// TODO: experimental design
struct ProtoGalaxy2<VC> {
    _vc: PhantomData<VC>,
}

impl<VC: GroupBasedVectorCommitment> FoldingSchemeDef for ProtoGalaxy2<VC> {
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = PW<VC::Scalar>;
    type IU = PU<VC::Scalar>;

    type TranscriptField = VC::Scalar;
    type Arith = R1CS<VC::Scalar>;

    type Config = usize;
    type PublicParam = VC::Key;
    type DeciderKey = ProtoGalaxyKey<Self::Arith, VC>;
    type Challenge = Vec<VC::Scalar>;
    type Proof<const M: usize, const N: usize> =
        ([VC::Commitment; N], ProtoGalaxyProof<VC::Scalar, N>);
}

#[derive(Clone)]
pub struct ProtoGalaxyProofVar<F: PrimeField, const N: usize> {
    pub f_coeffs: Vec<FpVar<F>>,
    pub k_coeffs: Vec<FpVar<F>>,
}

impl<F: PrimeField, const N: usize> AllocVar<ProtoGalaxyProof<F, N>, F>
    for ProtoGalaxyProofVar<F, N>
{
    fn new_variable<T: Borrow<ProtoGalaxyProof<F, N>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let proof = f()?.borrow().clone();

        Ok(Self {
            f_coeffs: Vec::new_variable(cs.clone(), || Ok(&proof.f_coeffs[..]), mode)?,
            k_coeffs: Vec::new_variable(cs.clone(), || Ok(&proof.k_coeffs[..]), mode)?,
        })
    }
}

impl<F: PrimeField, const N: usize> GR1CSVar<F> for ProtoGalaxyProofVar<F, N> {
    type Value = ProtoGalaxyProof<F, N>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.f_coeffs.cs().or(self.k_coeffs.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(ProtoGalaxyProof {
            f_coeffs: self.f_coeffs.value()?,
            k_coeffs: self.k_coeffs.value()?,
        })
    }
}

pub struct ProtoGalaxyGadget<VC> {
    _v: PhantomData<VC>,
}

impl<VC: GroupBasedVectorCommitment> FoldingSchemeGadgetDef for ProtoGalaxyGadget<VC> {
    type Native = ProtoGalaxy<VC>;

    type VC = VC::Gadget2;
    type RU = RUVar<VC::Gadget2>;
    type IU = IUVar<VC::Gadget2>;
    type VerifierKey = ();
    type Challenge = TaggedVec<FpVar<VC::Scalar>, 'c'>;
    type Proof<const M: usize, const N: usize> = ProtoGalaxyProofVar<VC::Scalar, N>;
}

impl<VC: GroupBasedVectorCommitment> GroupBasedFoldingSchemePrimaryDef for ProtoGalaxy<VC> {
    type Gadget = ProtoGalaxyGadget<VC>;
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

    fn test_protogalaxy_opt<const N: usize>(
        rounds: usize,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>> {
        test_folding_scheme::<ProtoGalaxy<Pedersen<G1Projective, true>>, 1, N>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<ProtoGalaxy<Pedersen<G1Projective, false>>, 1, N>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<ProtoGalaxy2<Pedersen<G1Projective, true>>, 1, N>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<ProtoGalaxy2<Pedersen<G1Projective, false>>, 1, N>(
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
    fn test_protogalaxy() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        test_protogalaxy_opt::<1>(10, &mut rng)?;
        test_protogalaxy_opt::<3>(10, &mut rng)?;
        test_protogalaxy_opt::<7>(10, &mut rng)?;
        test_protogalaxy_opt::<0>(10, &mut rng)?;
        Ok(())
    }
}
