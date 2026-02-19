//! This module implements the ProtoGalaxy folding scheme, which is introduced
//! in this [paper].
//!
//! [paper]: https://eprint.iacr.org/2023/1106.pdf

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    UniformRand, borrow::Borrow, cfg_into_iter, log2, marker::PhantomData, rand::RngCore, sync::Arc,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::pow::Pow,
    arithmetizations::{Arith, ArithConfig, ArithRelation, Error as ArithError, r1cs::R1CS},
    circuits::AssignmentsOwned,
    commitments::{CommitmentDef, CommitmentOps, GroupBasedCommitment},
    relations::{Relation, WitnessInstanceSampler},
    traits::Dummy,
};

use self::{
    instances::{
        IncomingInstance as IU, RunningInstance as RU,
        circuits::{IncomingInstanceVar as IUVar, RunningInstanceVar as RUVar},
    },
    witnesses::{IncomingWitness as IW, RunningWitness as RW},
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeDefGadget, GroupBasedFoldingSchemePrimaryDef,
    PlainInstance as PU, PlainWitness as PW, TaggedVec,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

/// [`ProtoGalaxyKey`] is ProtoGalaxy's decider key.
#[derive(Clone)]
pub struct ProtoGalaxyKey<A, CM: CommitmentDef> {
    arith: Arc<A>,
    ck: Arc<CM::Key>,
}

impl<A: Arith, CM: CommitmentDef> DeciderKey for ProtoGalaxyKey<A, CM> {
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

impl<CM: CommitmentDef<Scalar: Field>> ArithRelation<RW<CM>, RU<CM>> for R1CS<CM::Scalar> {
    type Evaluation = Vec<CM::Scalar>;

    fn eval_relation(&self, w: &RW<CM>, u: &RU<CM>) -> Result<Self::Evaluation, ArithError> {
        Self::eval_relation(self, &w.w, &u.x)
    }

    fn check_evaluation(_w: &RW<CM>, u: &RU<CM>, v: Self::Evaluation) -> Result<(), ArithError> {
        if u.betas.len() != log2(v.len()) as usize {
            return Err(ArithError::MalformedAssignments(format!(
                "The number of betas in the running instance ({}) does not match the expected length ({}).",
                u.betas.len(),
                log2(v.len())
            )));
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

impl<A, CM> Relation<RW<CM>, RU<CM>> for ProtoGalaxyKey<A, CM>
where
    A: ArithRelation<RW<CM>, RU<CM>>,
    CM: CommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<CM>, u: &RU<CM>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        CM::open(&self.ck, &w.w, &w.r, &u.phi)?;
        Ok(())
    }
}

impl<A, CM> Relation<IW<CM>, IU<CM>> for ProtoGalaxyKey<A, CM>
where
    A: ArithRelation<Vec<CM::Scalar>, Vec<CM::Scalar>>,
    CM: CommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<CM>, u: &IU<CM>) -> Result<(), Self::Error> {
        self.arith.check_relation(&w.w, &u.x)?;
        CM::open(&self.ck, &w.w, &w.r, &u.phi)?;
        Ok(())
    }
}

impl<A, CM> Relation<PW<CM::Scalar>, PU<CM::Scalar>> for ProtoGalaxyKey<A, CM>
where
    A: ArithRelation<Vec<CM::Scalar>, Vec<CM::Scalar>>,
    CM: CommitmentDef,
{
    type Error = Error;

    fn check_relation(&self, w: &PW<CM::Scalar>, u: &PU<CM::Scalar>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        Ok(())
    }
}

impl<A, CM: CommitmentOps> WitnessInstanceSampler<IW<CM>, IU<CM>> for ProtoGalaxyKey<A, CM> {
    type Source = AssignmentsOwned<CM::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, rng: impl RngCore) -> Result<(IW<CM>, IU<CM>), Error> {
        let (w, x) = (z.private, z.public);
        let (phi, r) = CM::commit(&self.ck, &w, rng)?;
        Ok((IW { w, r }, IU { phi, x }))
    }
}

impl<A, CM: CommitmentDef> WitnessInstanceSampler<PW<CM::Scalar>, PU<CM::Scalar>>
    for ProtoGalaxyKey<A, CM>
{
    type Source = AssignmentsOwned<CM::Scalar>;
    type Error = Error;

    fn sample(
        &self,
        z: Self::Source,
        _rng: impl RngCore,
    ) -> Result<(PW<CM::Scalar>, PU<CM::Scalar>), Error> {
        Ok((z.private.into(), z.public.into()))
    }
}

impl<A, CM> WitnessInstanceSampler<RW<CM>, RU<CM>> for ProtoGalaxyKey<A, CM>
where
    A: ArithRelation<Vec<CM::Scalar>, Vec<CM::Scalar>, Evaluation = Vec<CM::Scalar>>,
    CM: CommitmentOps<Scalar: Field>,
{
    type Source = ();
    type Error = Error;

    fn sample(&self, _: Self::Source, mut rng: impl RngCore) -> Result<(RW<CM>, RU<CM>), Error> {
        let cfg = self.arith.config();

        let x = (0..cfg.n_public_inputs())
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let w = (0..cfg.n_witnesses())
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let (phi, r) = CM::commit(&self.ck, &w, &mut rng)?;

        let betas = (0..cfg.log_constraints())
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();

        let v = self.arith.eval_relation(&w, &x)?;

        let e = cfg_into_iter!(v)
            .zip(Pow::powers_from_repeated_squares(&betas))
            .map(|(x, y)| x * y)
            .sum();

        Ok((RW { w, r }, RU { phi, x, e, betas }))
    }
}

/// [`ProtoGalaxyProof`] is ProtoGalaxy's proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoGalaxyProof<F, const N: usize> {
    f_coeffs: Vec<F>,
    k_coeffs: Vec<F>,
}

impl<F: Field, Cfg: ArithConfig, const N: usize> Dummy<&Cfg> for ProtoGalaxyProof<F, N> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            f_coeffs: vec![Default::default(); cfg.log_constraints()],
            k_coeffs: vec![Default::default(); cfg.degree() * N + 1],
        }
    }
}

/// [`ProtoGalaxy`] implements the ProtoGalaxy folding scheme.
pub struct ProtoGalaxy<CM> {
    _t: PhantomData<CM>,
}

impl<CM: GroupBasedCommitment> FoldingSchemeDef for ProtoGalaxy<CM> {
    type CM = CM;
    type RW = RW<CM>;
    type RU = RU<CM>;
    type IW = IW<CM>;
    type IU = IU<CM>;

    type TranscriptField = CM::Scalar;
    type Arith = R1CS<CM::Scalar>;

    type Config = usize;
    type PublicParam = CM::Key;
    type DeciderKey = ProtoGalaxyKey<Self::Arith, CM>;
    type Challenge = TaggedVec<CM::Scalar, 'c'>;
    type Proof<const M: usize, const N: usize> = ProtoGalaxyProof<CM::Scalar, N>;
}

/// [`ProtoGalaxy2`] implements the ProtoGalaxy folding scheme.
///
/// This design is experimental, following the definition of accumulation
/// schemes where the incoming witnesses and instances are simply plain vectors
/// in the circuit's assignments.
pub struct ProtoGalaxy2<CM> {
    _t: PhantomData<CM>,
}

impl<CM: GroupBasedCommitment> FoldingSchemeDef for ProtoGalaxy2<CM> {
    type CM = CM;
    type RW = RW<CM>;
    type RU = RU<CM>;
    type IW = PW<CM::Scalar>;
    type IU = PU<CM::Scalar>;

    type TranscriptField = CM::Scalar;
    type Arith = R1CS<CM::Scalar>;

    type Config = usize;
    type PublicParam = CM::Key;
    type DeciderKey = ProtoGalaxyKey<Self::Arith, CM>;
    type Challenge = Vec<CM::Scalar>;
    type Proof<const M: usize, const N: usize> =
        ([CM::Commitment; N], ProtoGalaxyProof<CM::Scalar, N>);
}

/// [`ProtoGalaxyProofVar`] is the in-circuit variable for [`ProtoGalaxyProof`].
#[derive(Clone)]
pub struct ProtoGalaxyProofVar<F: PrimeField, const N: usize> {
    f_coeffs: Vec<FpVar<F>>,
    k_coeffs: Vec<FpVar<F>>,
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

/// [`ProtoGalaxyGadget`] is the in-circuit gadget for [`ProtoGalaxy`].
pub struct ProtoGalaxyGadget<CM> {
    _t: PhantomData<CM>,
}

impl<CM: GroupBasedCommitment> FoldingSchemeDefGadget for ProtoGalaxyGadget<CM> {
    type Widget = ProtoGalaxy<CM>;

    type CM = CM::Gadget2;
    type RU = RUVar<CM::Gadget2>;
    type IU = IUVar<CM::Gadget2>;
    type VerifierKey = ();
    type Challenge = TaggedVec<FpVar<CM::Scalar>, 'c'>;
    type Proof<const M: usize, const N: usize> = ProtoGalaxyProofVar<CM::Scalar, N>;
}

impl<CM: GroupBasedCommitment> GroupBasedFoldingSchemePrimaryDef for ProtoGalaxy<CM> {
    type Gadget = ProtoGalaxyGadget<CM>;
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
        let mut rng = thread_rng();
        test_protogalaxy_opt::<1>(10, &mut rng)?;
        test_protogalaxy_opt::<3>(10, &mut rng)?;
        test_protogalaxy_opt::<7>(10, &mut rng)?;
        test_protogalaxy_opt::<0>(10, &mut rng)?;
        Ok(())
    }
}
