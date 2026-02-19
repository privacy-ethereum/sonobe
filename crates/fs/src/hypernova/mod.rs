//! This module implements the HyperNova folding scheme, which is introduced in
//! this [paper].
//!
//! [paper]: https://eprint.iacr.org/2023/573.pdf

use ark_ff::{Field, PrimeField};
use ark_poly::MultilinearExtension;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    UniformRand, borrow::Borrow, cfg_iter, marker::PhantomData, rand::RngCore, sync::Arc,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    arithmetizations::{
        Arith, ArithConfig, ArithRelation, Error as ArithError,
        ccs::{CCS, CCSConfig, CCSVariant},
        r1cs::R1CSConfig,
    },
    circuits::{Assignments, AssignmentsOwned},
    commitments::{CommitmentDef, CommitmentOps, GroupBasedCommitment},
    relations::{Relation, WitnessInstanceSampler},
    traits::Dummy,
};

use self::{
    instances::{
        CCCSInstance as IU, LCCCSInstance as RU,
        circuits::{CCCSInstanceVar as IUVar, LCCCSInstanceVar as RUVar},
    },
    witnesses::{CCCSWitness as IW, LCCCSWitness as RW},
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeDefGadget, GroupBasedFoldingSchemePrimaryDef,
    PlainInstance as PU, PlainWitness as PW,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod witnesses;

/// [`HyperNovaKey`] is HyperNova's decider key.
#[derive(Clone)]
pub struct HyperNovaKey<A, CM: CommitmentDef> {
    arith: Arc<A>,
    ck: Arc<CM::Key>,
}

impl<A: Arith, CM: CommitmentDef> DeciderKey for HyperNovaKey<A, CM> {
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

impl<CM: CommitmentDef<Scalar: Field>, V: CCSVariant> ArithRelation<RW<CM>, RU<CM>>
    for CCS<CM::Scalar, V>
{
    type Evaluation = Vec<CM::Scalar>;

    fn eval_relation(&self, w: &RW<CM>, u: &RU<CM>) -> Result<Self::Evaluation, ArithError> {
        let z = Assignments::from((u.u, &u.x, &w.w));
        Ok(self
            .mles(z)
            .iter()
            .map(|mle| mle.fix_variables(&u.r_x)[0])
            .collect())
    }

    fn check_evaluation(_w: &RW<CM>, u: &RU<CM>, e: Self::Evaluation) -> Result<(), ArithError> {
        cfg_iter!(e)
            .zip(&u.v)
            .all(|(e, v)| e == v)
            .then_some(())
            .ok_or(ArithError::UnsatisfiedAssignments(
                "Evaluation contains non-zero values".into(),
            ))
    }
}

impl<A, CM> Relation<RW<CM>, RU<CM>> for HyperNovaKey<A, CM>
where
    A: ArithRelation<RW<CM>, RU<CM>>,
    CM: CommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<CM>, u: &RU<CM>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        CM::open(&self.ck, &w.w, &w.r, &u.cm)?;
        Ok(())
    }
}

impl<A, CM> Relation<IW<CM>, IU<CM>> for HyperNovaKey<A, CM>
where
    A: ArithRelation<Vec<CM::Scalar>, Vec<CM::Scalar>>,
    CM: CommitmentOps,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<CM>, u: &IU<CM>) -> Result<(), Self::Error> {
        self.arith.check_relation(&w.w, &u.x)?;
        CM::open(&self.ck, &w.w, &w.r, &u.cm)?;
        Ok(())
    }
}

impl<A, CM> Relation<PW<CM::Scalar>, PU<CM::Scalar>> for HyperNovaKey<A, CM>
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

impl<A, CM: CommitmentOps> WitnessInstanceSampler<IW<CM>, IU<CM>> for HyperNovaKey<A, CM> {
    type Source = AssignmentsOwned<CM::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, rng: impl RngCore) -> Result<(IW<CM>, IU<CM>), Error> {
        let (w, x) = (z.private, z.public);
        let (cm, r) = CM::commit(&self.ck, &w, rng)?;
        Ok((IW { w, r }, IU { cm, x }))
    }
}

impl<A, CM: CommitmentDef> WitnessInstanceSampler<PW<CM::Scalar>, PU<CM::Scalar>>
    for HyperNovaKey<A, CM>
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

impl<A, CM> WitnessInstanceSampler<RW<CM>, RU<CM>> for HyperNovaKey<A, CM>
where
    A: ArithRelation<RW<CM>, RU<CM>, Evaluation = Vec<CM::Scalar>>,
    CM: CommitmentOps,
{
    type Source = ();
    type Error = Error;

    #[allow(non_snake_case)]
    fn sample(&self, _: Self::Source, mut rng: impl RngCore) -> Result<(RW<CM>, RU<CM>), Error> {
        let cfg = self.arith.config();

        let u = CM::Scalar::rand(&mut rng);
        let x = (0..cfg.n_public_inputs())
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let w = (0..cfg.n_witnesses())
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let (cm, r) = CM::commit(&self.ck, &w, &mut rng)?;

        let r_x = (0..cfg.log_constraints())
            .map(|_| CM::Scalar::rand(&mut rng))
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

/// [`NIMFSProof`] is HyperNova's proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NIMFSProof<F, const M: usize, const N: usize> {
    /// [`NIMFSProof::sc_proof`] is the sum-check proof.
    pub sc_proof: Vec<Vec<F>>,
    /// [`NIMFSProof::sigmas`] is a vector of claimed internal sums defined
    /// in Equation 9
    pub sigmas: Vec<F>,
    /// [`NIMFSProof::thetas`] is a vector of claimed internal sums defined
    /// in Equation 10
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

/// [`HyperNova`] implements the HyperNova folding scheme for a CCS variant `V`.
pub struct HyperNova<CM, V: CCSVariant = R1CSConfig, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<(CM, V)>,
}

impl<CM: GroupBasedCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for HyperNova<CM, V, CHALLENGE_BITS>
{
    type CM = CM;
    type RW = RW<CM>;
    type RU = RU<CM>;
    type IW = IW<CM>;
    type IU = IU<CM>;

    type TranscriptField = CM::Scalar;
    type Arith = CCS<CM::Scalar, V>;

    type Config = usize;
    type PublicParam = CM::Key;
    type DeciderKey = HyperNovaKey<Self::Arith, CM>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = NIMFSProof<CM::Scalar, M, N>;
}

/// [`HyperNova2`] implements the HyperNova folding scheme for a CCS variant
/// `V`.
///
/// This design is experimental, following the definition of accumulation
/// schemes where the incoming witnesses and instances are simply plain vectors
/// in the circuit's assignments.
pub struct HyperNova2<CM, V: CCSVariant = R1CSConfig, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<(CM, V)>,
}

impl<CM: GroupBasedCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for HyperNova2<CM, V, CHALLENGE_BITS>
{
    type CM = CM;
    type RW = RW<CM>;
    type RU = RU<CM>;
    type IW = PW<CM::Scalar>;
    type IU = PU<CM::Scalar>;

    type TranscriptField = CM::Scalar;
    type Arith = CCS<CM::Scalar, V>;

    type Config = usize;
    type PublicParam = CM::Key;
    type DeciderKey = HyperNovaKey<Self::Arith, CM>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> =
        ([CM::Commitment; N], NIMFSProof<CM::Scalar, M, N>);
}

/// [`NIMFSProofVar`] is the in-circuit variable for [`NIMFSProof`].
#[derive(Clone)]
pub struct NIMFSProofVar<F: PrimeField, const M: usize, const N: usize> {
    /// [`NIMFSProofVar::sc_proof`] is the sum-check proof.
    pub sc_proof: Vec<Vec<FpVar<F>>>,
    /// [`NIMFSProofVar::sigmas`] is a vector of claimed internal sums defined
    /// in Equation 9
    pub sigmas: Vec<FpVar<F>>,
    /// [`NIMFSProofVar::thetas`] is a vector of claimed internal sums defined
    /// in Equation 10
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

/// [`HyperNovaGadget`] is the in-circuit gadget for [`HyperNova`].
pub struct HyperNovaGadget<CM, V: CCSVariant = R1CSConfig, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<(CM, V)>,
}

impl<CM: GroupBasedCommitment, V: CCSVariant, const CHALLENGE_BITS: usize> FoldingSchemeDefGadget
    for HyperNovaGadget<CM, V, CHALLENGE_BITS>
{
    type Widget = HyperNova<CM, V, CHALLENGE_BITS>;

    type CM = CM::Gadget2;
    type RU = RUVar<CM::Gadget2>;
    type IU = IUVar<CM::Gadget2>;
    type VerifierKey = ();
    type Challenge = [Boolean<CM::Scalar>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = NIMFSProofVar<CM::Scalar, M, N>;
}

impl<CM: GroupBasedCommitment, V: CCSVariant, const CHALLENGE_BITS: usize>
    GroupBasedFoldingSchemePrimaryDef for HyperNova<CM, V, CHALLENGE_BITS>
{
    type Gadget = HyperNovaGadget<CM, V, CHALLENGE_BITS>;
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
        let mut rng = thread_rng();
        test_hypernova_opt::<1, 1>(10, &mut rng)?;
        test_hypernova_opt::<1, 3>(10, &mut rng)?;
        test_hypernova_opt::<3, 1>(10, &mut rng)?;
        test_hypernova_opt::<3, 3>(10, &mut rng)?;
        test_hypernova_opt::<0, 5>(10, &mut rng)?;
        test_hypernova_opt::<5, 0>(10, &mut rng)?;
        Ok(())
    }
}
