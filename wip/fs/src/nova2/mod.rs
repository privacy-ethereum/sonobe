use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, One, PrimeField};
use ark_std::{
    borrow::Borrow,
    cfg_into_iter, cfg_iter,
    marker::PhantomData,
    ops::Mul,
    rand::{rngs::mock::StepRng, RngCore},
    sync::Arc,
    UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use sonobe_primitives::{
    arithmetizations::{
        r1cs::{RelaxedInstance, RelaxedWitness, R1CS},
        ArithRelation,
    },
    circuits::AssignmentsOwned,
    commitments::VectorCommitment,
    relations::{Relation, WitnessInstanceSampler},
    traits::{SonobeCurve, SonobeField},
    transcripts::{Absorbable, Transcript},
};

use crate::{Error, FoldingScheme};

use instance::{IncomingInstance as IU, RunningInstance as RU};
use witness::{IncomingWitness as IW, RunningWitness as RW};

pub mod instance;
pub mod witness;

pub struct NovaKey<A, VC: VectorCommitment> {
    arith: Arc<A>,
    ck: Arc<VC::Key>,
}

impl<A, VC> Relation<RW<VC>, RU<VC>> for NovaKey<A, VC>
where
    A: for<'a> ArithRelation<RelaxedWitness<&'a [VC::Scalar]>, RelaxedInstance<&'a [VC::Scalar]>>,
    VC: VectorCommitment<Scalar: Field>,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(
            &RelaxedWitness { w: &w.w, e: &w.e },
            &RelaxedInstance { x: &u.x, u: &u.u },
        )?;
        // TODO: handle the error properly
        assert!(VC::open(&self.ck, &w.w, &w.r_w, &u.cm_w)?);
        assert!(VC::open(&self.ck, &w.e, &w.r_e, &u.cm_e)?);
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC>, IU<VC>> for NovaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitment,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC>, u: &IU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        Ok(())
    }
}

impl<A, VC: VectorCommitment<Scalar: Field>> WitnessInstanceSampler<IW<VC>, IU<VC>>
    for NovaKey<A, VC>
{
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, _rng: impl RngCore) -> Result<(IW<VC>, IU<VC>), Error> {
        Ok((z.private, z.public))
    }
}

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for NovaKey<A, VC>
where
    A: for<'a> ArithRelation<
        RelaxedWitness<&'a [VC::Scalar]>,
        RelaxedInstance<&'a [VC::Scalar]>,
        Evaluation = Vec<VC::Scalar>,
    >,
    VC: VectorCommitment<Scalar: Field>,
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
    AbstractNova<VC, <VC as VectorCommitment>::Scalar, CHALLENGE_BITS>;

pub type CycleFoldNova<VC, const CHALLENGE_BITS: usize = 128> = AbstractNova<
    VC,
    <<<VC as VectorCommitment>::Commitment as CurveGroup>::BaseField as Field>::BasePrimeField,
    CHALLENGE_BITS,
>;

impl<VC: VectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize> FoldingScheme<1, 1>
    for AbstractNova<VC, TF, CHALLENGE_BITS>
where
    VC::Scalar: SonobeField + Absorbable<TF>,
    VC::Commitment: SonobeCurve<ScalarField = VC::Scalar> + Absorbable<TF>,
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
    type ProverKey = NovaKey<Self::Arith, VC>;
    type VerifierKey = ();
    type DeciderKey = NovaKey<Self::Arith, VC>;
    type Challenge = Vec<bool>;
    type Proof = (VC::Commitment, VC::Commitment);

    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(&mut rng, ck_len)?;
        Ok(ck)
    }

    fn generate_keys(
        ck: Self::PublicParam,
        r1cs: Self::Arith,
    ) -> Result<(Self::ProverKey, Self::VerifierKey, Self::DeciderKey), Error> {
        let ck = Arc::new(ck);
        let r1cs = Arc::new(r1cs);
        Ok((
            NovaKey {
                arith: r1cs.clone(),
                ck: ck.clone(),
            },
            (),
            NovaKey { arith: r1cs, ck },
        ))
    }

    fn prove(
        pk: &Self::ProverKey,
        transcript: &mut impl Transcript<TF>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof, Self::Challenge), Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        // Compute the cross term `T` by following the optimized approach in
        // [Mova](https://eprint.iacr.org/2024/1220.pdf)'s section 5.2.
        let v = pk.arith.eval_assignments(AssignmentsOwned::from((
            U.u + VC::Scalar::one(),
            cfg_iter!(U.x).zip(u).map(|(a, b)| *a + b).collect(),
            cfg_iter!(W.w).zip(w).map(|(a, b)| *a + b).collect(),
        )))?;
        let t = cfg_into_iter!(v)
            .zip(&W.e)
            .map(|(a, b)| a - b)
            .collect::<Vec<_>>();

        let (cm_w, r_w) = VC::commit(&pk.ck, w, rng)?;

        // Use `StepRng::new(0, 0)`, which is a dummy RNG that always generates
        // 0 for the randomness (i.e., `r_T = 0`), no matter whether `VC` itself
        // is hiding or not.
        //
        // This is because in Nova, we don't need hiding property for commitment
        // to `T`.
        let (cm_t, r_t) = VC::commit(&pk.ck, &t, StepRng::new(0, 0))?;

        let pi = (cm_w, cm_t);

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(&pi);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        Ok((
            RW {
                e: cfg_iter!(W.e).zip(&t).map(|(a, b)| rho * b + a).collect(),
                r_e: W.r_e + r_t * rho,
                w: cfg_iter!(W.w).zip(w).map(|(a, b)| rho * b + a).collect(),
                r_w: W.r_w + r_w * rho,
            },
            RU {
                cm_e: U.cm_e + cm_t.mul(rho),
                u: U.u + rho,
                cm_w: U.cm_w + cm_w.mul(rho),
                x: cfg_iter!(U.x).zip(u).map(|(a, b)| rho * b + a).collect(),
            },
            pi,
            rho_bits,
        ))
    }

    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<TF>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        pi: &Self::Proof,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (Us[0].borrow(), us[0].borrow());

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(pi);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        let (cm_w, cm_t) = pi;

        Ok(RU {
            cm_e: U.cm_e + cm_t.mul(rho),
            u: U.u + rho,
            cm_w: U.cm_w + cm_w.mul(rho),
            x: cfg_iter!(U.x).zip(u).map(|(a, b)| rho * b + a).collect(),
        })
    }
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

    use crate::tests::test_folding_scheme;

    use super::*;

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
