use ark_ff::{BigInteger, Field, One, PrimeField};
use ark_std::{cfg_iter, marker::PhantomData, ops::Mul, rand::RngCore, sync::Arc, UniformRand};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use sonobe_primitives::{
    arithmetizations::{
        r1cs::{RelaxedInstance, RelaxedWitness, R1CS},
        ArithRelation,
    },
    circuits::{Assignments, AssignmentsOwned},
   commitments::VectorCommitment,
    relations::{Referenceable, Relation, WitnessInstanceSampler},
    traits::{SonobeCurve, CF1},
    transcripts::Transcript,
};

use crate::{Error, FoldingScheme};

use instance::{IncomingInstance as IU, RunningInstance as RU};
use witness::{IncomingWitness as IW, RunningWitness as RW};

pub mod instance;
pub mod witness;

pub struct OvaKey<A, VC: VectorCommitment> {
    arith: Arc<A>,
    ck: Arc<VC::Key>,
}

impl<A, VC> Relation<RW<VC>, RU<VC>> for OvaKey<A, VC>
where
    A: ArithRelation<
        RelaxedWitness<VC::Scalar>,
        RelaxedInstance<VC::Scalar>,
        Evaluation = Vec<VC::Scalar>,
    >,
    VC: VectorCommitment<Scalar: Field>,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        let e = self.arith.eval_relation((&w.w, &[]), (&u.x, u.u))?;
        // TODO: handle the error properly
        assert!(VC::open(&self.ck, &[&w.w[..], &e].concat(), &w.r, &u.cm)?);
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC>, IU<VC>> for OvaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitment,
{
    type Error = Error;

    fn check_relation(
        &self,
        w: <IW<VC> as Referenceable>::Ref<'_>,
        u: <IU<VC> as Referenceable>::Ref<'_>,
    ) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        Ok(())
    }
}

impl<A, VC: VectorCommitment<Scalar: Field>> WitnessInstanceSampler<IW<VC>, IU<VC>>
    for OvaKey<A, VC>
{
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, _rng: impl RngCore) -> Result<(IW<VC>, IU<VC>), Error> {
        Ok((z.private, z.public))
    }
}

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for OvaKey<A, VC>
where
    A: ArithRelation<
        RelaxedWitness<VC::Scalar>,
        RelaxedInstance<VC::Scalar>,
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
        let e = self.arith.eval_relation((&w, &[]), (&x, u))?;

        let (cm, r) = VC::commit(&self.ck, &[&w[..], &e].concat(), &mut rng)?;
        Ok((RW { w, r }, RU { x, cm, u }))
    }
}

pub struct Ova<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC: VectorCommitment, const CHALLENGE_BITS: usize> FoldingScheme<1, 1>
    for Ova<VC, CHALLENGE_BITS>
where
    VC: VectorCommitment<Scalar = CF1<<VC as VectorCommitment>::Commitment>>,
    VC::Commitment: SonobeCurve,
{
    type VC = VC;
    type RW = RW<VC>;
    type RU = RU<VC>;
    type IW = IW<VC>;
    type IU = IU<VC>;

    type TranscriptField = VC::Scalar;
    type Arith = R1CS<VC::Scalar>;

    type Config = (usize, usize);
    type PublicParam = VC::Key;
    type ProverKey = OvaKey<Self::Arith, VC>;
    type VerifierKey = ();
    type DeciderKey = OvaKey<Self::Arith, VC>;
    type Proof = VC::Commitment;

    fn preprocess(
        (n_constraints, n_witnesses): (usize, usize),
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(&mut rng, n_constraints + n_witnesses)?;
        Ok(ck)
    }

    fn generate_keys(
        ck: Self::PublicParam,
        r1cs: Self::Arith,
    ) -> Result<(Self::ProverKey, Self::VerifierKey, Self::DeciderKey), Error> {
        let ck = Arc::new(ck);
        let r1cs = Arc::new(r1cs);
        Ok((
            OvaKey {
                arith: r1cs.clone(),
                ck: ck.clone(),
            },
            (),
            OvaKey { arith: r1cs, ck },
        ))
    }

    fn prove(
        pk: &Self::ProverKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Ws: &[Self::RW; 1],
        Us: &[Self::RU; 1],
        ws: &[Self::IW; 1],
        us: &[Self::IU; 1],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof), Error> {
        let (W, U, w, u) = (&Ws[0], &Us[0], &ws[0], &us[0]);

        // Compute the cross term `T` by following the original Nova paper.
        let z1 = Assignments::from((U.u, &U.x, &W.w));
        let z2 = Assignments::from((VC::Scalar::one(), u, w));
        let t = cfg_iter!(pk.arith.A)
            .zip(&pk.arith.B)
            .zip(&pk.arith.C)
            .map(|((a, b), c)| {
                let az1 = a
                    .iter()
                    .map(|(val, col)| z1[*col] * val)
                    .sum::<VC::Scalar>();
                let az2 = a
                    .iter()
                    .map(|(val, col)| z2[*col] * val)
                    .sum::<VC::Scalar>();
                let bz1 = b
                    .iter()
                    .map(|(val, col)| z1[*col] * val)
                    .sum::<VC::Scalar>();
                let bz2 = b
                    .iter()
                    .map(|(val, col)| z2[*col] * val)
                    .sum::<VC::Scalar>();
                let cz1 = c
                    .iter()
                    .map(|(val, col)| z1[*col] * val)
                    .sum::<VC::Scalar>();
                let cz2 = c
                    .iter()
                    .map(|(val, col)| z2[*col] * val)
                    .sum::<VC::Scalar>();
                az1 * bz2 + az2 * bz1 - z2[0] * cz1 - z1[0] * cz2
            })
            .collect::<Vec<_>>();

        let (cm, r) = VC::commit(&pk.ck, &[w, &t[..]].concat(), rng)?;

        let rho_bits = {
            transcript.absorb(&U);
            transcript.absorb(&u);
            transcript.absorb_nonnative(&cm);
            transcript.squeeze_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        Ok((
            RW {
                w: cfg_iter!(W.w).zip(w).map(|(a, b)| rho * b + a).collect(),
                r: W.r + r * rho,
            },
            RU {
                u: U.u + rho,
                cm: U.cm + cm.mul(rho),
                x: cfg_iter!(U.x).zip(u).map(|(a, b)| rho * b + a).collect(),
            },
            cm,
        ))
    }

    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[Self::RU; 1],
        us: &[Self::IU; 1],
        cm: &Self::Proof,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (&Us[0], &us[0]);

        let rho_bits = {
            transcript.absorb(&U);
            transcript.absorb(&u);
            transcript.absorb_nonnative(cm);
            transcript.squeeze_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        Ok(RU {
            u: U.u + rho,
            cm: U.cm + cm.mul(rho),
            x: cfg_iter!(U.x).zip(u).map(|(a, b)| rho * b + a).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective};
    use ark_ff::UniformRand;
    use ark_std::{error::Error, test_rng};

    use sonobe_primitives::{
        circuits::utils::{satisfying_assignments_for_test, CircuitForTest},
        commitments::pedersen::Pedersen,
    };

    use crate::tests::test_folding_scheme;

    use super::*;

    #[test]
    fn test_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        let config = (4, 4);

        test_folding_scheme::<Ova<Pedersen<G1Projective, true>>, 1, 1>(
            config,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..10)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<Ova<Pedersen<G1Projective, false>>, 1, 1>(
            config,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..10)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;
        Ok(())
    }
}
