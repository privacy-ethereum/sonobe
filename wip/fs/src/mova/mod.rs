use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseMultilinearExtension as MLE, DenseUVPolynomial, Polynomial,
};
use ark_std::{
    borrow::Borrow, cfg_into_iter, cfg_iter, log2, marker::PhantomData, rand::RngCore, sync::Arc,
    UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::poly::MLEHelper,
    arithmetizations::{
        r1cs::{RelaxedInstance, RelaxedWitness, R1CS},
        ArithConfig, ArithRelation,
    },
    circuits::AssignmentsOwned,
    commitments::{GroupBasedVectorCommitment, VectorCommitment},
    relations::{Relation, WitnessInstanceSampler},
    traits::Dummy,
    transcripts::Transcript,
};

use self::{instance::RunningInstance as RU, witness::RunningWitness as RW};
use crate::{Error, FoldingScheme, PlainInstance as IU, PlainWitness as IW};

pub mod instance;
pub mod witness;

#[derive(Clone)]
pub struct MovaKey<A, VC: VectorCommitment> {
    pub arith: Arc<A>,
    pub ck: Arc<VC::Key>,
}

impl<A, VC> Relation<RW<VC>, RU<VC>> for MovaKey<A, VC>
where
    A: for<'a> ArithRelation<
        RelaxedWitness<&'a [VC::Scalar]>,
        RelaxedInstance<&'a [VC::Scalar]>,
        Evaluation = Vec<VC::Scalar>,
    >,
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

        assert_eq!(MLE::from_evaluations(&w.e).evaluate(&u.r_e), u.v);
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC::Scalar>, IU<VC::Scalar>> for MovaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitment,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC::Scalar>, u: &IU<VC::Scalar>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        Ok(())
    }
}

impl<A, VC: VectorCommitment> WitnessInstanceSampler<IW<VC::Scalar>, IU<VC::Scalar>>
    for MovaKey<A, VC>
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

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for MovaKey<A, VC>
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

        let r_e = (0..log2(e.len()) as usize)
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let v = MLE::from_evaluations(&e).evaluate(&r_e);

        Ok((RW { w, r_w, e }, RU { x, cm_w, u, r_e, v }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MovaProof<F: Field> {
    pub h1_coeffs: Vec<F>,
    pub t: F,
}

impl<F: Field, Cfg: ArithConfig> Dummy<&Cfg> for MovaProof<F> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            h1_coeffs: vec![F::zero(); 1 << (log2(cfg.n_constraints()) as usize)],
            t: F::zero(),
        }
    }
}

pub struct Mova<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingScheme<1, 1>
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
    type ProverKey = MovaKey<Self::Arith, VC>;
    type VerifierKey = ();
    type DeciderKey = MovaKey<Self::Arith, VC>;
    type Challenge = VC::Scalar;
    type Proof = (MovaProof<VC::Scalar>, VC::Commitment);

    fn preprocess(n_witnesses: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(&mut rng, n_witnesses)?;
        Ok(ck)
    }

    fn generate_keys(
        ck: Self::PublicParam,
        r1cs: Self::Arith,
    ) -> Result<(Self::ProverKey, Self::VerifierKey, Self::DeciderKey), Error> {
        let ck = Arc::new(ck);
        let r1cs = Arc::new(r1cs);
        Ok((
            MovaKey {
                arith: r1cs.clone(),
                ck: ck.clone(),
            },
            (),
            MovaKey { arith: r1cs, ck },
        ))
    }

    #[allow(non_snake_case)]
    fn prove(
        pk: &Self::ProverKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof, Self::Challenge), Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        // Protocol 5

        // Step 5.1: Commit to w & send commitment
        let (cm_w, r_w) = VC::commit(&pk.ck, w, rng)?;

        transcript.add(U);
        transcript.add(u);
        transcript.add(&cm_w);

        // Step 5.2: Get challenge r_E
        let r_e = transcript.challenge_field_elements(U.r_e.len());

        // Protocol 6

        // Step 6.1: Compute l(X) such that l(0) = r1, l(1) = r2
        let l = U
            .r_e
            .iter()
            .zip(&r_e)
            .map(|(&r1, &r2)| DensePolynomial::from_coefficients_vec(vec![r1, r2 - r1]))
            .collect::<Vec<_>>();
        // Step 6.1: Compute h1(X) and h2(X), where h2(X) is empty in our case
        let h1 = {
            // Initialize the polynomial vector from the evaluations in the MLE.
            // Each evaluation is turned into a constant polynomial.
            let mut poly =
                W.e.iter()
                    .chain(vec![Zero::zero(); 1 << U.r_e.len()].iter())
                    .map(|&x| DensePolynomial::from_coefficients_slice(&[x]))
                    .collect::<Vec<_>>();

            for i in &l {
                poly = poly
                    .chunks_exact(2)
                    .map(|w| &w[0] + (&w[1] - &w[0]).naive_mul(i))
                    .collect();
            }

            poly.swap_remove(0)
        };
        // Step 6.1: Send h1(X) and h2(X), where the constant term is omitted
        // because it always equals v
        transcript.add(&h1.coeffs[1..]);

        // Step 6.2: Get challenge beta
        let beta = transcript.challenge_field_element();

        // Step 6.3: Compute r_E'
        let r_e_prime = l.iter().map(|i| i.evaluate(&beta)).collect();

        // Protocol 7

        // Step 7.1: Compute cross term `T`. We follow the optimized approach in
        // [Mova](https://eprint.iacr.org/2024/1220.pdf)'s section 5.2.
        let v = pk.arith.eval_assignments(AssignmentsOwned::from((
            U.u + VC::Scalar::one(),
            cfg_iter!(U.x).zip(&u[..]).map(|(a, b)| *a + b).collect(),
            cfg_iter!(W.w).zip(&w[..]).map(|(a, b)| *a + b).collect(),
        )))?;
        let T = cfg_into_iter!(v)
            .zip(&W.e)
            .map(|(a, b)| a - b)
            .collect::<Vec<_>>();
        // Step 7.1: Evaluate & send T's MLE at r_E'
        let t = MLE::from_evaluations(&T).evaluate(&r_e_prime);
        transcript.add(&t);

        // Step 7.2: Get challenge rho
        let rho = transcript.challenge_field_element();

        // Step 7.3: Compute new W and U
        Ok((
            RW {
                e: cfg_iter!(W.e).zip(&T).map(|(a, b)| rho * b + a).collect(),
                w: cfg_iter!(W.w)
                    .zip(&w[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
                r_w: W.r_w + r_w * rho,
            },
            RU {
                r_e: r_e_prime,
                v: h1.evaluate(&beta) + rho * t,
                u: U.u + rho,
                cm_w: U.cm_w + cm_w * rho,
                x: cfg_iter!(U.x)
                    .zip(&u[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
            },
            (
                MovaProof {
                    h1_coeffs: h1.coeffs[1..].to_vec(),
                    t,
                },
                cm_w,
            ),
            rho,
        ))
    }

    #[allow(non_snake_case)]
    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        (proof, cm_w): &Self::Proof,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (Us[0].borrow(), us[0].borrow());

        let h1 = DensePolynomial::from_coefficients_vec([&[U.v][..], &proof.h1_coeffs].concat());

        transcript.add(U);
        transcript.add(u);
        transcript.add(cm_w);

        let r_e = transcript.challenge_field_elements(U.r_e.len());

        transcript.add(&proof.h1_coeffs);

        let beta = transcript.challenge_field_element();

        transcript.add(&proof.t);

        let rho = transcript.challenge_field_element();

        Ok(RU {
            r_e: U
                .r_e
                .iter()
                .zip(r_e)
                .map(|(&r1, r2)| r1 + beta * (r2 - r1))
                .collect(),
            v: h1.evaluate(&beta) + rho * proof.t,
            u: U.u + rho,
            cm_w: U.cm_w + *cm_w * rho,
            x: cfg_iter!(U.x)
                .zip(&u[..])
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
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
