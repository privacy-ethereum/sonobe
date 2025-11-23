use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseMultilinearExtension as MLE, DenseUVPolynomial, Polynomial,
};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    poly::polynomial::univariate::dense::DensePolynomialVar,
    prelude::Boolean,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow, cfg_into_iter, cfg_iter, marker::PhantomData, rand::RngCore, sync::Arc,
    UniformRand,
};
use num_bigint::BigInt;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{
        field::emulated::Bound,
        ops::{
            bits::{FromBits, FromBitsGadget},
            poly::MLEHelper,
        },
    },
    arithmetizations::{
        r1cs::{RelaxedInstance, RelaxedWitness, R1CS},
        Arith, ArithConfig, ArithRelation,
    },
    circuits::AssignmentsOwned,
    commitments::{
        CommitmentKey, GroupBasedVectorCommitment, VectorCommitmentDef, VectorCommitmentGadgetDef,
        VectorCommitmentOps,
    },
    relations::{Relation, WitnessInstanceSampler},
    traits::{Dummy, SonobeCurve, CF1},
    transcripts::{Transcript, TranscriptVar},
};

use self::{
    instance::{circuits::RunningInstanceVar as RUVar, RunningInstance as RU},
    witness::RunningWitness as RW,
};
use crate::{
    DeciderKey, Error, FoldingSchemeDef, FoldingSchemeGadgetDef, FoldingSchemeGadgetOpsPartial,
    FoldingSchemeOps, GroupBasedFoldingSchemePrimaryDef, PlainInstance as IU,
    PlainInstanceVar as IUVar, PlainWitness as IW,
};

pub mod instance;
pub mod witness;

#[derive(Clone)]
pub struct MovaKey<A, VC: VectorCommitmentDef> {
    pub arith: Arc<A>,
    pub ck: Arc<VC::Key>,
}

impl<A: Arith, VC: VectorCommitmentDef> DeciderKey for MovaKey<A, VC> {
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

impl<A, VC> Relation<RW<VC>, RU<VC>> for MovaKey<A, VC>
where
    A: for<'a> ArithRelation<
        RelaxedWitness<&'a [VC::Scalar]>,
        RelaxedInstance<&'a [VC::Scalar]>,
        Evaluation = Vec<VC::Scalar>,
    >,
    VC: VectorCommitmentOps<Scalar: Field>,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(
            &RelaxedWitness { w: &w.w, e: &w.e },
            &RelaxedInstance { x: &u.x, u: &u.u },
        )?;
        VC::open(&self.ck, &w.w, &w.r_w, &u.cm_w)?;

        (MLE::from_evaluations(&w.e).evaluate(&u.r_e) == u.v)
            .then_some(())
            .ok_or_else(|| {
                Error::UnsatisfiedRelation("Error term does not evaluate to claimed value".into())
            })
    }
}

impl<A, VC> Relation<IW<VC::Scalar>, IU<VC::Scalar>> for MovaKey<A, VC>
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
    VC: VectorCommitmentOps<Scalar: Field>,
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

        let r_e = (0..self.arith.log_constraints())
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();
        let v = MLE::from_evaluations(&e).evaluate(&r_e);

        Ok((RW { w, r_w, e }, RU { x, cm_w, u, r_e, v }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MovaProof<C: SonobeCurve> {
    pub h1_coeffs: Vec<CF1<C>>,
    pub t: CF1<C>,
    pub cm_w: C,
}

impl<C: SonobeCurve, Cfg: ArithConfig> Dummy<&Cfg> for MovaProof<C> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            h1_coeffs: vec![Zero::zero(); cfg.log_constraints()],
            t: Zero::zero(),
            cm_w: Zero::zero(),
        }
    }
}

pub struct Mova<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemeDef
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
    type DeciderKey = MovaKey<Self::Arith, VC>;
    type Challenge = Vec<bool>;
    type Proof<const M: usize, const N: usize> = MovaProof<VC::Commitment>;
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemeOps<1, 1>
    for Mova<VC, CHALLENGE_BITS>
{
    fn preprocess(n_witnesses: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(n_witnesses, &mut rng)?;
        Ok(ck)
    }

    fn generate_keys(ck: Self::PublicParam, r1cs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let r1cs = Arc::new(r1cs);
        if ck.max_scalars_len() < r1cs.n_witnesses() {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the R1CS instance".into(),
            ));
        }
        Ok(MovaKey { arith: r1cs, ck })
    }

    #[allow(non_snake_case)]
    fn prove(
        pk: &MovaKey<Self::Arith, VC>,
        transcript: &mut impl Transcript<VC::Scalar>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<1, 1>, Self::Challenge), Error> {
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
        let mut h1_coeffs = h1.coeffs.clone();
        h1_coeffs.resize(pk.arith.log_constraints() + 1, Zero::zero());
        h1_coeffs.remove(0);
        transcript.add(&h1_coeffs);

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
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = VC::Scalar::from_bits_le(&rho_bits);

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
            MovaProof { h1_coeffs, t, cm_w },
            rho_bits,
        ))
    }

    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (Us[0].borrow(), us[0].borrow());

        let h1 = DensePolynomial::from_coefficients_vec([&[U.v][..], &proof.h1_coeffs].concat());

        transcript.add(U);
        transcript.add(u);
        transcript.add(&proof.cm_w);

        let r_e = transcript.challenge_field_elements(U.r_e.len());

        transcript.add(&proof.h1_coeffs);

        let beta = transcript.challenge_field_element();

        transcript.add(&proof.t);

        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = VC::Scalar::from_bits_le(&rho_bits);

        Ok(RU {
            r_e: U
                .r_e
                .iter()
                .zip(r_e)
                .map(|(&r1, r2)| r1 + beta * (r2 - r1))
                .collect(),
            v: h1.evaluate(&beta) + rho * proof.t,
            u: U.u + rho,
            cm_w: U.cm_w + proof.cm_w * rho,
            x: cfg_iter!(U.x)
                .zip(&u[..])
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
}

#[derive(Clone)]
pub struct MovaProofVar<C: SonobeCurve> {
    pub h1_coeffs: Vec<FpVar<CF1<C>>>,
    pub t: FpVar<CF1<C>>,
    pub cm_w: C::EmulatedVar<CF1<C>>,
}

impl<C: SonobeCurve> AllocVar<MovaProof<C>, CF1<C>> for MovaProofVar<C> {
    fn new_variable<T: Borrow<MovaProof<C>>>(
        cs: impl Into<Namespace<CF1<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let proof = f()?.borrow().clone();

        Ok(Self {
            h1_coeffs: Vec::new_variable(cs.clone(), || Ok(&proof.h1_coeffs[..]), mode)?,
            t: FpVar::new_variable(cs.clone(), || Ok(proof.t), mode)?,
            cm_w: AllocVar::new_variable(cs.clone(), || Ok(proof.cm_w), mode)?,
        })
    }
}

impl<C: SonobeCurve> GR1CSVar<CF1<C>> for MovaProofVar<C> {
    type Value = MovaProof<C>;

    fn cs(&self) -> ConstraintSystemRef<CF1<C>> {
        self.h1_coeffs.cs().or(self.t.cs()).or(self.cm_w.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(MovaProof {
            h1_coeffs: self.h1_coeffs.value()?,
            t: self.t.value()?,
            cm_w: self.cm_w.value()?,
        })
    }
}

pub struct MovaGadget<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemeGadgetDef
    for MovaGadget<VC, CHALLENGE_BITS>
{
    type Native = Mova<VC, CHALLENGE_BITS>;

    type VC = VC::Gadget2;
    type RU = RUVar<VC::Gadget2>;
    type IU = IUVar<<VC::Gadget2 as VectorCommitmentGadgetDef>::ScalarVar>;
    type VerifierKey = ();
    type Challenge = Vec<Boolean<VC::Scalar>>;
    type Proof<const M: usize, const N: usize> = MovaProofVar<VC::Commitment>;
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize>
    FoldingSchemeGadgetOpsPartial<1, 1> for MovaGadget<VC, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<VC::Scalar>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        let h1 = DensePolynomialVar::from_coefficients_vec(
            [&[U.v.clone()][..], &proof.h1_coeffs].concat(),
        );

        transcript.add(U)?;
        transcript.add(u)?;
        transcript.add(&proof.cm_w)?;

        let r_e = transcript.challenge_field_elements(U.r_e.len())?;

        transcript.add(&proof.h1_coeffs)?;

        let beta = transcript.challenge_field_element()?;

        transcript.add(&proof.t)?;

        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS)?;
        let rho = FpVar::from_bits_le(
            &rho_bits,
            Bound(
                BigInt::zero(),
                (BigInt::one() << CHALLENGE_BITS) - BigInt::one(),
            ),
        )?;

        Ok((
            RUVar {
                r_e: U
                    .r_e
                    .iter()
                    .zip(r_e)
                    .map(|(r1, r2)| r1 + &beta * (r2 - r1))
                    .collect(),
                v: h1.evaluate(&beta)? + &rho * &proof.t,
                u: &U.u + &rho,
                cm_w: AllocVar::new_witness(U.cm_w.cs().or(proof.cm_w.cs()).or(rho.cs()), || {
                    Ok(U.cm_w.value().unwrap_or_default()
                        + proof.cm_w.value().unwrap_or_default() * rho.value().unwrap_or_default())
                })?,
                x: U.x.iter().zip(&u[..]).map(|(a, b)| &rho * b + a).collect(),
            },
            rho_bits,
        ))
    }
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemePrimaryDef
    for Mova<VC, CHALLENGE_BITS>
{
    type Gadget = MovaGadget<VC, CHALLENGE_BITS>;
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
