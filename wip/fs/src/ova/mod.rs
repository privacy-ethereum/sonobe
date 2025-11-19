use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, groups::CurveVar, GR1CSVar};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{
    borrow::Borrow, cfg_iter, marker::PhantomData, rand::RngCore, sync::Arc, UniformRand,
};
use num_bigint::BigInt;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::{field::emulated::Bound, ops::bits::FromBitsGadget},
    arithmetizations::{
        r1cs::{RelaxedInstance, RelaxedWitness, R1CS},
        Arith, ArithRelation,
    },
    circuits::{Assignments, AssignmentsOwned},
    commitments::{
        CommitmentKey, GroupBasedVectorCommitment, VectorCommitment, VectorCommitmentGadget,
    },
    relations::{Relation, WitnessInstanceSampler},
    traits::{SonobeField, CF2},
    transcripts::{Transcript, TranscriptVar},
};

use self::{
    instance::{circuits::RunningInstanceVar as RUVar, RunningInstance as RU},
    witness::{circuits::RunningWitnessVar as RWVar, RunningWitness as RW},
};
use crate::{
    DeciderKey, Error, FoldingScheme, FoldingSchemeFullGadget, FoldingSchemePartialGadget,
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary, PlainInstance as IU,
    PlainInstanceVar as IUVar, PlainWitness as IW, PlainWitnessVar as IWVar,
};

pub mod instance;
pub mod witness;

#[derive(Clone)]
pub struct OvaKey<A, VC: VectorCommitment> {
    pub arith: Arc<A>,
    pub ck: Arc<VC::Key>,
}

impl<A: Arith, VC: VectorCommitment> DeciderKey for OvaKey<A, VC> {
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
    VC: VectorCommitment,
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
    VC: VectorCommitment,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC::Scalar>, u: &IU<VC::Scalar>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        Ok(())
    }
}

impl<A, VC: VectorCommitment> WitnessInstanceSampler<IW<VC::Scalar>, IU<VC::Scalar>>
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
    VC: VectorCommitment,
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
    AbstractOva<VC, <VC as VectorCommitment>::Scalar, CHALLENGE_BITS>;

pub type CycleFoldOva<VC, const CHALLENGE_BITS: usize = 128> =
    AbstractOva<VC, CF2<<VC as VectorCommitment>::Commitment>, CHALLENGE_BITS>;

impl<VC: GroupBasedVectorCommitment, TF: SonobeField, const CHALLENGE_BITS: usize>
    FoldingScheme<1, 1> for AbstractOva<VC, TF, CHALLENGE_BITS>
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
    type Challenge = Vec<bool>;
    type Proof = VC::Commitment;

    fn preprocess(
        (n_constraints, n_witnesses): (usize, usize),
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(n_constraints + n_witnesses, &mut rng)?;
        Ok(ck)
    }

    fn generate_keys(ck: Self::PublicParam, r1cs: Self::Arith) -> Result<Self::DeciderKey, Error> {
        let ck = Arc::new(ck);
        let r1cs = Arc::new(r1cs);
        if ck.max_scalars_len() < r1cs.n_constraints() + r1cs.n_witnesses() {
            return Err(Error::InvalidPublicParameters(
                "The commitment key generated by preprocessing is too short for the R1CS instance"
                    .into(),
            ));
        }
        Ok(OvaKey { arith: r1cs, ck })
    }

    #[allow(non_snake_case)]
    fn prove(
        pk: &OvaKey<Self::Arith, VC>,
        transcript: &mut impl Transcript<TF>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof, Self::Challenge), Error> {
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let (w, u) = (ws[0].borrow(), us[0].borrow());

        // Compute the cross term `T` by following the original Nova paper.
        let z1 = Assignments::from((U.u, &U.x, &W.w));
        let z2 = Assignments::from((VC::Scalar::one(), &u[..], &w[..]));
        let t = cfg_iter!(pk.arith.A)
            .zip(&pk.arith.B)
            .zip(&pk.arith.C)
            .map(|((a, b), c)| {
                let az1: VC::Scalar = a.iter().map(|(val, col)| z1[*col] * val).sum();
                let az2: VC::Scalar = a.iter().map(|(val, col)| z2[*col] * val).sum();
                let bz1: VC::Scalar = b.iter().map(|(val, col)| z1[*col] * val).sum();
                let bz2: VC::Scalar = b.iter().map(|(val, col)| z2[*col] * val).sum();
                let cz1: VC::Scalar = c.iter().map(|(val, col)| z1[*col] * val).sum();
                let cz2: VC::Scalar = c.iter().map(|(val, col)| z2[*col] * val).sum();
                az1 * bz2 + az2 * bz1 - z2[0] * cz1 - z1[0] * cz2
            })
            .collect::<Vec<_>>();

        let (cm, r) = VC::commit(&pk.ck, &[w, &t[..]].concat(), rng)?;

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(&cm);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        Ok((
            RW {
                w: cfg_iter!(W.w)
                    .zip(&w[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
                r: W.r + r * rho,
            },
            RU {
                u: U.u + rho,
                cm: U.cm + cm * rho,
                x: cfg_iter!(U.x)
                    .zip(&u[..])
                    .map(|(a, b)| rho * b + a)
                    .collect(),
            },
            cm,
            rho_bits,
        ))
    }

    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<TF>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; 1],
        cm: &Self::Proof,
    ) -> Result<Self::RU, Error> {
        let (U, u) = (Us[0].borrow(), us[0].borrow());

        let rho_bits = {
            transcript.add(&U);
            transcript.add(&u);
            transcript.add(cm);
            transcript.challenge_bits(CHALLENGE_BITS)
        };
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        Ok(RU {
            u: U.u + rho,
            cm: U.cm + *cm * rho,
            x: cfg_iter!(U.x)
                .zip(&u[..])
                .map(|(a, b)| rho * b + a)
                .collect(),
        })
    }
}

pub struct AbstractOvaGadget<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemePartialGadget<1, 1>
    for AbstractOvaGadget<VC, CHALLENGE_BITS>
where
    VC: VectorCommitmentGadget<Native: GroupBasedVectorCommitment>,
{
    type Native = AbstractOva<VC::Native, VC::ConstraintField, CHALLENGE_BITS>;

    type VC = VC;
    type RW = RWVar<VC>;
    type RU = RUVar<VC>;
    type IW = IWVar<VC>;
    type IU = IUVar<VC>;
    type VerifierKey = ();
    type Challenge = Vec<Boolean<VC::ConstraintField>>;
    type Proof = VC::CommitmentVar;

    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<VC::ConstraintField>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        let rho_bits = {
            transcript.add(&U)?;
            transcript.add(&u)?;
            transcript.add(proof)?;
            transcript.challenge_bits(CHALLENGE_BITS)?
        };
        let rho = VC::ScalarVar::from_bits_le(
            &rho_bits,
            Bound(
                BigInt::zero(),
                (BigInt::one() << CHALLENGE_BITS) - BigInt::one(),
            ),
        )?;

        Ok((
            RUVar {
                u: (U.u.clone() + &rho)
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
                cm: VC::CommitmentVar::new_witness(U.cm.cs().or(proof.cs()).or(rho.cs()), || {
                    Ok(U.cm.value().unwrap_or_default()
                        + proof.value().unwrap_or_default() * rho.value().unwrap_or_default())
                })?,
                x: U.x
                    .iter()
                    .zip(&u[..])
                    .map(|(a, b)| (b.clone() * &rho + a).try_into())
                    .collect::<Result<_, _>>()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
            },
            rho_bits,
        ))
    }
}

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeFullGadget<1, 1>
    for AbstractOvaGadget<VC, CHALLENGE_BITS>
where
    VC: VectorCommitmentGadget<Native: GroupBasedVectorCommitment>,
    VC::CommitmentVar: CurveVar<<VC::Native as VectorCommitment>::Commitment, VC::ConstraintField>,
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<VC::ConstraintField>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof,
    ) -> Result<Self::RU, SynthesisError> {
        let rho_bits = {
            transcript.add(&U)?;
            transcript.add(&u)?;
            transcript.add(proof)?;
            transcript.challenge_bits(CHALLENGE_BITS)?
        };
        let rho = VC::ScalarVar::from_bits_le(
            &rho_bits,
            Bound(
                BigInt::zero(),
                (BigInt::one() << CHALLENGE_BITS) - BigInt::one(),
            ),
        )?;

        Ok(RUVar {
            u: (U.u.clone() + &rho)
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
            cm: proof.scalar_mul_le(rho_bits.iter())? + &U.cm,
            x: U.x
                .iter()
                .zip(&u[..])
                .map(|(a, b)| (b.clone() * &rho + a).try_into())
                .collect::<Result<_, _>>()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        })
    }
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize>
    GroupBasedFoldingSchemePrimary<1, 1> for AbstractOva<VC, VC::Scalar, CHALLENGE_BITS>
{
    type Gadget = AbstractOvaGadget<VC::EmulatedGadget, CHALLENGE_BITS>;
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize>
    GroupBasedFoldingSchemeSecondary<1, 1>
    for AbstractOva<VC, CF2<VC::Commitment>, CHALLENGE_BITS>
{
    type Gadget = AbstractOvaGadget<VC::Gadget, CHALLENGE_BITS>;
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
