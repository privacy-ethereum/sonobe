use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_poly::{DenseMultilinearExtension as MLE, MultilinearExtension};
use ark_std::{
    cfg_into_iter, cfg_iter, log2, marker::PhantomData, rand::RngCore, sync::Arc, UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use sonobe_primitives::{
    arithmetizations::{ccs::CCS, Arith, ArithRelation, Error as ArithError},
    circuits::{Assignments, AssignmentsOwned},
    commitments::VectorCommitment,
    relations::{Relation, WitnessInstanceSampler},
    sumcheck::{
        utils::{build_eq_x_r_vec, eq_eval, VPAuxInfo, VirtualPolynomial},
        IOPProof, IOPSumCheck,
    },
    traits::{ScalarRLC, SliceRLC, SonobeCurve, CF1},
    transcripts::Transcript,
};

use crate::{Error, FoldingScheme};

use instance::{CCCS as IU, LCCCS as RU};
use witness::{IncomingWitness as IW, RunningWitness as RW};

pub mod instance;
pub mod witness;

pub struct HyperNovaKey<A, VC: VectorCommitment> {
    arith: Arc<A>,
    ck: Arc<VC::Key>,
}

impl<VC: VectorCommitment<Scalar: Field>> ArithRelation<RW<VC>, RU<VC>> for CCS<VC::Scalar> {
    type Evaluation = Vec<VC::Scalar>;

    fn eval_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<Self::Evaluation, ArithError> {
        let z = Assignments::from((u.u, &u.x, &w.w));
        Ok(cfg_into_iter!(0..self.t)
            .map(|i| self.mle(i, z.clone()).fix_variables(&u.r_x)[0])
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
    VC: VectorCommitment<Scalar: Field>,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        // TODO: handle the error properly
        assert!(VC::open(&self.ck, &w.w, &w.r, &u.cm)?);
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC>, IU<VC>> for HyperNovaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitment,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC>, u: &IU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(&w.w, &u.x)?;
        assert!(VC::open(&self.ck, &w.w, &w.r, &u.cm)?);
        Ok(())
    }
}

impl<A, VC: VectorCommitment<Scalar: Field>> WitnessInstanceSampler<IW<VC>, IU<VC>>
    for HyperNovaKey<A, VC>
{
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, rng: impl RngCore) -> Result<(IW<VC>, IU<VC>), Error> {
        let (w, x) = (z.private, z.public);
        let (cm, r) = VC::commit(&self.ck, &w, rng)?;
        Ok((IW { w, r }, IU { cm, x }))
    }
}

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for HyperNovaKey<A, VC>
where
    A: ArithRelation<RW<VC>, RU<VC>, Evaluation = Vec<VC::Scalar>>,
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
        let (cm, r) = VC::commit(&self.ck, &w, &mut rng)?;

        let r_x = (0..log2(self.arith.n_constraints()))
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

pub struct NIMFSProof<F> {
    pub sc_proof: IOPProof<F>,
    pub sigmas: Vec<F>,
    pub thetas: Vec<F>,
}

pub struct HyperNova<VC, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
}

impl<VC: VectorCommitment, const M: usize, const N: usize, const CHALLENGE_BITS: usize>
    FoldingScheme<M, N> for HyperNova<VC, CHALLENGE_BITS>
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
    type Arith = CCS<VC::Scalar>;

    type Config = usize;
    type PublicParam = VC::Key;
    type ProverKey = HyperNovaKey<Self::Arith, VC>;
    type VerifierKey = CCS<VC::Scalar>;
    type DeciderKey = HyperNovaKey<Self::Arith, VC>;
    type Proof = NIMFSProof<VC::Scalar>;

    fn preprocess(ck_len: usize, mut rng: impl RngCore) -> Result<Self::PublicParam, Error> {
        let ck = VC::generate_key(&mut rng, ck_len)?;
        Ok(ck)
    }

    fn generate_keys(
        ck: Self::PublicParam,
        ccs: Self::Arith,
    ) -> Result<(Self::ProverKey, Self::VerifierKey, Self::DeciderKey), Error> {
        let ck = Arc::new(ck);
        let ccs = Arc::new(ccs);
        Ok((
            HyperNovaKey {
                arith: ccs.clone(),
                ck: ck.clone(),
            },
            CCS {
                m: ccs.n_constraints(),
                n: ccs.n_variables(),
                l: ccs.n_public_inputs(),
                s: ccs.s,
                t: ccs.t,
                d: ccs.degree(),
                S: ccs.S.clone(),
                c: ccs.c.clone(),
                M: vec![],
            },
            HyperNovaKey { arith: ccs, ck },
        ))
    }

    fn prove(
        pk: &Self::ProverKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Ws: &[Self::RW; M],
        Us: &[Self::RU; M],
        ws: &[Self::IW; N],
        us: &[Self::IU; N],
        _rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof), Error> {
        let ccs = &pk.arith;
        // absorb instances to transcript
        for U in Us {
            transcript.absorb(U);
        }
        for u in us {
            transcript.absorb(u);
        }

        let running_mles = cfg_iter!(Ws)
            .zip(Us)
            .map(|(W, U)| {
                (0..ccs.t)
                    .map(|i| ccs.mle(i, (U.u, &U.x, &W.w).into()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let incoming_mles = cfg_iter!(ws)
            .zip(us)
            .map(|(w, u)| {
                (0..ccs.t)
                    .map(|i| ccs.mle(i, (VC::Scalar::one(), &u.x, &w.w).into()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Step 1: Get some challenges
        let gamma: VC::Scalar = transcript.get_challenge();
        let beta: Vec<VC::Scalar> = transcript.get_challenges(ccs.s);

        let gamma_powers = pows(gamma, M * ccs.t + N);
        let (running_gammas, incoming_gammas) = gamma_powers.split_at(M * ccs.t);

        // Compute g(x)
        let flattened_ml_extensions = running_mles
            .into_iter()
            .chain(incoming_mles)
            .flatten()
            .chain(
                Us.iter()
                    .map(|U| MLE::from_evaluations_vec(ccs.s, build_eq_x_r_vec(&U.r_x))),
            )
            .chain(vec![MLE::from_evaluations_vec(
                ccs.s,
                build_eq_x_r_vec(&beta),
            )])
            .collect::<Vec<_>>();

        let products = running_gammas
            .iter()
            .enumerate()
            .map(|(i, &gamma)| (gamma, vec![i, (M + N) * ccs.t + i / ccs.t]))
            .chain(incoming_gammas.iter().enumerate().flat_map(|(k, gamma)| {
                ccs.S.iter().zip(&ccs.c).map(move |(S_i, &c_i)| {
                    (
                        c_i * gamma,
                        S_i.iter()
                            .map(|j| (M + k) * ccs.t + j)
                            .chain(vec![(M + N) * ccs.t + M])
                            .collect::<Vec<_>>(),
                    )
                })
            }))
            .collect::<Vec<_>>();

        let g = VirtualPolynomial {
            aux_info: VPAuxInfo {
                num_variables: ccs.s,
                max_degree: ccs.degree() + 1,
            },
            flattened_ml_extensions,
            products,
        };

        // Step 3: Run the sumcheck prover
        let (sumcheck_proof, mles) = IOPSumCheck::prove(g, transcript)?;

        // Step 2: dig into the sumcheck and extract r_x_prime
        let r_x_prime = sumcheck_proof.point.clone();

        // Step 4: compute sigmas and thetas
        let sigmas = mles[0..ccs.t * M]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();
        let thetas = mles[ccs.t * M..ccs.t * (M + N)]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();

        // Step 6: Get the folding challenge
        let rho_bits: Vec<bool> = transcript.get_challenge_nbits(CHALLENGE_BITS);
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        let rho_powers = pows(rho, M + N);

        Ok((
            RW {
                w: Ws
                    .iter()
                    .map(|w| &w.w[..])
                    .chain(ws.iter().map(|w| &w.w[..]))
                    .slice_rlc(&rho_powers),
                r: Ws
                    .iter()
                    .map(|w| w.r)
                    .chain(ws.iter().map(|w| w.r))
                    .scalar_rlc(&rho_powers),
            },
            Self::RU {
                cm: Us
                    .iter()
                    .map(|u| u.cm)
                    .chain(us.iter().map(|u| u.cm))
                    .scalar_rlc(&rho_powers),
                u: Us
                    .iter()
                    .map(|u| u.u)
                    .chain([VC::Scalar::one(); N])
                    .scalar_rlc(&rho_powers),
                x: Us
                    .iter()
                    .map(|u| &u.x[..])
                    .chain(us.iter().map(|u| &u.x[..]))
                    .slice_rlc(&rho_powers),
                r_x: r_x_prime,
                v: sigmas
                    .chunks(ccs.t)
                    .chain(thetas.chunks(ccs.t))
                    .slice_rlc(&rho_powers),
            },
            NIMFSProof {
                sc_proof: sumcheck_proof,
                sigmas,
                thetas,
            },
        ))
    }

    fn verify(
        ccs: &Self::VerifierKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[Self::RU; M],
        us: &[Self::IU; N],
        proof: &Self::Proof,
    ) -> Result<Self::RU, Error> {
        // absorb instances to transcript
        for U in Us {
            transcript.absorb(U);
        }
        for u in us {
            transcript.absorb(u);
        }

        // Step 1: Get some challenges
        let gamma: VC::Scalar = transcript.get_challenge();
        let beta: Vec<VC::Scalar> = transcript.get_challenges(ccs.s);

        let gamma_powers = pows(gamma, M * ccs.t + N);

        let vp_aux_info = VPAuxInfo {
            max_degree: ccs.degree() + 1,
            num_variables: ccs.s,
        };

        // Step 3: Start verifying the sumcheck
        // First, compute the expected sumcheck sum: \sum gamma^j v_j
        let mut sum_v_j_gamma = VC::Scalar::zero();
        for (i, U) in Us.iter().enumerate() {
            for j in 0..U.v.len() {
                sum_v_j_gamma += U.v[j] * gamma_powers[i * ccs.t + j];
            }
        }

        // Verify the interactive part of the sumcheck
        let sumcheck_subclaim =
            IOPSumCheck::verify(sum_v_j_gamma, &proof.sc_proof, &vp_aux_info, transcript)?;

        // Step 2: Dig into the sumcheck claim and extract the randomness used
        let r_x_prime = sumcheck_subclaim.point;

        // Step 5: Finish verifying sumcheck (verify the claim c)
        let c = {
            let e2 = eq_eval(&beta, &r_x_prime);
            proof
                .sigmas
                .chunks(ccs.t)
                .zip(Us)
                .flat_map(|(sigmas, u)| {
                    let e_lcccs = eq_eval(&u.r_x, &r_x_prime);
                    sigmas.iter().map(move |sigma_j| e_lcccs * sigma_j)
                })
                .chain(proof.thetas.chunks(ccs.t).map(|thetas| {
                    e2 * ccs
                        .S
                        .iter()
                        .zip(&ccs.c)
                        .map(|(S_i, &c_i)| {
                            c_i * S_i.iter().map(|&j| thetas[j]).product::<VC::Scalar>()
                        })
                        .sum::<VC::Scalar>()
                }))
                .zip(gamma_powers.iter())
                .map(|(val, gamma_i)| val * gamma_i)
                .sum::<VC::Scalar>()
        };

        // check that the g(r_x') from the sumcheck proof is equal to the computed c from sigmas&thetas
        assert_eq!(c, sumcheck_subclaim.expected_evaluation);

        // Step 6: Get the folding challenge
        let rho_bits = transcript.get_challenge_nbits(CHALLENGE_BITS);
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        let rho_powers = pows(rho, M + N);

        Ok(Self::RU {
            cm: Us
                .iter()
                .map(|u| u.cm)
                .chain(us.iter().map(|u| u.cm))
                .scalar_rlc(&rho_powers),
            u: Us
                .iter()
                .map(|u| u.u)
                .chain([VC::Scalar::one(); N])
                .scalar_rlc(&rho_powers),
            x: Us
                .iter()
                .map(|u| &u.x[..])
                .chain(us.iter().map(|u| &u.x[..]))
                .slice_rlc(&rho_powers),
            r_x: r_x_prime,
            v: proof
                .sigmas
                .chunks(ccs.t)
                .chain(proof.thetas.chunks(ccs.t))
                .slice_rlc(&rho_powers),
        })
    }
}

fn pows<F: Field>(base: F, n: usize) -> Vec<F> {
    let mut res = vec![F::one(); n];
    for i in 1..n {
        res[i] = res[i - 1] * base;
    }
    res
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

    use crate::tests::test_folding_scheme;

    use super::*;

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
