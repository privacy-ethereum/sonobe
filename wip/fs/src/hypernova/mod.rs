use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_poly::{DenseMultilinearExtension as MLE, MultilinearExtension};
use ark_std::{
    borrow::Borrow, cfg_iter, log2, marker::PhantomData, rand::RngCore, sync::Arc, UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sonobe_primitives::{
    algebra::ops::rlc::{ScalarRLC, SliceRLC},
    arithmetizations::{
        ccs::{CCSConfig, CCSVariant, CCS},
        r1cs::R1CSConfig,
        Arith, ArithConfig, ArithRelation, Error as ArithError,
    },
    circuits::{Assignments, AssignmentsOwned},
    commitments::{GroupBasedVectorCommitment, VectorCommitment},
    relations::{Relation, WitnessInstanceSampler},
    sumcheck::{
        utils::{build_eq_x_r_vec, eq_eval, VPAuxInfo, VirtualPolynomial},
        IOPProof, IOPSumCheck,
    },
    traits::{Dummy, SonobeCurve, SonobeField},
    transcripts::{Absorbable, Transcript},
};

use self::{
    instance::{CCCSInstance as IU, LCCCSInstance as RU},
    witness::{CCCSWitness as IW, LCCCSWitness as RW},
};
use crate::{Error, FoldingScheme, PlainInstance as PU, PlainWitness as PW};

pub mod instance;
pub mod witness;

#[derive(Clone)]
pub struct HyperNovaKey<A, VC: VectorCommitment> {
    arith: Arc<A>,
    ck: Arc<VC::Key>,
}

impl<VC: VectorCommitment<Scalar: Field>, V: CCSVariant> ArithRelation<RW<VC>, RU<VC>>
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

impl<A, VC> Relation<PW<VC::Scalar>, PU<VC::Scalar>> for HyperNovaKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitment,
{
    type Error = Error;

    fn check_relation(&self, w: &PW<VC::Scalar>, u: &PU<VC::Scalar>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
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

impl<A, VC: VectorCommitment> WitnessInstanceSampler<PW<VC::Scalar>, PU<VC::Scalar>>
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
    VC: VectorCommitment<Scalar: Field>,
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

#[derive(Clone)]
pub struct NIMFSProof<F, const M: usize, const N: usize> {
    pub sc_proof: IOPProof<F>,
    pub sigmas: Vec<F>,
    pub thetas: Vec<F>,
}

impl<F: Field, const M: usize, const N: usize, V: CCSVariant> Dummy<&CCSConfig<V>>
    for NIMFSProof<F, M, N>
{
    fn dummy(cfg: &CCSConfig<V>) -> Self {
        let s = log2(cfg.n_constraints()) as usize;
        let d = cfg.degree();
        let t = V::n_matrices();
        Self {
            sc_proof: IOPProof {
                point: vec![F::zero(); s],
                proofs: vec![vec![F::zero(); d + 2]; s],
            },
            sigmas: vec![F::zero(); t * M],
            thetas: vec![F::zero(); t * N],
        }
    }
}

pub struct HyperNova<VC, V: CCSVariant = R1CSConfig, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
    _v: PhantomData<V>,
}

impl<
        VC: GroupBasedVectorCommitment,
        V: CCSVariant,
        const M: usize,
        const N: usize,
        const CHALLENGE_BITS: usize,
    > FoldingScheme<M, N> for HyperNova<VC, V, CHALLENGE_BITS>
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
    type ProverKey = HyperNovaKey<Self::Arith, VC>;
    type VerifierKey = ();
    type DeciderKey = HyperNovaKey<Self::Arith, VC>;
    type Challenge = Vec<bool>;
    type Proof = NIMFSProof<VC::Scalar, M, N>;

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
            (),
            HyperNovaKey { arith: ccs, ck },
        ))
    }

    #[allow(non_snake_case)]
    fn prove(
        pk: &Self::ProverKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Ws: &[impl Borrow<Self::RW>; M],
        Us: &[impl Borrow<Self::RU>; M],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        _rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof, Self::Challenge), Error> {
        let Ws = &Ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let Us = &Us.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let ws = &ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let ccs = &pk.arith;
        let d = ccs.degree();
        let s = log2(ccs.n_constraints()) as usize;
        let t = V::n_matrices();
        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<VC::Scalar>();

        // absorb instances to transcript
        transcript.add(&Us[..]);
        transcript.add(&us[..]);

        // Step 1: Get some challenges
        let gamma = transcript.challenge_field_element();
        let beta = transcript.challenge_field_elements(s);

        let gamma_powers = pows(gamma, M * t + N);
        let (running_gammas, incoming_gammas) = gamma_powers.split_at(M * t);

        // Compute g(x)
        let running_mles = Ws
            .iter()
            .zip(Us)
            .flat_map(|(W, U)| ccs.mles((U.u, &U.x, &W.w).into()));
        let incoming_mles = ws
            .iter()
            .zip(us)
            .flat_map(|(w, u)| ccs.mles((One::one(), &u.x, &w.w).into()));
        let eq_mles = Us
            .iter()
            .map(|U| &U.r_x)
            .chain([&beta])
            .map(|r| MLE::from_evaluations_vec(s, build_eq_x_r_vec(r)));

        let running_products = running_gammas
            .iter()
            .enumerate()
            .map(|(i, &gamma)| (gamma, vec![i, (M + N) * t + i / t]));
        let incoming_products = incoming_gammas.iter().enumerate().flat_map(|(k, gamma)| {
            S.iter().zip(c).map(move |(S_i, &c_i)| {
                (
                    c_i * gamma,
                    S_i.iter()
                        .map(|j| (M + k) * t + j)
                        .chain([(M + N) * t + M])
                        .collect(),
                )
            })
        });

        let g = VirtualPolynomial {
            aux_info: VPAuxInfo {
                num_variables: s,
                max_degree: d + 1,
            },
            flattened_ml_extensions: running_mles.chain(incoming_mles).chain(eq_mles).collect(),
            products: running_products.chain(incoming_products).collect(),
        };

        // Step 3: Run the sumcheck prover
        let (sumcheck_proof, mles) = IOPSumCheck::prove(g, transcript)?;

        // Step 2: dig into the sumcheck and extract r_x_prime
        let r_x_prime = sumcheck_proof.point.clone();

        // Step 4: compute sigmas and thetas
        let sigmas = mles[0..t * M]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();
        let thetas = mles[t * M..t * (M + N)]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();

        // Step 6: Get the folding challenge
        let rho_bits: Vec<bool> = transcript.challenge_bits(CHALLENGE_BITS);
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
                    .chunks(t)
                    .chain(thetas.chunks(t))
                    .slice_rlc(&rho_powers),
            },
            NIMFSProof {
                sc_proof: sumcheck_proof,
                sigmas,
                thetas,
            },
            rho_bits,
        ))
    }

    #[allow(non_snake_case)]
    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof,
    ) -> Result<Self::RU, Error> {
        let Us = &Us.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let d = V::degree();
        let s = proof.sc_proof.point.len();
        let t = V::n_matrices();
        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<VC::Scalar>();

        // absorb instances to transcript
        transcript.add(&Us[..]);
        transcript.add(&us[..]);

        // Step 1: Get some challenges
        let gamma = transcript.challenge_field_element();
        let beta = transcript.challenge_field_elements(s);

        let gamma_powers = pows(gamma, M * t + N);

        let vp_aux_info = VPAuxInfo {
            max_degree: d + 1,
            num_variables: s,
        };

        // Step 3: Start verifying the sumcheck
        // First, compute the expected sumcheck sum: \sum gamma^j v_j
        let mut sum_v_j_gamma = VC::Scalar::zero();
        for (i, U) in Us.iter().enumerate() {
            for j in 0..U.v.len() {
                sum_v_j_gamma += U.v[j] * gamma_powers[i * t + j];
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
                .chunks(t)
                .zip(Us)
                .flat_map(|(sigmas, u)| {
                    let e_lcccs = eq_eval(&u.r_x, &r_x_prime);
                    sigmas.iter().map(move |sigma_j| e_lcccs * sigma_j)
                })
                .chain(proof.thetas.chunks(t).map(|thetas| {
                    e2 * S
                        .iter()
                        .zip(c)
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
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
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
                .chunks(t)
                .chain(proof.thetas.chunks(t))
                .slice_rlc(&rho_powers),
        })
    }
}

pub struct HyperNova2<VC, V: CCSVariant = R1CSConfig, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<VC>,
    _v: PhantomData<V>,
}

impl<
        VC: GroupBasedVectorCommitment,
        V: CCSVariant,
        const M: usize,
        const N: usize,
        const CHALLENGE_BITS: usize,
    > FoldingScheme<M, N> for HyperNova2<VC, V, CHALLENGE_BITS>
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
    type ProverKey = HyperNovaKey<Self::Arith, VC>;
    type VerifierKey = ();
    type DeciderKey = HyperNovaKey<Self::Arith, VC>;
    type Challenge = Vec<bool>;
    type Proof = ([VC::Commitment; N], NIMFSProof<VC::Scalar, M, N>);

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
            (),
            HyperNovaKey { arith: ccs, ck },
        ))
    }

    #[allow(non_snake_case)]
    fn prove(
        pk: &Self::ProverKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Ws: &[impl Borrow<Self::RW>; M],
        Us: &[impl Borrow<Self::RU>; M],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        mut rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof, Self::Challenge), Error> {
        let Ws = &Ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let Us = &Us.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let ws = &ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let ccs = &pk.arith;
        let d = ccs.degree();
        let s = log2(ccs.n_constraints()) as usize;
        let t = V::n_matrices();
        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<VC::Scalar>();

        let mut cms = [VC::Commitment::default(); N];
        let mut rs = [VC::Randomness::default(); N];
        for i in 0..N {
            let (cm, r) = VC::commit(&pk.ck, ws[i], &mut rng)?;
            cms[i] = cm;
            rs[i] = r;
        }

        // absorb instances to transcript
        transcript.add(&Us[..]);
        transcript.add(&us[..]);
        transcript.add(&cms[..]);

        // Step 1: Get some challenges
        let gamma = transcript.challenge_field_element();
        let beta = transcript.challenge_field_elements(s);

        let gamma_powers = pows(gamma, M * t + N);
        let (running_gammas, incoming_gammas) = gamma_powers.split_at(M * t);

        // Compute g(x)
        let running_mles = Ws
            .iter()
            .zip(Us)
            .flat_map(|(W, U)| ccs.mles((U.u, &U.x, &W.w).into()));
        let incoming_mles = ws
            .iter()
            .zip(us)
            .flat_map(|(w, u)| ccs.mles((One::one(), &u[..], &w[..]).into()));
        let eq_mles = Us
            .iter()
            .map(|U| &U.r_x)
            .chain([&beta])
            .map(|r| MLE::from_evaluations_vec(s, build_eq_x_r_vec(r)));

        let running_products = running_gammas
            .iter()
            .enumerate()
            .map(|(i, &gamma)| (gamma, vec![i, (M + N) * t + i / t]));
        let incoming_products = incoming_gammas.iter().enumerate().flat_map(|(k, gamma)| {
            S.iter().zip(c).map(move |(S_i, &c_i)| {
                (
                    c_i * gamma,
                    S_i.iter()
                        .map(|j| (M + k) * t + j)
                        .chain([(M + N) * t + M])
                        .collect(),
                )
            })
        });

        let g = VirtualPolynomial {
            aux_info: VPAuxInfo {
                num_variables: s,
                max_degree: d + 1,
            },
            flattened_ml_extensions: running_mles.chain(incoming_mles).chain(eq_mles).collect(),
            products: running_products.chain(incoming_products).collect(),
        };

        // Step 3: Run the sumcheck prover
        let (sumcheck_proof, mles) = IOPSumCheck::prove(g, transcript)?;

        // Step 2: dig into the sumcheck and extract r_x_prime
        let r_x_prime = sumcheck_proof.point.clone();

        // Step 4: compute sigmas and thetas
        let sigmas = mles[0..t * M]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();
        let thetas = mles[t * M..t * (M + N)]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();

        // Step 6: Get the folding challenge
        let rho_bits: Vec<bool> = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        let rho_powers = pows(rho, M + N);

        Ok((
            RW {
                w: Ws
                    .iter()
                    .map(|w| &w.w[..])
                    .chain(ws.iter().map(|w| &w[..]))
                    .slice_rlc(&rho_powers),
                r: Ws.iter().map(|w| w.r).chain(rs).scalar_rlc(&rho_powers),
            },
            Self::RU {
                cm: Us
                    .iter()
                    .map(|u| u.cm)
                    .chain(cms.iter().copied())
                    .scalar_rlc(&rho_powers),
                u: Us
                    .iter()
                    .map(|u| u.u)
                    .chain([VC::Scalar::one(); N])
                    .scalar_rlc(&rho_powers),
                x: Us
                    .iter()
                    .map(|u| &u.x[..])
                    .chain(us.iter().map(|u| &u[..]))
                    .slice_rlc(&rho_powers),
                r_x: r_x_prime,
                v: sigmas
                    .chunks(t)
                    .chain(thetas.chunks(t))
                    .slice_rlc(&rho_powers),
            },
            (
                cms,
                NIMFSProof {
                    sc_proof: sumcheck_proof,
                    sigmas,
                    thetas,
                },
            ),
            rho_bits,
        ))
    }

    #[allow(non_snake_case)]
    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        (cms, proof): &Self::Proof,
    ) -> Result<Self::RU, Error> {
        let Us = &Us.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let d = V::degree();
        let s = proof.sc_proof.point.len();
        let t = V::n_matrices();
        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<VC::Scalar>();

        // absorb instances to transcript
        transcript.add(&Us[..]);
        transcript.add(&us[..]);
        transcript.add(&cms[..]);

        // Step 1: Get some challenges
        let gamma = transcript.challenge_field_element();
        let beta = transcript.challenge_field_elements(s);

        let gamma_powers = pows(gamma, M * t + N);

        let vp_aux_info = VPAuxInfo {
            max_degree: d + 1,
            num_variables: s,
        };

        // Step 3: Start verifying the sumcheck
        // First, compute the expected sumcheck sum: \sum gamma^j v_j
        let mut sum_v_j_gamma = VC::Scalar::zero();
        for (i, U) in Us.iter().enumerate() {
            for j in 0..U.v.len() {
                sum_v_j_gamma += U.v[j] * gamma_powers[i * t + j];
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
                .chunks(t)
                .zip(Us)
                .flat_map(|(sigmas, u)| {
                    let e_lcccs = eq_eval(&u.r_x, &r_x_prime);
                    sigmas.iter().map(move |sigma_j| e_lcccs * sigma_j)
                })
                .chain(proof.thetas.chunks(t).map(|thetas| {
                    e2 * S
                        .iter()
                        .zip(c)
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
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = VC::Scalar::from(<VC::Scalar as PrimeField>::BigInt::from_bits_le(&rho_bits));

        let rho_powers = pows(rho, M + N);

        Ok(Self::RU {
            cm: Us
                .iter()
                .map(|u| u.cm)
                .chain(cms.iter().copied())
                .scalar_rlc(&rho_powers),
            u: Us
                .iter()
                .map(|u| u.u)
                .chain([VC::Scalar::one(); N])
                .scalar_rlc(&rho_powers),
            x: Us
                .iter()
                .map(|u| &u.x[..])
                .chain(us.iter().map(|u| &u[..]))
                .slice_rlc(&rho_powers),
            r_x: r_x_prime,
            v: proof
                .sigmas
                .chunks(t)
                .chain(proof.thetas.chunks(t))
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
