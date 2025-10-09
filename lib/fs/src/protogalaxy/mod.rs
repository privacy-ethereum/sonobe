use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, Polynomial,
};
use ark_std::{cfg_into_iter, log2, marker::PhantomData, rand::RngCore, sync::Arc, UniformRand};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use sonobe_primitives::{
    arithmetizations::{r1cs::R1CS, Arith, ArithRelation, Error as ArithError},
    circuits::{Assignments, AssignmentsOwned},
    commitments::VectorCommitment,
    relations::{Relation, WitnessInstanceSampler},
    traits::{ScalarRLC, SliceRLC, SonobeCurve, CF1},
    transcripts::Transcript,
};

use crate::{Error, FoldingScheme};

use instance::{IncomingInstance as IU, RunningInstance as RU};
use witness::{IncomingWitness as IW, RunningWitness as RW};

pub mod instance;
pub mod witness;

pub struct ProtoGalaxyKey<A, VC: VectorCommitment> {
    arith: Arc<A>,
    ck: Arc<VC::Key>,
}

impl<VC: VectorCommitment<Scalar: Field>> ArithRelation<RW<VC>, RU<VC>> for R1CS<VC::Scalar> {
    type Evaluation = Vec<VC::Scalar>;

    fn eval_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<Self::Evaluation, ArithError> {
        ArithRelation::<Vec<VC::Scalar>, Vec<VC::Scalar>>::eval_relation(self, &w.w, &u.x)
    }

    fn check_evaluation(_w: &RW<VC>, u: &RU<VC>, v: Self::Evaluation) -> Result<(), ArithError> {
        if u.betas.len() != log2(v.len()) as usize {
            return Err(ArithError::MalformedAssignments(
                format!("The number of betas in the running instance ({}) does not match the expected length ({}).", u.betas.len(), log2(v.len()))
            ));
        }

        let e = cfg_into_iter!(v)
            .zip(beta_all_powers(&u.betas))
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
    VC: VectorCommitment<Scalar: Field>,
{
    type Error = Error;

    fn check_relation(&self, w: &RW<VC>, u: &RU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(w, u)?;
        // TODO: handle the error properly
        assert!(VC::open(&self.ck, &w.w, &w.r, &u.phi)?);
        Ok(())
    }
}

impl<A, VC> Relation<IW<VC>, IU<VC>> for ProtoGalaxyKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>>,
    VC: VectorCommitment,
{
    type Error = Error;

    fn check_relation(&self, w: &IW<VC>, u: &IU<VC>) -> Result<(), Self::Error> {
        self.arith.check_relation(&w.w, &u.x)?;
        assert!(VC::open(&self.ck, &w.w, &w.r, &u.phi)?);
        Ok(())
    }
}

impl<A, VC: VectorCommitment<Scalar: Field>> WitnessInstanceSampler<IW<VC>, IU<VC>>
    for ProtoGalaxyKey<A, VC>
{
    type Source = AssignmentsOwned<VC::Scalar>;
    type Error = Error;

    fn sample(&self, z: Self::Source, rng: impl RngCore) -> Result<(IW<VC>, IU<VC>), Error> {
        let (w, x) = (z.private, z.public);
        let (phi, r) = VC::commit(&self.ck, &w, rng)?;
        Ok((IW { w, r }, IU { phi, x }))
    }
}

impl<A, VC> WitnessInstanceSampler<RW<VC>, RU<VC>> for ProtoGalaxyKey<A, VC>
where
    A: ArithRelation<Vec<VC::Scalar>, Vec<VC::Scalar>, Evaluation = Vec<VC::Scalar>>,
    VC: VectorCommitment<Scalar: Field>,
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

        let betas = (0..log2(self.arith.n_constraints()) as usize)
            .map(|_| VC::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();

        let v = self.arith.eval_relation(&w, &x)?;

        let e = cfg_into_iter!(v)
            .zip(beta_all_powers(&betas))
            .map(|(x, y)| x * y)
            .sum();

        Ok((RW { w, r }, RU { phi, x, e, betas }))
    }
}

pub struct ProtoGalaxyProof<F> {
    pub f_coeffs: Vec<F>,
    pub k_coeffs: Vec<F>,
}

pub struct ProtoGalaxy<VC> {
    _vc: PhantomData<VC>,
}

impl<VC, const N: usize> FoldingScheme<1, N> for ProtoGalaxy<VC>
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

    type Config = usize;
    type PublicParam = VC::Key;
    type ProverKey = Arc<Self::Arith>;
    type VerifierKey = ();
    type DeciderKey = ProtoGalaxyKey<Self::Arith, VC>;
    type Proof = ProtoGalaxyProof<VC::Scalar>;

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
        Ok((r1cs.clone(), (), ProtoGalaxyKey { arith: r1cs, ck }))
    }

    fn prove(
        r1cs: &Self::ProverKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Ws: &[&Self::RW; 1],
        Us: &[&Self::RU; 1],
        ws: &[&Self::IW; N],
        us: &[&Self::IU; N],
        _rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof), Error> {
        let (W, U) = (Ws[0], Us[0]);
        let d = r1cs.degree();
        let t = log2(r1cs.n_constraints()) as usize;

        if !(N + 1).is_power_of_two() {
            return Err(Error::Unsupported("N + 1 must be a power of two".into()));
        }

        transcript.absorb(&t);
        transcript.absorb(&(d * N + 1));

        // absorb the committed instances
        transcript.absorb(U);
        for u in us {
            transcript.absorb(u);
        }

        let delta = transcript.get_challenge();
        let deltas = exponential_powers(delta, t);

        let mut eval = r1cs.eval_assignments((VC::Scalar::one(), &U.x, &W.w).into())?;
        eval.resize(1 << t, VC::Scalar::default());

        // F(X)
        let f_poly = calc_f_from_btree(&eval, &U.betas, &deltas);
        let mut f_coeffs = f_poly.coeffs[1..].to_vec();
        f_coeffs.resize(t, VC::Scalar::default());
        transcript.absorb(&f_coeffs);

        let alpha = transcript.get_challenge();

        // eval F(alpha)
        let f_alpha = f_poly.evaluate(&alpha);

        // betas*
        let betas_star = betas_star(&U.betas, &deltas, alpha);

        let zs = vec![Assignments::from((VC::Scalar::one(), &U.x, &W.w))]
            .into_iter()
            .chain(
                ws.iter()
                    .zip(us)
                    .map(|(w, u)| Assignments::from((VC::Scalar::one(), &u.x, &w.w))),
            )
            .collect::<Vec<_>>();

        let G = GeneralEvaluationDomain::new((d * N) + 1).ok_or(Error::DomainCreationFailure)?;
        let H = GeneralEvaluationDomain::new(N + 1).ok_or(Error::DomainCreationFailure)?;

        let lagrange_polys = cfg_into_iter!(0..H.size())
            .map(|i| {
                let evals = (0..H.size()).map(|k| VC::Scalar::from(k == i)).collect();
                Evaluations::from_vec_and_domain(evals, H).interpolate()
            })
            .collect::<Vec<_>>();

        // Optimized G(X) computation as described in Claim 4.5 of the paper.
        let beta_star_pows = beta_all_powers(&betas_star);

        let s_evals = (0..r1cs.n_variables())
            .map(|i| {
                lagrange_polys
                    .iter()
                    .zip(&zs)
                    .map(|(l, z)| l * z[i])
                    .fold(DensePolynomial::zero(), |acc, x| acc + x)
                    .evaluate_over_domain_by_ref(G)
                    .evals
            })
            .collect::<Vec<_>>();

        let g_evals = (0..G.size())
            .map(|k| {
                let z = AssignmentsOwned::from((
                    s_evals[0][k],
                    (1..1 + r1cs.n_public_inputs())
                        .map(|i| s_evals[i][k])
                        .collect(),
                    (1 + r1cs.n_public_inputs()..r1cs.n_variables())
                        .map(|i| s_evals[i][k])
                        .collect(),
                ));
                let v = r1cs.eval_assignments(z)?;
                Ok(v.into_iter().scalar_rlc(&beta_star_pows))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let g_poly = Evaluations::from_vec_and_domain(g_evals, G).interpolate();

        let z_poly = H.vanishing_polynomial();
        // K(X) = (G(X) - F(alpha)*L_0(X)) / Z(X)
        // Pending optimization: move division by Z_X to the prev loop
        let (k_poly, r) = (&g_poly - &lagrange_polys[0] * f_alpha).divide_by_vanishing_poly(H);
        assert!(r.is_zero());

        let mut k_coeffs = k_poly.coeffs.clone();
        k_coeffs.resize(d * N + 1, VC::Scalar::default());
        transcript.absorb(&k_coeffs);

        let gamma = transcript.get_challenge();

        let lagrange_evals = lagrange_polys
            .iter()
            .take(N + 1)
            .map(|l| l.evaluate(&gamma))
            .collect::<Vec<_>>();

        Ok((
            RW {
                w: vec![&W.w[..]]
                    .into_iter()
                    .chain(ws.iter().map(|w| &w.w[..]))
                    .slice_rlc(&lagrange_evals),
                r: vec![W.r]
                    .into_iter()
                    .chain(ws.iter().map(|w| w.r))
                    .scalar_rlc(&lagrange_evals),
            },
            RU {
                e: f_alpha * lagrange_evals[0] + z_poly.evaluate(&gamma) * k_poly.evaluate(&gamma),
                x: vec![&U.x[..]]
                    .into_iter()
                    .chain(us.iter().map(|u| &u.x[..]))
                    .slice_rlc(&lagrange_evals),
                betas: betas_star,
                phi: vec![U.phi]
                    .into_iter()
                    .chain(us.iter().map(|u| u.phi))
                    .scalar_rlc(&lagrange_evals),
            },
            ProtoGalaxyProof { f_coeffs, k_coeffs },
        ))
    }

    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[&Self::RU; 1],
        us: &[&Self::IU; N],
        proof: &Self::Proof,
    ) -> Result<Self::RU, Error> {
        let U = Us[0];

        transcript.absorb(&proof.f_coeffs.len());
        transcript.absorb(&proof.k_coeffs.len());

        // absorb the committed instances
        transcript.absorb(U);
        for u in us {
            transcript.absorb(u);
        }

        let delta = transcript.get_challenge();
        let deltas = exponential_powers(delta, U.betas.len());

        transcript.absorb(&proof.f_coeffs);

        let alpha = transcript.get_challenge();

        let f_poly = DensePolynomial::from_coefficients_vec([&[U.e][..], &proof.f_coeffs].concat());

        let f_alpha = f_poly.evaluate(&alpha);

        let betas_star = betas_star(&U.betas, &deltas, alpha);

        transcript.absorb(&proof.k_coeffs);

        let H = GeneralEvaluationDomain::new(N + 1).ok_or(Error::DomainCreationFailure)?;
        let z_poly = H.vanishing_polynomial();
        let k_poly = DensePolynomial::from_coefficients_slice(&proof.k_coeffs);

        let gamma = transcript.get_challenge();

        let lagrange_evals = H.evaluate_all_lagrange_coefficients(gamma);

        Ok(RU {
            e: f_alpha * lagrange_evals[0] + z_poly.evaluate(&gamma) * k_poly.evaluate(&gamma),
            x: vec![&U.x[..]]
                .into_iter()
                .chain(us.iter().map(|u| &u.x[..]))
                .slice_rlc(&lagrange_evals),
            betas: betas_star,
            phi: vec![U.phi]
                .into_iter()
                .chain(us.iter().map(|u| u.phi))
                .scalar_rlc(&lagrange_evals),
        })
    }
}

/// Returns (b, b^2, b^4, ..., b^{2^{t-1}})
pub fn exponential_powers<F: Field>(b: F, t: usize) -> Vec<F> {
    let mut r = vec![F::zero(); t];
    r[0] = b;
    for i in 1..t {
        r[i] = r[i - 1].square();
    }
    r
}

/// calculates F[x] using the optimized binary-tree technique
/// described in Claim 4.4
/// of [ProtoGalaxy](https://eprint.iacr.org/2023/1106.pdf)
fn calc_f_from_btree<F: Field>(fw: &[F], betas: &[F], deltas: &[F]) -> DensePolynomial<F> {
    let mut layer = fw
        .iter()
        .map(|&e| DensePolynomial::from_coefficients_vec(vec![e]))
        .collect::<Vec<_>>();
    for l in 0..betas.len() {
        layer = layer
            .chunks(2)
            .map(|chunk| {
                let e = DensePolynomial::from_coefficients_vec(vec![betas[l], deltas[l]]);
                chunk[1].naive_mul(&e) + &chunk[0]
            })
            .collect();
    }
    layer.pop().unwrap()
}

/// returns a vector containing βᵢ* = βᵢ + α ⋅ δᵢ
pub fn betas_star<F: Field>(betas: &[F], deltas: &[F], alpha: F) -> Vec<F> {
    betas
        .iter()
        .zip(deltas)
        .map(|(beta_i, delta_i)| alpha * delta_i + beta_i)
        .collect()
}

pub fn beta_all_powers<F: Field>(betas: &[F]) -> Vec<F> {
    let mut pows = vec![F::one()];
    for beta in betas.iter().rev() {
        pows = pows
            .into_iter()
            .flat_map(|e| [e, e * beta])
            .collect::<Vec<_>>();
    }
    pows
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

    use crate::tests::test_folding_scheme_1_1;

    use super::*;

    #[test]
    fn test_protogalaxy() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        test_folding_scheme_1_1::<ProtoGalaxy<Pedersen<G1Projective, true>>>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..10)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme_1_1::<ProtoGalaxy<Pedersen<G1Projective, false>>>(
            8,
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
