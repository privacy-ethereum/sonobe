//! Proof generation for ProtoGalaxy.

use ark_ff::{Field, One, Zero, batch_inversion};
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial,
    univariate::DensePolynomial,
};
use ark_std::{borrow::Borrow, iter::once, rand::RngCore};
use sonobe_primitives::{
    algebra::ops::{
        pow::Pow,
        rlc::{ScalarRLC, SliceRLC},
    },
    arithmetizations::{Arith, ArithConfig, ArithRelation},
    circuits::{Assignments, AssignmentsOwned},
    commitments::GroupBasedCommitment,
    transcripts::Transcript,
};

use crate::{
    Error, FoldStep, FoldingSchemeProver,
    protogalaxy::{ProtoGalaxy, ProtoGalaxy2, ProtoGalaxyKey, ProtoGalaxyProof},
};

impl<CM: GroupBasedCommitment, const N: usize> FoldingSchemeProver<1, N> for ProtoGalaxy<CM> {
    #[allow(non_snake_case)]
    fn prove(
        pk: &ProtoGalaxyKey<Self::Arith, CM>,
        transcript: &mut impl Transcript<CM::Scalar>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        _rng: impl RngCore,
    ) -> Result<FoldStep<Self, 1, N>, Error> {
        if !(N + 1).is_power_of_two() {
            return Err(Error::Unsupported("N + 1 must be a power of two".into()));
        }
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let ws = &ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let r1cs = &pk.arith;
        let cfg = r1cs.config();
        let d = cfg.degree();
        let t = cfg.log_constraints();

        transcript.add(&t);
        transcript.add(&(d * N + 1));

        // absorb the committed instances
        transcript.add(U);
        transcript.add(&us[..]);

        let delta = transcript.challenge_field_element();
        let deltas = delta.repeated_squares(t);

        let mut eval = r1cs.eval_relation(&W.w, &U.x)?;
        eval.resize(1 << t, CM::Scalar::default());

        // F(X)
        let f_poly = calc_f_from_btree(&eval, &U.betas, &deltas);
        let mut f_coeffs = f_poly.coeffs[1..].to_vec();
        f_coeffs.resize(t, CM::Scalar::default());
        transcript.add(&f_coeffs);

        let alpha = transcript.challenge_field_element();

        // eval F(alpha)
        let f_alpha = f_poly.evaluate(&alpha);

        // betas*
        let betas_star = [&U.betas[..], &deltas[..]]
            .into_iter()
            .slice_rlc(&[One::one(), alpha]);

        let zs = once(Assignments::from((One::one(), &U.x, &W.w)))
            .chain(
                ws.iter()
                    .zip(us)
                    .map(|(w, u)| Assignments::from((One::one(), &u.x, &w.w))),
            )
            .collect::<Vec<_>>();

        let G = GeneralEvaluationDomain::<CM::Scalar>::new(d * N + 1)
            .ok_or(Error::DomainCreationFailure)?;
        let H = GeneralEvaluationDomain::<CM::Scalar>::new(N + 1)
            .ok_or(Error::DomainCreationFailure)?;

        let omegas = H.group_gen_inv().powers(H.size());
        let mut lagrange_bases = vec![vec![H.size_inv(); H.size()]];
        for i in 1..H.size() {
            lagrange_bases.push(
                lagrange_bases[i - 1]
                    .iter()
                    .zip(&omegas)
                    .map(|(a, b)| *a * b)
                    .collect(),
            );
        }
        let lagrange_bases = lagrange_bases
            .into_iter()
            .map(DensePolynomial::from_coefficients_vec)
            .collect::<Vec<_>>();

        // Optimized G(X) computation as described in Claim 4.5 of the paper.
        let s_evals = (0..cfg.n_variables())
            .map(|i| {
                lagrange_bases
                    .iter()
                    .zip(&zs)
                    .map(|(l, z)| l * z[i])
                    .fold(DensePolynomial::zero(), |acc, x| acc + x)
                    .evaluate_over_domain(G)
                    .evals
            })
            .collect::<Vec<_>>();

        let mut invs = G
            .elements()
            .map(|e| e - CM::Scalar::one())
            .collect::<Vec<_>>();
        batch_inversion(&mut invs);

        // Compute evaluations of G(X) - F(alpha)*L_0(X)
        let beta_star_pows = Pow::powers_from_repeated_squares(&betas_star);
        let g_evals = G
            .elements()
            .zip(invs)
            .enumerate()
            .map(|(k, (e, inv))| {
                if k % H.size() == 0 {
                    return Ok(CM::Scalar::zero());
                }
                let z = AssignmentsOwned::from((
                    s_evals[0][k],
                    (1..1 + cfg.n_public_inputs())
                        .map(|i| s_evals[i][k])
                        .collect(),
                    (1 + cfg.n_public_inputs()..cfg.n_variables())
                        .map(|i| s_evals[i][k])
                        .collect(),
                ));
                let v = r1cs.evaluate_at(z)?;
                // L_0(e) = (e^H.size() - 1) / (e - 1) / H.size()
                let l_0_eval = H.evaluate_vanishing_polynomial(e) * inv * H.size_inv();
                Ok(v.into_iter().scalar_rlc(&beta_star_pows) - f_alpha * l_0_eval)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // Interpolate G(X) - F(alpha)*L_0(X)
        let g_poly = Evaluations::from_vec_and_domain(g_evals, G).interpolate();
        // Compute K(X) = (G(X) - F(alpha)*L_0(X)) / Z(X)
        let (mut k_poly, r) = g_poly.divide_by_vanishing_poly(H);
        if !r.is_zero() {
            return Err(Error::IndivisibleByVanishingPoly);
        }

        k_poly.coeffs.resize(d * N + 1, CM::Scalar::default());
        transcript.add(&k_poly.coeffs);

        let gamma = transcript.challenge_field_element();

        let lagrange_evals = H.evaluate_all_lagrange_coefficients(gamma);

        Ok(FoldStep {
            next_running_witness: Self::RW {
                w: once(&W.w[..])
                    .chain(ws.iter().map(|w| &w.w[..]))
                    .slice_rlc(&lagrange_evals),
                r: once(W.r)
                    .chain(ws.iter().map(|w| w.r))
                    .scalar_rlc(&lagrange_evals),
            },
            next_running_instance: Self::RU {
                e: f_alpha * lagrange_evals[0]
                    + H.evaluate_vanishing_polynomial(gamma) * k_poly.evaluate(&gamma),
                x: once(&U.x[..])
                    .chain(us.iter().map(|u| &u.x[..]))
                    .slice_rlc(&lagrange_evals),
                betas: betas_star,
                phi: once(U.phi)
                    .chain(us.iter().map(|u| u.phi))
                    .scalar_rlc(&lagrange_evals),
            },
            proof: ProtoGalaxyProof {
                f_coeffs,
                k_coeffs: k_poly.coeffs,
            },
            challenge: lagrange_evals.into(),
        })
    }
}

impl<CM: GroupBasedCommitment, const N: usize> FoldingSchemeProver<1, N> for ProtoGalaxy2<CM> {
    #[allow(non_snake_case)]
    fn prove(
        pk: &ProtoGalaxyKey<Self::Arith, CM>,
        transcript: &mut impl Transcript<CM::Scalar>,
        Ws: &[impl Borrow<Self::RW>; 1],
        Us: &[impl Borrow<Self::RU>; 1],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        mut rng: impl RngCore,
    ) -> Result<FoldStep<Self, 1, N>, Error> {
        if !(N + 1).is_power_of_two() {
            return Err(Error::Unsupported("N + 1 must be a power of two".into()));
        }
        let (W, U) = (Ws[0].borrow(), Us[0].borrow());
        let ws = &ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let r1cs = &pk.arith;
        let cfg = r1cs.config();
        let d = cfg.degree();
        let t = cfg.log_constraints();

        let mut phis = [CM::Commitment::default(); N];
        let mut rs = [CM::Randomness::default(); N];
        for i in 0..N {
            let (cm, r) = CM::commit(&pk.ck, ws[i], &mut rng)?;
            phis[i] = cm;
            rs[i] = r;
        }

        transcript.add(&t);
        transcript.add(&(d * N + 1));

        // absorb the committed instances
        transcript.add(U);
        transcript.add(&us[..]);
        transcript.add(&phis[..]);

        let delta = transcript.challenge_field_element();
        let deltas = delta.repeated_squares(t);

        let mut eval = r1cs.eval_relation(&W.w, &U.x)?;
        eval.resize(1 << t, CM::Scalar::default());

        // F(X)
        let f_poly = calc_f_from_btree(&eval, &U.betas, &deltas);
        let mut f_coeffs = f_poly.coeffs[1..].to_vec();
        f_coeffs.resize(t, CM::Scalar::default());
        transcript.add(&f_coeffs);

        let alpha = transcript.challenge_field_element();

        // eval F(alpha)
        let f_alpha = f_poly.evaluate(&alpha);

        // betas*
        let betas_star = [&U.betas[..], &deltas[..]]
            .into_iter()
            .slice_rlc(&[One::one(), alpha]);

        let zs = once(Assignments::from((CM::Scalar::one(), &U.x, &W.w)))
            .chain(
                ws.iter()
                    .zip(us)
                    .map(|(w, u)| Assignments::from((CM::Scalar::one(), u.as_ref(), w.as_ref()))),
            )
            .collect::<Vec<_>>();

        let G = GeneralEvaluationDomain::<CM::Scalar>::new(d * N + 1)
            .ok_or(Error::DomainCreationFailure)?;
        let H = GeneralEvaluationDomain::<CM::Scalar>::new(N + 1)
            .ok_or(Error::DomainCreationFailure)?;

        let omegas = H.group_gen_inv().powers(H.size());
        let mut lagrange_bases = vec![vec![H.size_inv(); H.size()]];
        for i in 1..H.size() {
            lagrange_bases.push(
                lagrange_bases[i - 1]
                    .iter()
                    .zip(&omegas)
                    .map(|(a, b)| *a * b)
                    .collect(),
            );
        }
        let lagrange_bases = lagrange_bases
            .into_iter()
            .map(DensePolynomial::from_coefficients_vec)
            .collect::<Vec<_>>();

        // Optimized G(X) computation as described in Claim 4.5 of the paper.
        let s_evals = (0..cfg.n_variables())
            .map(|i| {
                lagrange_bases
                    .iter()
                    .zip(&zs)
                    .map(|(l, z)| l * z[i])
                    .fold(DensePolynomial::zero(), |acc, x| acc + x)
                    .evaluate_over_domain(G)
                    .evals
            })
            .collect::<Vec<_>>();

        let mut invs = G
            .elements()
            .map(|e| e - CM::Scalar::one())
            .collect::<Vec<_>>();
        batch_inversion(&mut invs);

        // Compute evaluations of G(X) - F(alpha)*L_0(X)
        let beta_star_pows = Pow::powers_from_repeated_squares(&betas_star);
        let g_evals = G
            .elements()
            .zip(invs)
            .enumerate()
            .map(|(k, (e, inv))| {
                if k % H.size() == 0 {
                    return Ok(CM::Scalar::zero());
                }
                let z = AssignmentsOwned::from((
                    s_evals[0][k],
                    (1..1 + cfg.n_public_inputs())
                        .map(|i| s_evals[i][k])
                        .collect(),
                    (1 + cfg.n_public_inputs()..cfg.n_variables())
                        .map(|i| s_evals[i][k])
                        .collect(),
                ));
                let v = r1cs.evaluate_at(z)?;
                // L_0(e) = (e^H.size() - 1) / (e - 1) / H.size()
                let l_0_eval = H.evaluate_vanishing_polynomial(e) * inv * H.size_inv();
                Ok(v.into_iter().scalar_rlc(&beta_star_pows) - f_alpha * l_0_eval)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // Interpolate G(X) - F(alpha)*L_0(X)
        let g_poly = Evaluations::from_vec_and_domain(g_evals, G).interpolate();
        // Compute K(X) = (G(X) - F(alpha)*L_0(X)) / Z(X)
        let (mut k_poly, r) = g_poly.divide_by_vanishing_poly(H);
        if !r.is_zero() {
            return Err(Error::IndivisibleByVanishingPoly);
        }

        k_poly.coeffs.resize(d * N + 1, CM::Scalar::default());
        transcript.add(&k_poly.coeffs);

        let gamma = transcript.challenge_field_element();

        let lagrange_evals = H.evaluate_all_lagrange_coefficients(gamma);

        Ok(FoldStep {
            next_running_witness: Self::RW {
                w: once(&W.w[..])
                    .chain(ws.iter().map(|w| &w[..]))
                    .slice_rlc(&lagrange_evals),
                r: once(W.r).chain(rs).scalar_rlc(&lagrange_evals),
            },
            next_running_instance: Self::RU {
                e: f_alpha * lagrange_evals[0]
                    + H.evaluate_vanishing_polynomial(gamma) * k_poly.evaluate(&gamma),
                x: once(&U.x[..])
                    .chain(us.iter().map(|u| &u[..]))
                    .slice_rlc(&lagrange_evals),
                betas: betas_star,
                phi: once(U.phi).chain(phis).scalar_rlc(&lagrange_evals),
            },
            proof: (
                phis,
                ProtoGalaxyProof {
                    f_coeffs,
                    k_coeffs: k_poly.coeffs,
                },
            ),
            challenge: lagrange_evals,
        })
    }
}

// Calculates F[x] using the optimized binary-tree technique described in Claim
// 4.4 of [ProtoGalaxy](https://eprint.iacr.org/2023/1106.pdf)
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
    layer.swap_remove(0)
}
