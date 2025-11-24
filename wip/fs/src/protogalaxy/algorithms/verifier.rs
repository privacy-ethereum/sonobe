use ark_ff::One;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_primitives::{
    algebra::ops::{
        pow::Pow,
        rlc::{ScalarRLC, SliceRLC},
    },
    commitments::GroupBasedVectorCommitment,
    transcripts::Transcript,
};

use crate::{
    protogalaxy::{ProtoGalaxy, ProtoGalaxy2},
    Error, FoldingSchemeVerifier,
};

impl<VC: GroupBasedVectorCommitment, const N: usize> FoldingSchemeVerifier<1, N>
    for ProtoGalaxy<VC>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<1, N>,
    ) -> Result<Self::RU, Error> {
        if !(N + 1).is_power_of_two() {
            return Err(Error::Unsupported("N + 1 must be a power of two".into()));
        }
        let U = Us[0].borrow();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        transcript.add(&proof.f_coeffs.len());
        transcript.add(&proof.k_coeffs.len());

        // absorb the committed instances
        transcript.add(U);
        transcript.add(&us[..]);

        let delta = transcript.challenge_field_element();
        let deltas = delta.repeated_squares(U.betas.len());

        transcript.add(&proof.f_coeffs);

        let alpha = transcript.challenge_field_element();

        let f_poly = DensePolynomial::from_coefficients_vec([&[U.e][..], &proof.f_coeffs].concat());

        let f_alpha = f_poly.evaluate(&alpha);

        transcript.add(&proof.k_coeffs);

        let H = GeneralEvaluationDomain::new(N + 1).ok_or(Error::DomainCreationFailure)?;
        let k_poly = DensePolynomial::from_coefficients_slice(&proof.k_coeffs);

        let gamma = transcript.challenge_field_element();

        let lagrange_evals = H.evaluate_all_lagrange_coefficients(gamma);

        Ok(Self::RU {
            e: f_alpha * lagrange_evals[0]
                + H.evaluate_vanishing_polynomial(gamma) * k_poly.evaluate(&gamma),
            x: once(&U.x[..])
                .chain(us.iter().map(|u| &u.x[..]))
                .slice_rlc(&lagrange_evals),
            betas: [&U.betas[..], &deltas[..]]
                .into_iter()
                .slice_rlc(&[One::one(), alpha]),
            phi: once(U.phi)
                .chain(us.iter().map(|u| u.phi))
                .scalar_rlc(&lagrange_evals),
        })
    }
}

impl<VC: GroupBasedVectorCommitment, const N: usize> FoldingSchemeVerifier<1, N>
    for ProtoGalaxy2<VC>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; N],
        (phis, proof): &Self::Proof<1, N>,
    ) -> Result<Self::RU, Error> {
        if !(N + 1).is_power_of_two() {
            return Err(Error::Unsupported("N + 1 must be a power of two".into()));
        }
        let U = Us[0].borrow();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        transcript.add(&proof.f_coeffs.len());
        transcript.add(&proof.k_coeffs.len());

        // absorb the committed instances
        transcript.add(U);
        transcript.add(&us[..]);
        transcript.add(&phis[..]);

        let delta = transcript.challenge_field_element();
        let deltas = delta.repeated_squares(U.betas.len());

        transcript.add(&proof.f_coeffs);

        let alpha = transcript.challenge_field_element();

        let f_poly = DensePolynomial::from_coefficients_vec([&[U.e][..], &proof.f_coeffs].concat());

        let f_alpha = f_poly.evaluate(&alpha);

        transcript.add(&proof.k_coeffs);

        let H = GeneralEvaluationDomain::new(N + 1).ok_or(Error::DomainCreationFailure)?;
        let k_poly = DensePolynomial::from_coefficients_slice(&proof.k_coeffs);

        let gamma = transcript.challenge_field_element();

        let lagrange_evals = H.evaluate_all_lagrange_coefficients(gamma);

        Ok(Self::RU {
            e: f_alpha * lagrange_evals[0]
                + H.evaluate_vanishing_polynomial(gamma) * k_poly.evaluate(&gamma),
            x: once(&U.x[..])
                .chain(us.iter().map(|u| &u[..]))
                .slice_rlc(&lagrange_evals),
            betas: [&U.betas[..], &deltas[..]]
                .into_iter()
                .slice_rlc(&[One::one(), alpha]),
            phi: once(U.phi).chain(*phis).scalar_rlc(&lagrange_evals),
        })
    }
}
