//! Partial in-circuit verifier implementation for ProtoGalaxy.

use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    fields::{FieldVar, fp::FpVar},
    poly::polynomial::univariate::dense::DensePolynomialVar,
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::iter::once;
use sonobe_primitives::{
    algebra::ops::{
        poly::EvaluationDomainGadget,
        pow::PowGadget,
        rlc::{ScalarRLC, SliceRLC},
    },
    commitments::GroupBasedCommitment,
    transcripts::TranscriptGadget,
};

use crate::{FoldingSchemePartialVerifierGadget, protogalaxy::ProtoGalaxyGadget};

impl<CM: GroupBasedCommitment, const N: usize> FoldingSchemePartialVerifierGadget<1, N>
    for ProtoGalaxyGadget<CM>
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<CM::Scalar>,
        [U]: [&Self::RU; 1],
        us: [&Self::IU; N],
        proof: &Self::Proof<1, N>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        transcript.add(&FpVar::constant((proof.f_coeffs.len() as u64).into()))?;
        transcript.add(&FpVar::constant((proof.k_coeffs.len() as u64).into()))?;

        // absorb the committed instances
        transcript.add(U)?;
        transcript.add(&us[..])?;

        let delta = transcript.challenge_field_element()?;
        let deltas = delta.repeated_squares(U.betas.len());

        transcript.add(&proof.f_coeffs)?;

        let alpha = transcript.challenge_field_element()?;

        let f_poly = DensePolynomialVar::from_coefficients_vec(
            [&[U.e.clone()][..], &proof.f_coeffs].concat(),
        );

        let f_alpha = f_poly.evaluate(&alpha)?;

        transcript.add(&proof.k_coeffs)?;

        let H =
            GeneralEvaluationDomain::new(N + 1).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let k_poly = DensePolynomialVar::from_coefficients_slice(&proof.k_coeffs);

        let gamma = transcript.challenge_field_element()?;

        let lagrange_evals = H.evaluate_all_lagrange_coefficients_var(&gamma)?;

        Ok((
            Self::RU {
                e: f_alpha * &lagrange_evals[0]
                    + H.evaluate_vanishing_polynomial_var(&gamma)? * k_poly.evaluate(&gamma)?,
                x: once(&U.x[..])
                    .chain(us.iter().map(|u| &u.x[..]))
                    .slice_rlc(&lagrange_evals),
                betas: [&U.betas[..], &deltas[..]]
                    .into_iter()
                    .slice_rlc(&[FpVar::one(), alpha]),
                phi: {
                    let phis = once(&U.phi)
                        .chain(us.iter().map(|u| &u.phi))
                        .collect::<Vec<_>>();

                    AllocVar::new_witness(phis.cs().or(lagrange_evals.cs()), || {
                        let phis = phis.value().unwrap_or(vec![Default::default(); 1 + N]);
                        let lagrange_evals =
                            lagrange_evals
                                .value()
                                .unwrap_or(vec![Default::default(); 1 + N]);
                        Ok(phis.into_iter().scalar_rlc(&lagrange_evals))
                    })?
                },
            },
            lagrange_evals.into(),
        ))
    }
}
