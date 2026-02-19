//! Partial in-circuit verifier implementation for HyperNova.

use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::Boolean,
};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    algebra::ops::{
        pow::PowGadget,
        rlc::{ScalarRLC, SliceRLC},
    },
    arithmetizations::ccs::CCSVariant,
    commitments::GroupBasedCommitment,
    sumcheck::{
        circuits::SumCheckGadget,
        utils::{EqPolyGadget, VPAuxInfo},
    },
    transcripts::TranscriptGadget,
};

use crate::{FoldingSchemePartialVerifierGadget, hypernova::HyperNovaGadget};

impl<
    CM: GroupBasedCommitment,
    V: CCSVariant,
    const M: usize,
    const N: usize,
    const CHALLENGE_BITS: usize,
> FoldingSchemePartialVerifierGadget<M, N> for HyperNovaGadget<CM, V, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<CM::Scalar>,
        Us: [&Self::RU; M],
        us: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        let d = V::degree();
        let s = proof.sc_proof.len();
        let t = V::n_matrices();
        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<CM::Scalar>();

        // absorb instances to transcript
        transcript.add(&Us[..])?;
        transcript.add(&us[..])?;

        // Step 1: Get some challenges
        let gamma = transcript.challenge_field_element()?;
        let beta = transcript.challenge_field_elements(s)?;

        let gamma_powers = gamma.powers(M * t + N);

        let vp_aux_info = VPAuxInfo {
            max_degree: d + 1,
            num_variables: s,
        };

        // Step 3: Start verifying the sumcheck
        // First, compute the expected sumcheck sum: \sum gamma^j v_j
        let mut sum_v_j_gamma = FpVar::zero();
        for (i, U) in Us.iter().enumerate() {
            for j in 0..U.v.len() {
                sum_v_j_gamma += &U.v[j] * &gamma_powers[i * t + j];
            }
        }

        // Verify the interactive part of the sumcheck
        // Step 2: Dig into the sumcheck claim and extract the randomness used
        let (expected_eval, r_x_prime) =
            SumCheckGadget::verify(sum_v_j_gamma, &proof.sc_proof, &vp_aux_info, transcript)?;

        // Step 5: Finish verifying sumcheck (verify the claim c)
        let c = {
            let e2 = EqPolyGadget::fix_xy_eval(&beta, &r_x_prime);
            proof
                .sigmas
                .chunks(t)
                .zip(Us)
                .flat_map(|(sigmas, u)| {
                    let e_lcccs = EqPolyGadget::fix_xy_eval(&u.r_x, &r_x_prime);
                    sigmas.iter().map(move |sigma_j| &e_lcccs * sigma_j)
                })
                .chain(proof.thetas.chunks(t).map(|thetas| {
                    &e2 * S
                        .iter()
                        .zip(c)
                        .map(|(S_i, &c_i)| {
                            let mut prod = FpVar::one();
                            for &j in S_i {
                                prod *= &thetas[j];
                            }
                            prod * c_i
                        })
                        .sum::<FpVar<_>>()
                }))
                .zip(gamma_powers.iter())
                .map(|(val, gamma_i)| val * gamma_i)
                .sum::<FpVar<_>>()
        };

        // check that the g(r_x') from the sumcheck proof is equal to the computed c from sigmas&thetas
        c.enforce_equal(&expected_eval)?;

        // Step 6: Get the folding challenge
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS)?;
        let rho = Boolean::le_bits_to_fp(&rho_bits)?;

        let rho_powers = rho.powers(M + N);

        Ok((
            Self::RU {
                cm: {
                    let cms = Us
                        .iter()
                        .map(|u| &u.cm)
                        .chain(us.iter().map(|u| &u.cm))
                        .collect::<Vec<_>>();

                    AllocVar::new_witness(cms.cs().or(rho_powers.cs()), || {
                        let cms = cms.value().unwrap_or(vec![Default::default(); M + N]);
                        let rho_powers = rho_powers
                            .value()
                            .unwrap_or(vec![Default::default(); M + N]);
                        Ok(cms.into_iter().scalar_rlc(&rho_powers))
                    })?
                },
                u: Us
                    .iter()
                    .map(|u| u.u.clone())
                    .chain(vec![FpVar::one(); N])
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
            },
            rho_bits.try_into().unwrap(),
        ))
    }
}
