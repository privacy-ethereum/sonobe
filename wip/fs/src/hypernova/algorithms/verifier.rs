use ark_ff::One;
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    algebra::ops::{
        bits::FromBits,
        pow::Pow,
        rlc::{ScalarRLC, SliceRLC},
    },
    arithmetizations::ccs::CCSVariant,
    commitments::GroupBasedVectorCommitment,
    sumcheck::{
        utils::{EqPoly, VPAuxInfo},
        Error as SumCheckError, IOPSumCheck,
    },
    transcripts::Transcript,
};

use crate::{
    hypernova::{HyperNova, HyperNova2},
    Error, FoldingSchemeVerifier,
};

impl<
        VC: GroupBasedVectorCommitment,
        V: CCSVariant,
        const M: usize,
        const N: usize,
        const CHALLENGE_BITS: usize,
    > FoldingSchemeVerifier<M, N> for HyperNova<VC, V, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, Error> {
        let Us = &Us.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let d = V::degree();
        let s = proof.sc_proof.len();
        let t = V::n_matrices();
        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<VC::Scalar>();

        // absorb instances to transcript
        transcript.add(&Us[..]);
        transcript.add(&us[..]);

        // Step 1: Get some challenges
        let gamma = transcript.challenge_field_element();
        let beta = transcript.challenge_field_elements(s);

        let gamma_powers = gamma.powers(M * t + N);

        let vp_aux_info = VPAuxInfo {
            max_degree: d + 1,
            num_variables: s,
        };

        // Step 3: Start verifying the sumcheck
        // First, compute the expected sumcheck sum: \sum gamma^j v_j
        let sum_v_j_gamma = Us
            .iter()
            .zip(gamma_powers.chunks(t))
            .flat_map(|(U, gammas)| U.v.iter().zip(gammas).map(|(&v, &g)| v * g))
            .sum();

        // Verify the interactive part of the sumcheck
        // Step 2: Dig into the sumcheck claim and extract the randomness used
        let (claimed_eval, r_x_prime) =
            IOPSumCheck::verify(sum_v_j_gamma, &proof.sc_proof, &vp_aux_info, transcript)?;

        // Step 5: Finish verifying sumcheck (verify the claim c)
        let e_beta = EqPoly::fix_xy_eval(&beta, &r_x_prime);
        let c = proof
            .sigmas
            .chunks(t)
            .zip(Us)
            .flat_map(|(sigmas, u)| {
                let e_lcccs = EqPoly::fix_xy_eval(&u.r_x, &r_x_prime);
                sigmas.iter().map(move |sigma_j| e_lcccs * sigma_j)
            })
            .chain(proof.thetas.chunks(t).map(|thetas| {
                S.iter()
                    .zip(c)
                    .map(|(S_i, &c_i)| c_i * S_i.iter().map(|&j| thetas[j]).product::<VC::Scalar>())
                    .sum::<VC::Scalar>()
                    * e_beta
            }))
            .zip(gamma_powers)
            .map(|(val, gamma_i)| val * gamma_i)
            .sum::<VC::Scalar>();
        // check that the g(r_x') from the sumcheck proof is equal to the computed c from sigmas&thetas
        (c == claimed_eval).then_some(()).ok_or_else(|| {
            SumCheckError::IncorrectEvaluation(claimed_eval.to_string(), c.to_string())
        })?;

        // Step 6: Get the folding challenge
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = VC::Scalar::from_bits_le(&rho_bits);

        let rho_powers = rho.powers(M + N);

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

impl<
        VC: GroupBasedVectorCommitment,
        V: CCSVariant,
        const M: usize,
        const N: usize,
        const CHALLENGE_BITS: usize,
    > FoldingSchemeVerifier<M, N> for HyperNova2<VC, V, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &(),
        transcript: &mut impl Transcript<VC::Scalar>,
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        (cms, proof): &Self::Proof<M, N>,
    ) -> Result<Self::RU, Error> {
        let Us = &Us.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let d = V::degree();
        let s = proof.sc_proof.len();
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

        let gamma_powers = gamma.powers(M * t + N);

        let vp_aux_info = VPAuxInfo {
            max_degree: d + 1,
            num_variables: s,
        };

        // Step 3: Start verifying the sumcheck
        // First, compute the expected sumcheck sum: \sum gamma^j v_j
        let sum_v_j_gamma = Us
            .iter()
            .zip(gamma_powers.chunks(t))
            .flat_map(|(U, gammas)| U.v.iter().zip(gammas).map(|(&v, &g)| v * g))
            .sum();

        // Verify the interactive part of the sumcheck
        // Step 2: Dig into the sumcheck claim and extract the randomness used
        let (claimed_eval, r_x_prime) =
            IOPSumCheck::verify(sum_v_j_gamma, &proof.sc_proof, &vp_aux_info, transcript)?;

        // Step 5: Finish verifying sumcheck (verify the claim c)
        let e_beta = EqPoly::fix_xy_eval(&beta, &r_x_prime);
        let c = proof
            .sigmas
            .chunks(t)
            .zip(Us)
            .flat_map(|(sigmas, u)| {
                let e_lcccs = EqPoly::fix_xy_eval(&u.r_x, &r_x_prime);
                sigmas.iter().map(move |sigma_j| e_lcccs * sigma_j)
            })
            .chain(proof.thetas.chunks(t).map(|thetas| {
                S.iter()
                    .zip(c)
                    .map(|(S_i, &c_i)| c_i * S_i.iter().map(|&j| thetas[j]).product::<VC::Scalar>())
                    .sum::<VC::Scalar>()
                    * e_beta
            }))
            .zip(gamma_powers)
            .map(|(val, gamma_i)| val * gamma_i)
            .sum::<VC::Scalar>();
        // check that the g(r_x') from the sumcheck proof is equal to the computed c from sigmas&thetas
        (c == claimed_eval).then_some(()).ok_or_else(|| {
            SumCheckError::IncorrectEvaluation(claimed_eval.to_string(), c.to_string())
        })?;

        // Step 6: Get the folding challenge
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = VC::Scalar::from_bits_le(&rho_bits);

        let rho_powers = rho.powers(M + N);

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
