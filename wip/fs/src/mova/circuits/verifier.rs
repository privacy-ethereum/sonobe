use ark_ff::{One, Zero};
use ark_r1cs_std::{
    alloc::AllocVar, fields::fp::FpVar, poly::polynomial::univariate::dense::DensePolynomialVar,
    GR1CSVar,
};
use ark_relations::gr1cs::SynthesisError;
use num_bigint::BigInt;
use sonobe_primitives::{
    algebra::{field::emulated::Bound, ops::bits::FromBitsGadget},
    commitments::GroupBasedVectorCommitment,
    transcripts::TranscriptVar,
};

use crate::{mova::MovaGadget, FoldingSchemeGadgetOpsPartial};

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
            Self::RU {
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
            rho_bits.try_into().unwrap(),
        ))
    }
}
