//! Partial and full in-circuit verifier implementations for Ova.

use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, groups::CurveVar};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    algebra::ops::bits::FromBitsGadget,
    commitments::{CommitmentDef, CommitmentDefGadget, GroupBasedCommitment},
    transcripts::TranscriptGadget,
};

use crate::{
    FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget, ova::AbstractOvaGadget,
};

impl<CM, const CHALLENGE_BITS: usize> FoldingSchemePartialVerifierGadget<1, 1>
    for AbstractOvaGadget<CM, CHALLENGE_BITS>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<CM::ConstraintField>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        let rho_bits = {
            transcript.add(&U)?;
            transcript.add(&u)?;
            transcript.add(proof)?;
            transcript.challenge_bits(CHALLENGE_BITS)?
        };
        let rho = CM::ScalarVar::from_bits_le(&rho_bits)?;

        Ok((
            Self::RU {
                u: (U.u.clone() + &rho)
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
                cm: CM::CommitmentVar::new_witness(U.cm.cs().or(proof.cs()).or(rho.cs()), || {
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
            rho_bits.try_into().unwrap(),
        ))
    }
}

impl<CM, const CHALLENGE_BITS: usize> FoldingSchemeFullVerifierGadget<1, 1>
    for AbstractOvaGadget<CM, CHALLENGE_BITS>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
    CM::CommitmentVar: CurveVar<<CM::Widget as CommitmentDef>::Commitment, CM::ConstraintField>,
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<CM::ConstraintField>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, SynthesisError> {
        let rho_bits = {
            transcript.add(&U)?;
            transcript.add(&u)?;
            transcript.add(proof)?;
            transcript.challenge_bits(CHALLENGE_BITS)?
        };
        let rho = CM::ScalarVar::from_bits_le(&rho_bits)?;

        Ok(Self::RU {
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
