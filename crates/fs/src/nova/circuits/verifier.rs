//! Partial and full in-circuit verifier implementations for Nova.

use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, groups::CurveVar};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    algebra::ops::bits::FromBitsGadget,
    circuits::linkage::CF,
    commitments::{CommitmentDef, CommitmentDefGadget, GroupBasedCommitment},
    transcripts::TranscriptVar,
};

use crate::{
    FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget, nova::AbstractNovaGadget,
};

impl<CM, const B: usize> FoldingSchemePartialVerifierGadget<1, 1> for AbstractNovaGadget<CM, B>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<ConstraintField = CF<CM>>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, SynthesisError> {
        let rho_bits = transcript.add(&U)?.add(&u)?.add(proof)?.challenge_bits(B)?;
        let rho = CM::UnitVar::from_bits_le(&rho_bits)?;

        if U.x.len() != u.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(Self::RU {
            u: (U.u.clone() + &rho)
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
            cm_e: CM::CommitmentVar::new_witness(U.cm_e.cs().or(proof.cs()).or(rho.cs()), || {
                Ok(U.cm_e.value().unwrap_or_default()
                    + proof.value().unwrap_or_default() * rho.value().unwrap_or_default())
            })?,
            cm_w: CM::CommitmentVar::new_witness(U.cm_w.cs().or(u.cm_w.cs()).or(rho.cs()), || {
                Ok(U.cm_w.value().unwrap_or_default()
                    + u.cm_w.value().unwrap_or_default() * rho.value().unwrap_or_default())
            })?,
            x: U.x
                .iter()
                .zip(&u.x)
                .map(|(a, b)| (b.clone() * &rho + a).try_into())
                .collect::<Result<_, _>>()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        })
    }
}

impl<CM, const B: usize> FoldingSchemePartialVerifierGadget<2, 0> for AbstractNovaGadget<CM, B>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<ConstraintField = CF<CM>>,
        [U1, U2]: [&Self::RU; 2],
        _: [&Self::IU; 0],
        proof: &Self::Proof<2, 0>,
    ) -> Result<Self::RU, SynthesisError> {
        let rho_bits = transcript.add(&(U1, U2))?.add(proof)?.challenge_bits(B)?;
        let rho = CM::UnitVar::from_bits_le(&rho_bits)?;

        if U1.x.len() != U2.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(Self::RU {
            u: (U2.u.clone() * &rho + &U1.u)
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
            cm_e: CM::CommitmentVar::new_witness(
                U1.cm_e.cs().or(U2.cm_e.cs()).or(proof.cs()).or(rho.cs()),
                || {
                    let rho = rho.value().unwrap_or_default();
                    Ok(U1.cm_e.value().unwrap_or_default()
                        + proof.value().unwrap_or_default() * rho
                        + U2.cm_e.value().unwrap_or_default() * rho * rho)
                },
            )?,
            cm_w: CM::CommitmentVar::new_witness(
                U1.cm_w.cs().or(U2.cm_w.cs()).or(rho.cs()),
                || {
                    Ok(U1.cm_w.value().unwrap_or_default()
                        + U2.cm_w.value().unwrap_or_default() * rho.value().unwrap_or_default())
                },
            )?,
            x: U1
                .x
                .iter()
                .zip(&U2.x)
                .map(|(a, b)| (b.clone() * &rho + a).try_into())
                .collect::<Result<_, _>>()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        })
    }
}

impl<CM, const B: usize> FoldingSchemeFullVerifierGadget<1, 1> for AbstractNovaGadget<CM, B>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
    CM::CommitmentVar: CurveVar<<CM::Widget as CommitmentDef>::Commitment, CF<CM>>,
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<ConstraintField = CF<CM>>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, SynthesisError> {
        let rho_bits = transcript.add(&U)?.add(&u)?.add(proof)?.challenge_bits(B)?;
        let rho = CM::UnitVar::from_bits_le(&rho_bits)?;

        if U.x.len() != u.x.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(Self::RU {
            u: (U.u.clone() + &rho)
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
            cm_e: proof.scalar_mul_le(rho_bits.iter())? + &U.cm_e,
            cm_w: u.cm_w.scalar_mul_le(rho_bits.iter())? + &U.cm_w,
            x: U.x
                .iter()
                .zip(&u.x)
                .map(|(a, b)| (b.clone() * &rho + a).try_into())
                .collect::<Result<_, _>>()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        })
    }
}
