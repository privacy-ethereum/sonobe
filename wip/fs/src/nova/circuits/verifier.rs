use ark_ff::{One, Zero};
use ark_r1cs_std::{
    alloc::AllocVar, groups::CurveVar, GR1CSVar,
};
use ark_relations::gr1cs::SynthesisError;
use num_bigint::BigInt;
use sonobe_primitives::{
    algebra::{field::emulated::Bound, ops::bits::FromBitsGadget},
    commitments::{GroupBasedVectorCommitment, VectorCommitmentDef, VectorCommitmentGadgetDef},
    transcripts::TranscriptVar,
};

use crate::{
    nova::AbstractNovaGadget, FoldingSchemeGadgetOpsFull,
    FoldingSchemeGadgetOpsPartial,
};

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeGadgetOpsPartial<1, 1>
    for AbstractNovaGadget<VC, CHALLENGE_BITS>
where
    VC: VectorCommitmentGadgetDef<Native: GroupBasedVectorCommitment>,
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<VC::ConstraintField>,
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
        let rho = VC::ScalarVar::from_bits_le(
            &rho_bits,
            Bound(
                BigInt::zero(),
                (BigInt::one() << CHALLENGE_BITS) - BigInt::one(),
            ),
        )?;

        Ok((
            Self::RU {
                u: (U.u.clone() + &rho)
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
                cm_e: VC::CommitmentVar::new_witness(
                    U.cm_e.cs().or(proof.cs()).or(rho.cs()),
                    || {
                        Ok(U.cm_e.value().unwrap_or_default()
                            + proof.value().unwrap_or_default() * rho.value().unwrap_or_default())
                    },
                )?,
                cm_w: VC::CommitmentVar::new_witness(
                    U.cm_w.cs().or(u.cm_w.cs()).or(rho.cs()),
                    || {
                        Ok(U.cm_w.value().unwrap_or_default()
                            + u.cm_w.value().unwrap_or_default() * rho.value().unwrap_or_default())
                    },
                )?,
                x: U.x
                    .iter()
                    .zip(&u.x)
                    .map(|(a, b)| (b.clone() * &rho + a).try_into())
                    .collect::<Result<_, _>>()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
            },
            rho_bits.try_into().unwrap(),
        ))
    }
}

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeGadgetOpsPartial<2, 0>
    for AbstractNovaGadget<VC, CHALLENGE_BITS>
where
    VC: VectorCommitmentGadgetDef<Native: GroupBasedVectorCommitment>,
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<VC::ConstraintField>,
        [U1, U2]: [&Self::RU; 2],
        _: [&Self::IU; 0],
        proof: &Self::Proof<2, 0>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        let rho_bits = {
            transcript.add(&U1)?;
            transcript.add(&U2)?;
            transcript.add(proof)?;
            transcript.challenge_bits(CHALLENGE_BITS)?
        };
        let rho = VC::ScalarVar::from_bits_le(
            &rho_bits,
            Bound(
                BigInt::zero(),
                (BigInt::one() << CHALLENGE_BITS) - BigInt::one(),
            ),
        )?;

        Ok((
            Self::RU {
                u: (U2.u.clone() * &rho + &U1.u)
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
                cm_e: VC::CommitmentVar::new_witness(
                    U1.cm_e.cs().or(U2.cm_e.cs()).or(proof.cs()).or(rho.cs()),
                    || {
                        let rho = rho.value().unwrap_or_default();
                        Ok(U1.cm_e.value().unwrap_or_default()
                            + proof.value().unwrap_or_default() * rho
                            + U2.cm_e.value().unwrap_or_default() * rho * rho)
                    },
                )?,
                cm_w: VC::CommitmentVar::new_witness(
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
            },
            rho_bits.try_into().unwrap(),
        ))
    }
}

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeGadgetOpsFull<1, 1>
    for AbstractNovaGadget<VC, CHALLENGE_BITS>
where
    VC: VectorCommitmentGadgetDef<Native: GroupBasedVectorCommitment>,
    VC::CommitmentVar:
        CurveVar<<VC::Native as VectorCommitmentDef>::Commitment, VC::ConstraintField>,
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<VC::ConstraintField>,
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
        let rho = VC::ScalarVar::from_bits_le(
            &rho_bits,
            Bound(
                BigInt::zero(),
                (BigInt::one() << CHALLENGE_BITS) - BigInt::one(),
            ),
        )?;

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
