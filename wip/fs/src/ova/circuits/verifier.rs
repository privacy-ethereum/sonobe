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

use crate::{ova::AbstractOvaGadget, FoldingSchemeGadgetOpsFull, FoldingSchemeGadgetOpsPartial};

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeGadgetOpsPartial<1, 1>
    for AbstractOvaGadget<VC, CHALLENGE_BITS>
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
                cm: VC::CommitmentVar::new_witness(U.cm.cs().or(proof.cs()).or(rho.cs()), || {
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

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeGadgetOpsFull<1, 1>
    for AbstractOvaGadget<VC, CHALLENGE_BITS>
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
