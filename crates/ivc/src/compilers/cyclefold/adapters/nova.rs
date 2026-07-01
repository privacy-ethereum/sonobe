//! Nova CycleFold adapter that bridges Nova into the CycleFold IVC compiler.

use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{
    GR1CSVar, alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    FoldingSchemeDefGadget,
    nova::{CycleFoldNova, Nova},
};
#[cfg(feature = "evm")]
use sonobe_primitives::utils::evm::serialize::EVMSerialize;
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bounds, EmulatedFieldVar},
        group::{CF1, CF2, SonobeCurve, emulated::EmulatedAffineVar},
        ops::bits::{FromBits, ToBitsGadgetExt},
    },
    circuits::WitnessToPublic,
    commitments::GroupBasedCommitment,
    transcripts::{
        Transcript, TranscriptGadget,
        replay::{ReplayTranscript, ReplayTranscriptVar},
    },
};

#[cfg(feature = "evm")]
use crate::compilers::cyclefold::evm_verifier::{DeciderFoldFragment, FoldingSchemeEVMExt};
use crate::compilers::cyclefold::{
    CycleFoldBasedIVC, FoldingSchemeCycleFoldExt, circuits::CycleFoldCircuit,
};

/// [`NovaCycleFoldCircuit`] defines CycleFold circuit for Nova.
pub struct NovaCycleFoldCircuit<C, const CHALLENGE_BITS: usize> {
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> Default
    for NovaCycleFoldCircuit<C, CHALLENGE_BITS>
{
    fn default() -> Self {
        Self {
            r: vec![false; CHALLENGE_BITS],
            points: vec![C::zero(); 2],
        }
    }
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> CycleFoldCircuit<CF2<C>>
    for NovaCycleFoldCircuit<C, CHALLENGE_BITS>
{
    fn verify_point_rlc(&self, cs: ConstraintSystemRef<CF2<C>>) -> Result<(), SynthesisError> {
        let rho = FpVar::new_input(cs.clone(), || Ok(CF2::<C>::from_bits_le(&self.r[..])))?;
        let rho_bits = rho.to_n_bits_le(CHALLENGE_BITS)?;

        let points = Vec::<C::Var>::new_witness(cs.clone(), || Ok(&self.points[..]))?;
        points.mark_as_public()?;

        (points[1].scalar_mul_le(rho_bits.iter())? + &points[0]).mark_as_public()
    }
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeCycleFoldExt<1, 1>
    for Nova<CM, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 2;

    type CFCircuit = NovaCycleFoldCircuit<CM::Commitment, CHALLENGE_BITS>;

    #[allow(non_snake_case)]
    fn to_cyclefold_circuits(
        [U]: &[impl Borrow<Self::RU>; 1],
        [u]: &[impl Borrow<Self::IU>; 1],
        proof: &Self::Proof<1, 1>,
        mut transcript: ReplayTranscript<CF1<CM::Commitment>>,
    ) -> Vec<Self::CFCircuit> {
        let rho = transcript.challenge_bits(CHALLENGE_BITS);
        vec![
            NovaCycleFoldCircuit {
                r: rho.clone(),
                points: vec![U.borrow().cm_e, *proof],
            },
            NovaCycleFoldCircuit {
                r: rho,
                points: vec![U.borrow().cm_w, u.borrow().cm_w],
            },
        ]
    }

    #[allow(non_snake_case)]
    fn to_cyclefold_inputs(
        [U]: [<Self::Gadget as FoldingSchemeDefGadget>::RU; 1],
        [u]: [<Self::Gadget as FoldingSchemeDefGadget>::IU; 1],
        UU: <Self::Gadget as FoldingSchemeDefGadget>::RU,
        proof: <Self::Gadget as FoldingSchemeDefGadget>::Proof<1, 1>,
        mut transcript: ReplayTranscriptVar<CF1<CM::Commitment>>,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut rho = transcript.challenge_bits(CHALLENGE_BITS)?;
        rho.resize(
            CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let rho = EmulatedFieldVar::from_bounded_bits_le(
            &rho,
            Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
        )?;
        Ok(vec![
            once(rho.clone())
                .chain(
                    [U.cm_e, proof, UU.cm_e]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(rho)
                .chain(
                    [U.cm_w, u.cm_w, UU.cm_w]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
        ])
    }
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeCycleFoldExt<2, 0>
    for Nova<CM, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 3;

    type CFCircuit = NovaCycleFoldCircuit<CM::Commitment, CHALLENGE_BITS>;

    #[allow(non_snake_case)]
    fn to_cyclefold_circuits(
        [U1, U2]: &[impl Borrow<Self::RU>; 2],
        _: &[impl Borrow<Self::IU>; 0],
        proof: &Self::Proof<2, 0>,
        mut transcript: ReplayTranscript<CF1<CM::Commitment>>,
    ) -> Vec<Self::CFCircuit> {
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = CM::Scalar::from_bits_le(&rho_bits);
        vec![
            NovaCycleFoldCircuit {
                r: rho_bits.clone(),
                points: vec![*proof, U2.borrow().cm_e],
            },
            NovaCycleFoldCircuit {
                r: rho_bits.clone(),
                points: vec![U1.borrow().cm_e, U2.borrow().cm_e * rho + proof],
            },
            NovaCycleFoldCircuit {
                r: rho_bits,
                points: vec![U1.borrow().cm_w, U2.borrow().cm_w],
            },
        ]
    }

    #[allow(non_snake_case)]
    fn to_cyclefold_inputs(
        [U1, U2]: [<Self::Gadget as FoldingSchemeDefGadget>::RU; 2],
        _: [<Self::Gadget as FoldingSchemeDefGadget>::IU; 0],
        UU: <Self::Gadget as FoldingSchemeDefGadget>::RU,
        proof: <Self::Gadget as FoldingSchemeDefGadget>::Proof<2, 0>,
        mut transcript: ReplayTranscriptVar<CF1<CM::Commitment>>,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut rho_bits = transcript.challenge_bits(CHALLENGE_BITS)?;
        rho_bits.resize(
            CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let rho = EmulatedFieldVar::from_bounded_bits_le(
            &rho_bits,
            Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
        )?;
        let cm_tmp =
            EmulatedAffineVar::new_witness(U2.cm_e.cs().or(proof.cs()).or(rho_bits.cs()), || {
                let rho_bits = rho_bits.value().unwrap_or_default();
                let rho = CM::Scalar::from_bits_le(&rho_bits);
                Ok(proof.value().unwrap_or_default() + U2.cm_e.value().unwrap_or_default() * rho)
            })?;
        Ok(vec![
            once(rho.clone())
                .chain(
                    [proof, U2.cm_e, cm_tmp.clone()]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(rho.clone())
                .chain(
                    [U1.cm_e, cm_tmp, UU.cm_e]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(rho)
                .chain(
                    [U1.cm_w, U2.cm_w, UU.cm_w]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
        ])
    }
}

/// [`NovaNovaIVC`] defines a CycleFold-based IVC using Nova as the primary
/// folding scheme and Nova as the secondary folding scheme.
pub type NovaNovaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldNova<VC2, CHALLENGE_BITS>, T>;

#[cfg(feature = "evm")]
impl<
    CM: GroupBasedCommitment<Commitment: sonobe_primitives::utils::evm::serialize::EVMSerialize>,
    const CHALLENGE_BITS: usize,
> FoldingSchemeEVMExt<1, 1> for Nova<CM, CHALLENGE_BITS>
{
    fn decider_fold_fragment() -> DeciderFoldFragment {
        let challenge = "challenge";
        DeciderFoldFragment {
            challenge: challenge.to_string(),
            params: ["U_cm_e", "cm_t", "U_cm_w", "u_cm_w"]
                .map(|p| format!("uint256[2] calldata {p}"))
                .to_vec(),
            body: [
                format!("uint256 rho = {challenge} & ((1 << {CHALLENGE_BITS}) - 1);"),
                "uint256[2] memory cm_e = _ecAdd(U_cm_e, _ecMul(cm_t, rho));".to_string(),
                "uint256[2] memory cm_w = _ecAdd(U_cm_w, _ecMul(u_cm_w, rho));".to_string(),
            ]
            .join("\n"),
            commitments: ["cm_e", "cm_w"].map(ToString::to_string).to_vec(),
        }
    }

    #[allow(non_snake_case)]
    fn verify_calldata(
        [U]: &[impl Borrow<Self::RU>; 1],
        [u]: &[impl Borrow<Self::IU>; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<Vec<u8>, sonobe_fs::Error> {
        let (U, u) = (U.borrow(), u.borrow());
        Ok((&U.cm_e, proof, &U.cm_w, &u.cm_w).to_calldata())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254, Fr, G1Projective as C1};
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as C2;
    use ark_std::{error::Error, rand::thread_rng, sync::Arc};
    #[cfg(feature = "evm")]
    use askama::Template;
    use sonobe_primitives::{
        circuits::test_utils::CircuitForTest,
        commitments::pedersen::Pedersen,
        transcripts::griffin::{GriffinParams, sponge::GriffinSponge},
    };
    use sonobe_snarks::cp::legogroth16::LegoGroth16;
    #[cfg(feature = "evm")]
    use sonobe_snarks::cp::legogroth16::evm_verifier::LegoGroth16VerifierTemplate;
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{
        compilers::cyclefold::CycleFoldBasedIVCDecider,
        tests::{test_decider, test_ivc},
    };
    #[cfg(feature = "evm")]
    use crate::{
        compilers::cyclefold::evm_verifier::CycleFoldBasedIVCDeciderVerifierTemplate,
        tests::test_decider_evm,
    };

    #[test]
    fn test_nova_nova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_ivc::<NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            vec![(); 20],
            &mut rng,
        )
    }

    #[test]
    fn test_nova_nova_decider() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_decider::<
            CycleFoldBasedIVCDecider<
                Nova<Pedersen<C1, true>>,
                CycleFoldNova<Pedersen<C2, true>>,
                GriffinSponge<_>,
                LegoGroth16<Bn254>,
            >,
            _,
        >(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            vec![(); 20],
            &mut rng,
        )
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_nova_nova_decider_evm() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_decider_evm::<
            CycleFoldBasedIVCDecider<
                Nova<Pedersen<C1, true>>,
                CycleFoldNova<Pedersen<C2, true>>,
                GriffinSponge<Fr>,
                LegoGroth16<Bn254>,
            >,
            _,
        >(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            vec![(); 20],
            |(lego_vk, _, _, _, reference_state)| {
                let lego_src = LegoGroth16VerifierTemplate { vk: lego_vk }.render()?;
                let decider_src = CycleFoldBasedIVCDeciderVerifierTemplate::<
                    Nova<Pedersen<C1, true>>,
                    CircuitForTest<Fr>,
                >::new(lego_vk, reference_state)
                .render()?;
                Ok(vec![
                    ("DeciderVerifier.sol".to_string(), decider_src),
                    ("LegoGroth16Verifier.sol".to_string(), lego_src),
                ])
            },
            &mut rng,
        )
    }
}
