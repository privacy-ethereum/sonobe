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
    ova::CycleFoldOva,
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bounds, EmulatedFieldVar},
        group::emulated::EmulatedAffineVar,
        ops::bits::{FromBits, FromBitsGadget, ToBitsGadgetExt},
    },
    commitments::GroupBasedCommitment,
    traits::{CF2, SonobeCurve},
};

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
        for point in &points {
            Self::mark_point_as_public(point)?;
        }

        Self::mark_point_as_public(&(points[1].scalar_mul_le(rho_bits.iter())? + &points[0]))
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
        rho: Self::Challenge,
    ) -> Vec<Self::CFCircuit> {
        vec![
            NovaCycleFoldCircuit {
                r: rho.into(),
                points: vec![U.borrow().cm_e, *proof],
            },
            NovaCycleFoldCircuit {
                r: rho.into(),
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
        rho: <Self::Gadget as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut rho = rho.to_vec();
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
        rho_bits: Self::Challenge,
    ) -> Vec<Self::CFCircuit> {
        let rho = CM::Scalar::from_bits_le(&rho_bits);
        vec![
            NovaCycleFoldCircuit {
                r: rho_bits.into(),
                points: vec![*proof, U2.borrow().cm_e],
            },
            NovaCycleFoldCircuit {
                r: rho_bits.into(),
                points: vec![U1.borrow().cm_e, U2.borrow().cm_e * rho + proof],
            },
            NovaCycleFoldCircuit {
                r: rho_bits.into(),
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
        rho_bits: <Self::Gadget as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut rho_bits = rho_bits.to_vec();
        rho_bits.resize(
            CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let rho = EmulatedFieldVar::from_bounded_bits_le(
            &rho_bits,
            Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
        )?;
        let x =
            EmulatedAffineVar::new_witness(U2.cm_e.cs().or(proof.cs()).or(rho_bits.cs()), || {
                let rho_bits = rho_bits.value().unwrap_or_default();
                let rho = CM::Scalar::from_bits_le(&rho_bits);
                Ok(proof.value().unwrap_or_default() + U2.cm_e.value().unwrap_or_default() * rho)
            })?;
        Ok(vec![
            once(rho.clone())
                .chain(
                    [proof, U2.cm_e, x.clone()]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(rho.clone())
                .chain([U1.cm_e, x, UU.cm_e].into_iter().flat_map(|p| [p.x, p.y]))
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

/// [`NovaOvaIVC`] defines a CycleFold-based IVC using Nova as the primary
/// folding scheme and Ova as the secondary folding scheme.
pub type NovaOvaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldOva<VC2, CHALLENGE_BITS>, T>;

/// [`NovaNovaIVC`] defines a CycleFold-based IVC using Nova as the primary
/// folding scheme and Nova as the secondary folding scheme.
pub type NovaNovaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldNova<VC2, CHALLENGE_BITS>, T>;

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective as C1};
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as C2;
    use ark_std::{error::Error, rand::thread_rng, sync::Arc};
    use sonobe_primitives::{
        circuits::utils::CircuitForTest,
        commitments::pedersen::Pedersen,
        transcripts::griffin::{GriffinParams, sponge::GriffinSponge},
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::tests::test_ivc;

    #[test]
    fn test_nova_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_ivc::<NovaOvaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
            (65536, (2048, 2048), Arc::new(GriffinParams::new(16, 5, 9))),
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            vec![(); 20],
            &mut rng,
        )?;

        Ok(())
    }

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
        )?;

        Ok(())
    }
}
