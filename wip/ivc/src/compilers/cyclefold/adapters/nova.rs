use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean, GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    nova::{CycleFoldNova, Nova},
    ova::CycleFoldOva,
    FoldingSchemeGadgetDef,
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bound, EmulatedFieldVar},
        group::emulated::EmulatedAffineVar,
        ops::bits::{FromBits, FromBitsGadget, ToBitsGadgetExt},
    },
    commitments::GroupBasedVectorCommitment,
    traits::{SonobeCurve, CF2},
};

use crate::compilers::cyclefold::{
    circuits::CycleFoldConfig, CycleFoldBasedIVC, FoldingSchemeCycleFoldExt,
};

/// Configuration for Nova's CycleFold circuit
pub struct NovaCycleFoldConfig<C, const CHALLENGE_BITS: usize> {
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> Default
    for NovaCycleFoldConfig<C, CHALLENGE_BITS>
{
    fn default() -> Self {
        Self {
            r: vec![false; CHALLENGE_BITS],
            points: vec![C::zero(); 2],
        }
    }
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> CycleFoldConfig
    for NovaCycleFoldConfig<C, CHALLENGE_BITS>
{
    type C = C;

    fn verify_point_rlc(
        &self,
        cs: ConstraintSystemRef<CF2<Self::C>>,
    ) -> Result<(), SynthesisError> {
        let rho = FpVar::new_input(cs.clone(), || Ok(CF2::<C>::from_bits_le(&self.r[..])))?;
        let rho_bits = rho.to_n_bits_le(CHALLENGE_BITS)?;

        let points = Vec::<C::Var>::new_witness(cs.clone(), || Ok(&self.points[..]))?;
        for point in &points {
            Self::mark_point_as_public(point)?;
        }

        Self::mark_point_as_public(&(points[1].scalar_mul_le(rho_bits.iter())? + &points[0]))
    }
}

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemeCycleFoldExt<1, 1>
    for Nova<VC, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 2;

    type CFConfig = NovaCycleFoldConfig<VC::Commitment, CHALLENGE_BITS>;

    fn to_cyclefold_configs(
        [U]: &[impl Borrow<Self::RU>; 1],
        [u]: &[impl Borrow<Self::IU>; 1],
        proof: &Self::Proof<1, 1>,
        rho: Self::Challenge,
    ) -> Vec<Self::CFConfig> {
        vec![
            NovaCycleFoldConfig {
                r: rho.into(),
                points: vec![U.borrow().cm_e, *proof],
            },
            NovaCycleFoldConfig {
                r: rho.into(),
                points: vec![U.borrow().cm_w, u.borrow().cm_w],
            },
        ]
    }

    fn to_cyclefold_inputs(
        [U]: [<Self::Gadget as FoldingSchemeGadgetDef>::RU; 1],
        [u]: [<Self::Gadget as FoldingSchemeGadgetDef>::IU; 1],
        UU: <Self::Gadget as FoldingSchemeGadgetDef>::RU,
        proof: <Self::Gadget as FoldingSchemeGadgetDef>::Proof<1, 1>,
        rho: <Self::Gadget as FoldingSchemeGadgetDef>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<VC::Scalar, CF2<VC::Commitment>>>>, SynthesisError> {
        let mut rho = rho.to_vec();
        rho.resize(
            CF2::<VC::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let rho = EmulatedFieldVar::from_bits_le(
            &rho,
            Bound(Zero::zero(), CF2::<VC::Commitment>::MODULUS.into().into()),
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

impl<VC: GroupBasedVectorCommitment, const CHALLENGE_BITS: usize> FoldingSchemeCycleFoldExt<2, 0>
    for Nova<VC, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 3;

    type CFConfig = NovaCycleFoldConfig<VC::Commitment, CHALLENGE_BITS>;

    fn to_cyclefold_configs(
        [U1, U2]: &[impl Borrow<Self::RU>; 2],
        _: &[impl Borrow<Self::IU>; 0],
        proof: &Self::Proof<2, 0>,
        rho_bits: Self::Challenge,
    ) -> Vec<Self::CFConfig> {
        let rho = VC::Scalar::from_bits_le(&rho_bits);
        vec![
            NovaCycleFoldConfig {
                r: rho_bits.into(),
                points: vec![*proof, U2.borrow().cm_e],
            },
            NovaCycleFoldConfig {
                r: rho_bits.into(),
                points: vec![U1.borrow().cm_e, U2.borrow().cm_e * rho + proof],
            },
            NovaCycleFoldConfig {
                r: rho_bits.into(),
                points: vec![U1.borrow().cm_w, U2.borrow().cm_w],
            },
        ]
    }

    fn to_cyclefold_inputs(
        [U1, U2]: [<Self::Gadget as FoldingSchemeGadgetDef>::RU; 2],
        _: [<Self::Gadget as FoldingSchemeGadgetDef>::IU; 0],
        UU: <Self::Gadget as FoldingSchemeGadgetDef>::RU,
        proof: <Self::Gadget as FoldingSchemeGadgetDef>::Proof<2, 0>,
        rho_bits: <Self::Gadget as FoldingSchemeGadgetDef>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<VC::Scalar, CF2<VC::Commitment>>>>, SynthesisError> {
        let mut rho_bits = rho_bits.to_vec();
        rho_bits.resize(
            CF2::<VC::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let rho = EmulatedFieldVar::from_bits_le(
            &rho_bits,
            Bound(Zero::zero(), CF2::<VC::Commitment>::MODULUS.into().into()),
        )?;
        let x =
            EmulatedAffineVar::new_witness(U2.cm_e.cs().or(proof.cs()).or(rho_bits.cs()), || {
                let rho_bits = rho_bits.value().unwrap_or_default();
                let rho = VC::Scalar::from_bits_le(&rho_bits);
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

pub type NovaOvaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldOva<VC2, CHALLENGE_BITS>, T>;

pub type NovaNovaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldNova<VC2, CHALLENGE_BITS>, T>;

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective as C1};
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as C2;
    use ark_std::{error::Error, sync::Arc, test_rng};
    use sonobe_primitives::{
        circuits::utils::CircuitForTest,
        commitments::pedersen::Pedersen,
        transcripts::griffin::{sponge::GriffinSponge, GriffinParams},
    };

    use super::*;
    use crate::tests::test_ivc;

    #[test]
    fn test_nova_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

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
        let mut rng = test_rng();

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
