use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    nova::{CycleFoldNova, Nova},
    ova::CycleFoldOva,
    FoldingSchemePartialGadget,
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bound, EmulatedFieldVar},
        ops::bits::{FromBitsGadget, ToBitsGadgetExt},
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
            points: vec![C::zero(); Self::N_INPUT_POINTS],
        }
    }
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> CycleFoldConfig
    for NovaCycleFoldConfig<C, CHALLENGE_BITS>
{
    type C = C;

    const N_INPUT_RANDOMNESS_BITS: usize = CHALLENGE_BITS;
    const N_INPUT_POINTS: usize = 2;

    fn verify_point_rlc(
        &self,
        cs: ConstraintSystemRef<CF2<Self::C>>,
    ) -> Result<(), SynthesisError> {
        let rho = FpVar::new_input(cs.clone(), || {
            Ok(CF2::<C>::from(
                <CF2<C> as PrimeField>::BigInt::from_bits_le(&self.r[..]),
            ))
        })?;
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
        proof: &Self::Proof,
        rho: Self::Challenge,
    ) -> Vec<Self::CFConfig> {
        vec![
            NovaCycleFoldConfig {
                r: rho.clone(),
                points: vec![U.borrow().cm_e, *proof],
            },
            NovaCycleFoldConfig {
                r: rho,
                points: vec![U.borrow().cm_w, u.borrow().cm_w],
            },
        ]
    }

    fn to_cyclefold_inputs(
        [U]: [<Self::Gadget as FoldingSchemePartialGadget<1, 1>>::RU; 1],
        [u]: [<Self::Gadget as FoldingSchemePartialGadget<1, 1>>::IU; 1],
        UU: <Self::Gadget as FoldingSchemePartialGadget<1, 1>>::RU,
        proof: <Self::Gadget as FoldingSchemePartialGadget<1, 1>>::Proof,
        mut rho: <Self::Gadget as FoldingSchemePartialGadget<1, 1>>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<VC::Scalar, CF2<VC::Commitment>, true>>>, SynthesisError>
    {
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

pub type NovaOvaIVC<VC1, VC2, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldOva<VC2, CHALLENGE_BITS>>;

pub type NovaNovaIVC<VC1, VC2, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldNova<VC2, CHALLENGE_BITS>>;

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective as C1};
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as C2;
    use ark_std::{error::Error, sync::Arc, test_rng};
    use sonobe_primitives::{
        circuits::utils::CircuitForTest, commitments::pedersen::Pedersen,
        transcripts::griffin::GriffinParams,
    };

    use super::*;
    use crate::tests::test_ivc;

    #[test]
    fn test_nova_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        test_ivc::<NovaOvaIVC<Pedersen<C1, true>, Pedersen<C2, true>>, _>(
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

        test_ivc::<NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>>, _>(
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
