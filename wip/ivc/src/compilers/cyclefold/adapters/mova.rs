use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{mova::Mova, nova::CycleFoldNova, ova::CycleFoldOva, FoldingSchemeGadgetDef};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bound, EmulatedFieldVar},
        ops::bits::{FromBits, FromBitsGadget, ToBitsGadgetExt},
    },
    commitments::GroupBasedVectorCommitment,
    traits::{SonobeCurve, CF2},
};

use crate::compilers::cyclefold::{
    circuits::CycleFoldConfig, CycleFoldBasedIVC, FoldingSchemeCycleFoldExt,
};

/// Configuration for Mova's CycleFold circuit
pub struct MovaCycleFoldConfig<C, const CHALLENGE_BITS: usize> {
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> Default
    for MovaCycleFoldConfig<C, CHALLENGE_BITS>
{
    fn default() -> Self {
        Self {
            r: vec![false; CHALLENGE_BITS],
            points: vec![C::zero(); 2],
        }
    }
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> CycleFoldConfig
    for MovaCycleFoldConfig<C, CHALLENGE_BITS>
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
    for Mova<VC, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 1;

    type CFConfig = MovaCycleFoldConfig<VC::Commitment, CHALLENGE_BITS>;

    fn to_cyclefold_configs(
        [U]: &[impl Borrow<Self::RU>; 1],
        _us: &[impl Borrow<Self::IU>; 1],
        proof: &Self::Proof<1, 1>,
        rho: Self::Challenge,
    ) -> Vec<Self::CFConfig> {
        vec![MovaCycleFoldConfig {
            r: rho,
            points: vec![U.borrow().cm_w, proof.cm_w],
        }]
    }

    fn to_cyclefold_inputs(
        [U]: [<Self::Gadget as FoldingSchemeGadgetDef>::RU; 1],
        _us: [<Self::Gadget as FoldingSchemeGadgetDef>::IU; 1],
        UU: <Self::Gadget as FoldingSchemeGadgetDef>::RU,
        proof: <Self::Gadget as FoldingSchemeGadgetDef>::Proof<1, 1>,
        mut rho: <Self::Gadget as FoldingSchemeGadgetDef>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<VC::Scalar, CF2<VC::Commitment>>>>, SynthesisError> {
        rho.resize(
            CF2::<VC::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        Ok(vec![once(EmulatedFieldVar::from_bits_le(
            &rho,
            Bound(Zero::zero(), CF2::<VC::Commitment>::MODULUS.into().into()),
        )?)
        .chain(
            [U.cm_w, proof.cm_w, UU.cm_w]
                .into_iter()
                .flat_map(|p| [p.x, p.y]),
        )
        .collect()])
    }
}

pub type MovaOvaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Mova<VC1, CHALLENGE_BITS>, CycleFoldOva<VC2, CHALLENGE_BITS>, T>;

pub type MovaNovaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Mova<VC1, CHALLENGE_BITS>, CycleFoldNova<VC2, CHALLENGE_BITS>, T>;

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
    fn test_mova_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        test_ivc::<MovaOvaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
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
    fn test_mova_nova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        test_ivc::<MovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
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
