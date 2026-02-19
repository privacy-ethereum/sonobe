//! HyperNova CycleFold adapter that bridges HyperNova into the CycleFold IVC
//! compiler.

use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    FoldingSchemeDefGadget, hypernova::HyperNova, nova::CycleFoldNova, ova::CycleFoldOva,
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bounds, EmulatedFieldVar},
        ops::bits::{FromBits, FromBitsGadget, ToBitsGadgetExt},
    },
    arithmetizations::{ccs::CCSVariant, r1cs::R1CSConfig},
    commitments::GroupBasedCommitment,
    traits::{CF2, SonobeCurve},
};

use crate::compilers::cyclefold::{
    CycleFoldBasedIVC, FoldingSchemeCycleFoldExt, circuits::CycleFoldCircuit,
};

/// [`HyperNovaCycleFoldCircuit`] defines CycleFold circuit for HyperNova.
pub struct HyperNovaCycleFoldCircuit<C, const M: usize, const N: usize, const CHALLENGE_BITS: usize>
{
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const M: usize, const N: usize, const CHALLENGE_BITS: usize> Default
    for HyperNovaCycleFoldCircuit<C, M, N, CHALLENGE_BITS>
{
    fn default() -> Self {
        Self {
            r: vec![false; CHALLENGE_BITS],
            points: vec![C::zero(); M + N],
        }
    }
}

impl<C: SonobeCurve, const M: usize, const N: usize, const CHALLENGE_BITS: usize>
    CycleFoldCircuit<CF2<C>> for HyperNovaCycleFoldCircuit<C, M, N, CHALLENGE_BITS>
{
    fn verify_point_rlc(&self, cs: ConstraintSystemRef<CF2<C>>) -> Result<(), SynthesisError> {
        let rho = FpVar::new_input(cs.clone(), || Ok(CF2::<C>::from_bits_le(&self.r)))?;
        let rho_bits = rho.to_n_bits_le(CHALLENGE_BITS)?;

        let points = Vec::new_witness(cs.clone(), || Ok(&self.points[..]))?;
        for point in &points {
            Self::mark_point_as_public(point)?;
        }

        let mut p_folded = C::Var::zero();
        for i in (1..M + N).rev() {
            p_folded += &points[i];
            p_folded = p_folded.scalar_mul_le(rho_bits.iter())?;
        }
        p_folded += &points[0];

        Self::mark_point_as_public(&p_folded)
    }
}

impl<
    CM: GroupBasedCommitment,
    V: CCSVariant,
    const M: usize,
    const N: usize,
    const CHALLENGE_BITS: usize,
> FoldingSchemeCycleFoldExt<M, N> for HyperNova<CM, V, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 1;

    type CFCircuit = HyperNovaCycleFoldCircuit<CM::Commitment, M, N, CHALLENGE_BITS>;

    #[allow(non_snake_case)]
    fn to_cyclefold_circuits(
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        _proof: &Self::Proof<M, N>,
        rho: Self::Challenge,
    ) -> Vec<Self::CFCircuit> {
        vec![HyperNovaCycleFoldCircuit {
            r: rho.into(),
            points: Us
                .iter()
                .map(|U| U.borrow().cm)
                .chain(us.iter().map(|u| u.borrow().cm))
                .collect(),
        }]
    }

    #[allow(non_snake_case)]
    fn to_cyclefold_inputs(
        Us: [<Self::Gadget as FoldingSchemeDefGadget>::RU; M],
        us: [<Self::Gadget as FoldingSchemeDefGadget>::IU; N],
        UU: <Self::Gadget as FoldingSchemeDefGadget>::RU,
        _proof: <Self::Gadget as FoldingSchemeDefGadget>::Proof<M, N>,
        rho: <Self::Gadget as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut rho = rho.to_vec();
        rho.resize(
            CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        Ok(vec![
            once(EmulatedFieldVar::from_bounded_bits_le(
                &rho,
                Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
            )?)
            .chain(
                Us.into_iter()
                    .map(|U| U.cm)
                    .chain(us.into_iter().map(|u| u.cm))
                    .chain(once(UU.cm))
                    .flat_map(|p| [p.x, p.y]),
            )
            .collect(),
        ])
    }
}

/// [`HyperNovaOvaIVC`] defines a CycleFold-based IVC using HyperNova as the
/// primary folding scheme and Ova as the secondary folding scheme.
pub type HyperNovaOvaIVC<VC1, VC2, T, V = R1CSConfig, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<HyperNova<VC1, V, CHALLENGE_BITS>, CycleFoldOva<VC2, CHALLENGE_BITS>, T>;

/// [`HyperNovaNovaIVC`] defines a CycleFold-based IVC using HyperNova as the
/// primary folding scheme and Nova as the secondary folding scheme.
pub type HyperNovaNovaIVC<VC1, VC2, T, V = R1CSConfig, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<HyperNova<VC1, V, CHALLENGE_BITS>, CycleFoldNova<VC2, CHALLENGE_BITS>, T>;

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
    fn test_hypernova_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_ivc::<HyperNovaOvaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
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
    fn test_hypernova_nova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_ivc::<HyperNovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
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
