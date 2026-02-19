//! ProtoGalaxy CycleFold adapter that bridges ProtoGalaxy into the CycleFold
//! IVC compiler.

use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    FoldingSchemeDefGadget, nova::CycleFoldNova, ova::CycleFoldOva, protogalaxy::ProtoGalaxy,
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bounds, EmulatedFieldVar},
        ops::bits::{FromBits, FromBitsGadget, ToBitsGadgetExt},
    },
    commitments::GroupBasedCommitment,
    traits::{CF1, CF2, SonobeCurve},
};

use crate::compilers::cyclefold::{
    CycleFoldBasedIVC, FoldingSchemeCycleFoldExt, circuits::CycleFoldCircuit,
};

/// [`ProtoGalaxyCycleFoldCircuit`] defines CycleFold circuit for ProtoGalaxy.
pub struct ProtoGalaxyCycleFoldCircuit<C: SonobeCurve, const N: usize> {
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const N: usize> Default for ProtoGalaxyCycleFoldCircuit<C, N> {
    fn default() -> Self {
        Self {
            r: vec![false; CF1::<C>::MODULUS_BIT_SIZE as usize * (1 + N)],
            points: vec![C::zero(); 1 + N],
        }
    }
}

impl<C: SonobeCurve, const N: usize> CycleFoldCircuit<CF2<C>>
    for ProtoGalaxyCycleFoldCircuit<C, N>
{
    fn verify_point_rlc(&self, cs: ConstraintSystemRef<CF2<C>>) -> Result<(), SynthesisError> {
        let rho_bits = self
            .r
            .chunks(CF2::<C>::MODULUS_BIT_SIZE as usize - 1)
            .map(|bits| {
                FpVar::new_input(cs.clone(), || Ok(CF2::<C>::from_bits_le(bits)))?
                    .to_n_bits_le(bits.len())
            })
            .collect::<Result<Vec<_>, _>>()?
            .concat();

        let points = Vec::<C::Var>::new_witness(cs.clone(), || Ok(&self.points[..]))?;
        for point in &points {
            Self::mark_point_as_public(point)?;
        }

        let mut p_folded = C::Var::zero();
        for (point, bits) in points
            .into_iter()
            .zip(rho_bits.chunks(CF1::<C>::MODULUS_BIT_SIZE as usize))
        {
            p_folded += point.scalar_mul_le(bits.iter())?;
        }

        Self::mark_point_as_public(&p_folded)
    }
}

impl<CM: GroupBasedCommitment, const N: usize> FoldingSchemeCycleFoldExt<1, N> for ProtoGalaxy<CM> {
    const N_CYCLEFOLDS: usize = 1;

    type CFCircuit = ProtoGalaxyCycleFoldCircuit<CM::Commitment, N>;

    #[allow(non_snake_case)]
    fn to_cyclefold_circuits(
        [U]: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; N],
        _proof: &Self::Proof<1, N>,
        lagrange_evals: Self::Challenge,
    ) -> Vec<Self::CFCircuit> {
        vec![ProtoGalaxyCycleFoldCircuit {
            r: lagrange_evals
                .iter()
                .flat_map(|eval| {
                    let mut bits = eval.into_bigint().to_bits_le();
                    bits.resize(CM::Scalar::MODULUS_BIT_SIZE as usize, false);
                    bits
                })
                .collect(),
            points: once(U.borrow().phi)
                .chain(us.iter().map(|u| u.borrow().phi))
                .collect(),
        }]
    }

    #[allow(non_snake_case)]
    fn to_cyclefold_inputs(
        [U]: [<Self::Gadget as FoldingSchemeDefGadget>::RU; 1],
        us: [<Self::Gadget as FoldingSchemeDefGadget>::IU; N],
        UU: <Self::Gadget as FoldingSchemeDefGadget>::RU,
        _proof: <Self::Gadget as FoldingSchemeDefGadget>::Proof<1, N>,
        lagrange_evals: <Self::Gadget as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let lagrange_evals_bits = lagrange_evals
            .iter()
            .map(|eval| eval.to_n_bits_le(CM::Scalar::MODULUS_BIT_SIZE as usize))
            .collect::<Result<Vec<_>, _>>()?
            .concat();

        Ok(vec![
            lagrange_evals_bits
                .chunks(CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize - 1)
                .map(|bits| {
                    EmulatedFieldVar::from_bounded_bits_le(
                        &[
                            bits,
                            &vec![
                                Boolean::FALSE;
                                CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize - bits.len()
                            ][..],
                        ]
                        .concat(),
                        Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
                    )
                })
                .chain(
                    once(U.phi)
                        .chain(us.into_iter().map(|u| u.phi))
                        .chain([UU.phi])
                        .flat_map(|p| [Ok(p.x), Ok(p.y)]),
                )
                .collect::<Result<_, _>>()?,
        ])
    }
}

/// [`ProtoGalaxyOvaIVC`] defines a CycleFold-based IVC using ProtoGalaxy as the
/// primary folding scheme and Ova as the secondary folding scheme.
pub type ProtoGalaxyOvaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<ProtoGalaxy<VC1>, CycleFoldOva<VC2, CHALLENGE_BITS>, T>;

/// [`ProtoGalaxyNovaIVC`] defines a CycleFold-based IVC using ProtoGalaxy as
/// the primary folding scheme and Nova as the secondary folding scheme.
pub type ProtoGalaxyNovaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<ProtoGalaxy<VC1>, CycleFoldNova<VC2, CHALLENGE_BITS>, T>;

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
    fn test_protogalaxy_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_ivc::<ProtoGalaxyOvaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
            (65536, (8192, 8192), Arc::new(GriffinParams::new(16, 5, 9))),
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            vec![(); 20],
            &mut rng,
        )?;

        Ok(())
    }

    #[test]
    fn test_protogalaxy_nova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_ivc::<ProtoGalaxyNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
            (65536, 8192, Arc::new(GriffinParams::new(16, 5, 9))),
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            vec![(); 20],
            &mut rng,
        )?;

        Ok(())
    }
}
