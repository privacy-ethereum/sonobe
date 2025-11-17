use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    nova::CycleFoldNova, ova::CycleFoldOva, protogalaxy::ProtoGalaxy, FoldingSchemePartialGadget,
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bound, EmulatedFieldVar},
        group::CI2,
        ops::bits::{FromBitsGadget, ToBitsGadgetExt},
    },
    commitments::GroupBasedVectorCommitment,
    traits::{SonobeCurve, CF1, CF2},
};

use crate::compilers::cyclefold::{
    circuits::CycleFoldConfig, CycleFoldBasedIVC, FoldingSchemeCycleFoldExt,
};

/// Configuration for ProtoGalaxy's CycleFold circuit
pub struct ProtoGalaxyCycleFoldConfig<C: SonobeCurve, const N: usize> {
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const N: usize> Default for ProtoGalaxyCycleFoldConfig<C, N> {
    fn default() -> Self {
        Self {
            r: vec![false; CF1::<C>::MODULUS_BIT_SIZE as usize * Self::N_INPUT_POINTS],
            points: vec![C::zero(); Self::N_INPUT_POINTS],
        }
    }
}

impl<C: SonobeCurve, const N: usize> CycleFoldConfig for ProtoGalaxyCycleFoldConfig<C, N> {
    type C = C;

    const N_INPUT_RANDOMNESS_BITS: usize =
        CF1::<C>::MODULUS_BIT_SIZE as usize * Self::N_INPUT_POINTS;
    const N_INPUT_POINTS: usize = 1 + N;

    fn verify_point_rlc(
        &self,
        cs: ConstraintSystemRef<CF2<Self::C>>,
    ) -> Result<(), SynthesisError> {
        let rhos = self
            .r
            .chunks(Self::FIELD_CAPACITY)
            .map(|bits| {
                FpVar::new_input(cs.clone(), || {
                    Ok(CF2::<C>::from(CI2::<C>::from_bits_le(bits)))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut bit_lengths =
            vec![Self::FIELD_CAPACITY; Self::N_INPUT_RANDOMNESS_BITS / Self::FIELD_CAPACITY];
        if !Self::N_INPUT_RANDOMNESS_BITS.is_multiple_of(Self::FIELD_CAPACITY) {
            bit_lengths.push(Self::N_INPUT_RANDOMNESS_BITS % Self::FIELD_CAPACITY);
        }
        let rho_bits = rhos
            .iter()
            .zip(bit_lengths)
            .map(|(rho, len)| rho.to_n_bits_le(len))
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

impl<VC: GroupBasedVectorCommitment, const N: usize> FoldingSchemeCycleFoldExt<1, N>
    for ProtoGalaxy<VC>
{
    const N_CYCLEFOLDS: usize = 1;

    type CFConfig = ProtoGalaxyCycleFoldConfig<VC::Commitment, N>;

    fn to_cyclefold_configs(
        [U]: &[impl Borrow<Self::RU>; 1],
        us: &[impl Borrow<Self::IU>; N],
        _proof: &Self::Proof,
        lagrange_evals: Self::Challenge,
    ) -> Vec<Self::CFConfig> {
        vec![ProtoGalaxyCycleFoldConfig {
            r: lagrange_evals
                .iter()
                .flat_map(|eval| {
                    let mut bits = eval.into_bigint().to_bits_le();
                    bits.resize(VC::Scalar::MODULUS_BIT_SIZE as usize, false);
                    bits
                })
                .collect(),
            points: once(U.borrow().phi)
                .chain(us.iter().map(|u| u.borrow().phi))
                .collect(),
        }]
    }

    fn to_cyclefold_inputs(
        [U]: [<Self::Gadget as FoldingSchemePartialGadget<1, N>>::RU; 1],
        us: [<Self::Gadget as FoldingSchemePartialGadget<1, N>>::IU; N],
        UU: <Self::Gadget as FoldingSchemePartialGadget<1, N>>::RU,
        _proof: <Self::Gadget as FoldingSchemePartialGadget<1, N>>::Proof,
        lagrange_evals: Vec<FpVar<VC::Scalar>>,
    ) -> Result<Vec<Vec<EmulatedFieldVar<VC::Scalar, CF2<VC::Commitment>, true>>>, SynthesisError>
    {
        let lagrange_evals_bits = lagrange_evals
            .into_iter()
            .map(|eval| eval.to_n_bits_le(VC::Scalar::MODULUS_BIT_SIZE as usize))
            .collect::<Result<Vec<_>, _>>()?
            .concat();

        Ok(vec![lagrange_evals_bits
            .chunks(CF2::<VC::Commitment>::MODULUS_BIT_SIZE as usize - 1)
            .map(|bits| {
                EmulatedFieldVar::from_bits_le(
                    &[
                        bits,
                        &vec![
                            Boolean::FALSE;
                            CF2::<VC::Commitment>::MODULUS_BIT_SIZE as usize - bits.len()
                        ][..],
                    ]
                    .concat(),
                    Bound(Zero::zero(), CF2::<VC::Commitment>::MODULUS.into().into()),
                )
            })
            .chain(
                once(U.phi)
                    .chain(us.into_iter().map(|u| u.phi))
                    .chain([UU.phi])
                    .flat_map(|p| [Ok(p.x), Ok(p.y)]),
            )
            .collect::<Result<_, _>>()?])
    }
}

pub type ProtoGalaxyOvaIVC<VC1, VC2, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<ProtoGalaxy<VC1>, CycleFoldOva<VC2, CHALLENGE_BITS>>;

pub type ProtoGalaxyNovaIVC<VC1, VC2, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<ProtoGalaxy<VC1>, CycleFoldNova<VC2, CHALLENGE_BITS>>;

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
    fn test_protogalaxy_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        test_ivc::<ProtoGalaxyOvaIVC<Pedersen<C1, true>, Pedersen<C2, true>>, _>(
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
        let mut rng = test_rng();

        test_ivc::<ProtoGalaxyNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>>, _>(
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
