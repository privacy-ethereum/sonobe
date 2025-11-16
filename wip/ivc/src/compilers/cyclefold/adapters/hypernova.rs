use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    groups::CurveVar,
    prelude::{Boolean, ToBitsGadget},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    hypernova::{HyperNova, HyperNovaGadget},
    ova::{AbstractOvaGadget, CycleFoldOva},
    FoldingScheme, FoldingSchemePartialGadget,
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bound, EmulatedFieldVar},
        group::{emulated::EmulatedAffineVar, CI2},
        ops::{
            bits::{FromBitsGadget, ToBitsGadgetExt},
            pow::Pow,
        },
    },
    arithmetizations::{ccs::CCSVariant, r1cs::R1CSConfig},
    commitments::{GroupBasedVectorCommitment, VectorCommitment, VectorCommitmentGadget},
    traits::{SonobeCurve, SonobeField, CF1, CF2},
    transcripts::{Absorbable, AbsorbableGadget},
};

use crate::compilers::cyclefold::{
    circuits::CycleFoldConfig, CycleFoldBasedIVC, FoldingSchemeCycleFoldGadget,
};

/// Configuration for HyperNova's CycleFold circuit
pub struct HyperNovaCycleFoldConfig<
    C,
    const MU: usize,
    const NU: usize,
    const CHALLENGE_BITS: usize,
> {
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const MU: usize, const NU: usize, const CHALLENGE_BITS: usize> Default
    for HyperNovaCycleFoldConfig<C, MU, NU, CHALLENGE_BITS>
{
    fn default() -> Self {
        Self {
            r: vec![false; CHALLENGE_BITS],
            points: vec![C::zero(); Self::N_INPUT_POINTS],
        }
    }
}

impl<C: SonobeCurve, const MU: usize, const NU: usize, const CHALLENGE_BITS: usize> CycleFoldConfig
    for HyperNovaCycleFoldConfig<C, MU, NU, CHALLENGE_BITS>
{
    type C = C;

    const N_INPUT_RANDOMNESS_BITS: usize = CHALLENGE_BITS;
    const N_INPUT_POINTS: usize = MU + NU;

    fn verify_point_rlc(
        &self,
        cs: ConstraintSystemRef<CF2<Self::C>>,
    ) -> Result<(), SynthesisError> {
        let rho = FpVar::new_input(cs.clone(), || {
            Ok(CF2::<C>::from(CI2::<C>::from_bits_le(&self.r)))
        })?;
        let rho_bits = rho.to_n_bits_le(CHALLENGE_BITS)?;

        let points = Vec::new_witness(cs.clone(), || Ok(&self.points[..]))?;
        for point in &points {
            Self::mark_point_as_public(point)?;
        }

        let mut p_folded = C::Var::zero();
        for i in (1..Self::N_INPUT_POINTS).rev() {
            p_folded += &points[i];
            p_folded = p_folded.scalar_mul_le(rho_bits.iter())?;
        }
        p_folded += &points[0];

        Self::mark_point_as_public(&p_folded)
    }
}

impl<
        VC: GroupBasedVectorCommitment,
        V: CCSVariant,
        const M: usize,
        const N: usize,
        const CHALLENGE_BITS: usize,
    > FoldingSchemeCycleFoldGadget<M, N> for HyperNova<VC, V, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 1;

    type CFConfig = HyperNovaCycleFoldConfig<VC::Commitment, M, N, CHALLENGE_BITS>;

    fn to_cyclefold_configs(
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        _proof: &Self::Proof,
        rho: Self::Challenge,
    ) -> Vec<Self::CFConfig> {
        vec![HyperNovaCycleFoldConfig {
            r: rho,
            points: Us
                .iter()
                .map(|U| U.borrow().cm)
                .chain(us.iter().map(|u| u.borrow().cm))
                .collect(),
        }]
    }

    fn to_cyclefold_inputs(
        Us: [<Self::Gadget as FoldingSchemePartialGadget<M, N>>::RU; M],
        us: [<Self::Gadget as FoldingSchemePartialGadget<M, N>>::IU; N],
        UU: <Self::Gadget as FoldingSchemePartialGadget<M, N>>::RU,
        _proof: <Self::Gadget as FoldingSchemePartialGadget<M, N>>::Proof,
        mut rho: <Self::Gadget as FoldingSchemePartialGadget<M, N>>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<VC::Scalar, CF2<VC::Commitment>, true>>>, SynthesisError>
    {
        rho.resize(
            CF2::<VC::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        Ok(vec![once(EmulatedFieldVar::from_bits_le(
            &rho,
            Bound(Zero::zero(), CF2::<VC::Commitment>::MODULUS.into().into()),
        )?)
        .chain(
            Us.into_iter()
                .map(|U| U.cm)
                .chain(us.into_iter().map(|u| u.cm))
                .chain(once(UU.cm))
                .flat_map(|p| [p.x, p.y]),
        )
        .collect()])
    }
}

pub type HyperNovaIVC<VC1, VC2, V = R1CSConfig, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<HyperNova<VC1, V, CHALLENGE_BITS>, CycleFoldOva<VC2, CHALLENGE_BITS>>;

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective as C1};
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as C2;
    use ark_std::{error::Error, sync::Arc, test_rng};
    use sonobe_fs::{
        ova::{
            instance::{circuits::RunningInstanceVar as RUVar, RunningInstance as RU},
            witness::{circuits::RunningWitnessVar as RWVar, RunningWitness as RW},
        },
        FoldingScheme, FoldingSchemeFullGadget, FoldingSchemePartialGadget, PlainInstance as IU,
        PlainInstanceVar as IUVar, PlainWitness as IW, PlainWitnessVar as IWVar,
    };
    use sonobe_primitives::{
        arithmetizations::Arith,
        circuits::utils::CircuitForTest,
        commitments::pedersen::{Pedersen, PedersenEmulatedGadget, PedersenGadget},
        traits::Dummy,
        transcripts::{
            griffin::params::GriffinParams, poseidon::poseidon_canonical_config, Transcript,
        },
    };

    use super::*;
    use crate::{tests::test_ivc, IVCStatefulProver, IVC};

    #[test]
    fn test_hypernova_ova() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        test_ivc::<HyperNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>>, _>(
            (65536, (2048, 2048), Arc::new(GriffinParams::new(16, 5, 9))),
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            vec![(); 20],
            &mut rng,
        )?;

        Ok(())
    }
}
