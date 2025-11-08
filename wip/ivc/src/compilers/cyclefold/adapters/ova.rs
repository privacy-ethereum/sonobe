use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    prelude::{Boolean, ToBitsGadget},
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use sonobe_fs::{ova::AbstractOvaGadget, FoldingScheme};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bound, EmulatedFieldVar},
        group::emulated::EmulatedAffineVar,
        ops::bits::FromBitsGadget,
    },
    commitments::{GroupBasedVectorCommitment, VectorCommitment, VectorCommitmentGadget},
    traits::{SonobeCurve, SonobeField, CF1, CF2},
    transcripts::{Absorbable, AbsorbableGadget},
};

use crate::compilers::cyclefold::{
    circuits::CycleFoldConfig, CycleFoldBasedIVC, FoldingSchemeCycleFoldGadget,
};

/// Configuration for Ova's CycleFold circuit
pub struct OvaCycleFoldConfig<C, const CHALLENGE_BITS: usize> {
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> Default
    for OvaCycleFoldConfig<C, CHALLENGE_BITS>
{
    fn default() -> Self {
        Self {
            r: vec![false; CHALLENGE_BITS],
            points: vec![C::zero(); Self::N_INPUT_POINTS],
        }
    }
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> CycleFoldConfig
    for OvaCycleFoldConfig<C, CHALLENGE_BITS>
{
    type C = C;

    const RANDOMNESS_BIT_LENGTH: usize = CHALLENGE_BITS;
    // Number of points to be folded in the CycleFold circuit, in Ova's case, this is a fixed
    // amount:
    // 2 points to be folded.
    const N_INPUT_POINTS: usize = 2;
    const N_UNIQUE_RANDOMNESSES: usize = 1;

    fn alloc_points(&self, cs: ConstraintSystemRef<CF2<C>>) -> Result<Vec<C::Var>, SynthesisError> {
        let points = Vec::new_witness(cs.clone(), || Ok(self.points.clone()))?;
        for point in &points {
            Self::mark_point_as_public(point)?;
        }
        Ok(points)
    }

    fn alloc_randomnesses(
        &self,
        cs: ConstraintSystemRef<CF2<C>>,
    ) -> Result<Vec<Vec<Boolean<CF2<C>>>>, SynthesisError> {
        let one = &CF1::<C>::one().into_bigint().to_bits_le()[..CHALLENGE_BITS];
        let one_var = Vec::new_constant(cs.clone(), one)?;
        let r_var = Vec::new_witness(cs.clone(), || Ok(self.r.clone()))?;
        Self::mark_randomness_as_public(&r_var)?;
        Ok(vec![one_var, r_var])
    }
}

impl<VC, const CHALLENGE_BITS: usize> FoldingSchemeCycleFoldGadget<1, 1>
    for AbstractOvaGadget<VC, CHALLENGE_BITS>
where
    VC: VectorCommitmentGadget<
        CommitmentVar = EmulatedAffineVar<
            <<VC as VectorCommitmentGadget>::Native as VectorCommitment>::Commitment,
        >,
        ScalarVar: FromBitsGadget<VC::ConstraintField>,
        Native: GroupBasedVectorCommitment<
            Commitment: SonobeCurve<ScalarField = VC::ConstraintField>,
        >,
    >,
{
    const N_CYCLEFOLDS: usize = 1;

    type CFConfig =
        OvaCycleFoldConfig<<VC::Native as VectorCommitment>::Commitment, CHALLENGE_BITS>;

    type CFScalarVar = EmulatedFieldVar<
        VC::ConstraintField,
        CF2<<VC::Native as VectorCommitment>::Commitment>,
        true,
    >;

    fn to_cyclefold_configs(
        U: &<Self::Native as FoldingScheme<1, 1>>::RU,
        _u: &<Self::Native as FoldingScheme<1, 1>>::IU,
        proof: &<Self::Native as FoldingScheme<1, 1>>::Proof,
        rho: <Self::Native as FoldingScheme<1, 1>>::Challenge,
    ) -> Vec<Self::CFConfig> {
        vec![OvaCycleFoldConfig {
            r: rho,
            points: vec![U.cm, *proof],
        }]
    }

    fn to_cyclefold_inputs(
        U: Self::RU,
        _u: Self::IU,
        UU: Self::RU,
        proof: Self::Proof,
        rho: Self::Challenge,
    ) -> Result<Vec<Vec<Self::CFScalarVar>>, SynthesisError> {
        rho.chunks(
            CF2::<<VC::Native as VectorCommitment>::Commitment>::MODULUS_BIT_SIZE as usize - 1,
        )
        .map(|bits| {
            let mut bits = bits.to_vec();
            bits.resize(
                CF2::<<VC::Native as VectorCommitment>::Commitment>::MODULUS_BIT_SIZE as usize,
                Boolean::FALSE,
            );
            EmulatedFieldVar::from_bits_le(
                &bits,
                Bound(
                    Zero::zero(),
                    CF2::<<VC::Native as VectorCommitment>::Commitment>::MODULUS
                        .into()
                        .into(),
                ),
            )
        })
        .chain(
            [U.cm, proof, UU.cm]
                .into_iter()
                .flat_map(|p| [p.x, p.y])
                .map(Ok),
        )
        .collect::<Result<Vec<_>, _>>()
        .map(|vars| vec![vars])
    }
}

pub type OvaIVC<VC1, VC2, const CHALLENGE_BITS: usize = 128> = CycleFoldBasedIVC<
    <<VC1 as VectorCommitmentGadget>::Native as VectorCommitment>::Commitment,
    <<VC2 as VectorCommitmentGadget>::Native as VectorCommitment>::Commitment,
    AbstractOvaGadget<VC1, CHALLENGE_BITS>,
    AbstractOvaGadget<VC2, CHALLENGE_BITS>,
>;

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
    use crate::{IVCStatefulProver, IVC};

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        let griffin_config = Arc::new(GriffinParams::new(16, 5, 9));

        let step_circuit = CircuitForTest {
            x: Fr::rand(&mut rng),
        };

        let pp = OvaIVC::<PedersenEmulatedGadget<C1, true>, PedersenGadget<C2, true>>::preprocess(
            ((65536, 65536), (2048, 2048), griffin_config.clone()),
            &mut rng,
        )?;

        let (pk, vk) =
            OvaIVC::<PedersenEmulatedGadget<C1, true>, PedersenGadget<C2, true>>::generate_keys(
                pp,
                &step_circuit,
            )?;

        let initial_state = vec![Fr::rand(&mut rng)];

        let mut prover = IVCStatefulProver::<
            _,
            OvaIVC<PedersenEmulatedGadget<C1, true>, PedersenGadget<C2, true>>,
        >::new(pk, step_circuit, initial_state)?;

        for _ in 0..20 {
            prover.prove_step((), &mut rng)?;

            OvaIVC::<PedersenEmulatedGadget<C1, true>, PedersenGadget<C2, true>>::verify(
                &vk,
                prover.i,
                &prover.initial_state,
                &prover.current_state,
                &prover.current_proof,
            )?;
        }

        Ok(())
    }
}
