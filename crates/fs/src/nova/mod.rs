//! This module implements the Nova folding scheme, which is introduced in this
//! [paper].
//!
//! [paper]: https://eprint.iacr.org/2021/370.pdf

use ark_r1cs_std::boolean::Boolean;
use ark_std::marker::PhantomData;
use sonobe_primitives::{
    algebra::group::{BF, SF},
    arithmetizations::r1cs::R1CS,
    circuits::linkage::{CF, Gadget, HasConstraintField, HasGadget, HasWidget},
    commitments::{CommitmentDefGadget, FieldFriendly, GroupBasedCommitment, GroupFriendly},
    traits::SonobeField,
};

use self::{
    instances::{
        IncomingInstance as IU, RunningInstance as RU,
        circuits::{IncomingInstanceVar as IUVar, RunningInstanceVar as RUVar},
    },
    witnesses::{IncomingWitness as IW, RunningWitness as RW},
};
use crate::{
    FoldingSchemeDef, FoldingSchemeDefGadget, GroupBasedFoldingSchemePrimaryDef,
    GroupBasedFoldingSchemeSecondaryDef,
    definitions::variants::{Primary, Secondary},
    nova::keys::NovaKey,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod keys;
pub mod witnesses;

// used for the RO challenges.
// From [Srinath Setty](https://microsoft.com/en-us/research/people/srinath/): In Nova, soundness
// error ≤ 2/|S|, where S is the subset of the field F from which the challenges are drawn. In this
// case, we keep the size of S close to 2^128.
/// [`AbstractNova`] implements the Nova folding scheme which can operate on
/// both the primary and secondary curves.
pub struct AbstractNova<CM, TF, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<(CM, TF)>,
}

/// [`Nova`] is the main Nova folding scheme on the primary curve.
pub type Nova<CM, const CHALLENGE_BITS: usize = 128> = AbstractNova<CM, SF<CM>, CHALLENGE_BITS>;

/// [`CycleFoldNova`] is the Nova folding scheme on the secondary curve which
/// can be used as the folding scheme for folding CycleFold instances.
pub type CycleFoldNova<CM, const CHALLENGE_BITS: usize = 128> =
    AbstractNova<CM, BF<CM>, CHALLENGE_BITS>;

impl<CM: GroupBasedCommitment, TF: SonobeField, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for AbstractNova<CM, TF, CHALLENGE_BITS>
{
    type CM = CM;
    type RW = RW<CM>;
    type RU = RU<CM>;
    type IW = IW<CM>;
    type IU = IU<CM>;

    type TranscriptField = TF;
    type Arith = R1CS<CM::Unit>;

    type Config = usize;
    type PublicParam = CM::Key;
    type DeciderKey = NovaKey<Self::Arith, CM>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = CM::Commitment;
}

/// [`AbstractNovaGadget`] is the in-circuit gadget for [`AbstractNova`].
pub struct AbstractNovaGadget<CM, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<CM>,
}

impl<CM, const CHALLENGE_BITS: usize> HasConstraintField for AbstractNovaGadget<CM, CHALLENGE_BITS>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    type ConstraintField = CF<CM>;
}

impl<CM, const CHALLENGE_BITS: usize> HasWidget for AbstractNovaGadget<CM, CHALLENGE_BITS>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    type Widget = AbstractNova<CM::Widget, CF<CM>, CHALLENGE_BITS>;
}

impl<CM, const CHALLENGE_BITS: usize> FoldingSchemeDefGadget
    for AbstractNovaGadget<CM, CHALLENGE_BITS>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    type CM = CM;
    type RU = RUVar<CM>;
    type IU = IUVar<CM>;
    type VerifierKey = ();
    type Challenge = [Boolean<CF<CM>>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = CM::CommitmentVar;
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> HasGadget<Primary>
    for AbstractNova<CM, SF<CM>, CHALLENGE_BITS>
{
    type Gadget = AbstractNovaGadget<Gadget<CM, FieldFriendly>, CHALLENGE_BITS>;
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemePrimaryDef
    for AbstractNova<CM, SF<CM>, CHALLENGE_BITS>
{
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> HasGadget<Secondary>
    for AbstractNova<CM, BF<CM>, CHALLENGE_BITS>
{
    type Gadget = AbstractNovaGadget<Gadget<CM, GroupFriendly>, CHALLENGE_BITS>;
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemeSecondaryDef
    for AbstractNova<CM, BF<CM>, CHALLENGE_BITS>
{
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_ff::UniformRand;
    use ark_std::{
        error::Error,
        rand::{RngCore, thread_rng},
    };
    use sonobe_primitives::{
        circuits::utils::{CircuitForTest, satisfying_assignments_for_test},
        commitments::pedersen::Pedersen,
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::tests::test_folding_scheme;

    fn test_nova_opt<TF: SonobeField>(
        rounds: usize,
        mut rng: impl RngCore,
    ) -> Result<(), Box<dyn Error>> {
        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, true>, TF>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, false>, TF>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, true>, TF>, 2, 0>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, false>, TF>, 2, 0>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;
        Ok(())
    }

    #[test]
    fn test_nova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_nova_opt::<Fr>(10, &mut rng)?;
        test_nova_opt::<Fq>(10, &mut rng)?;
        Ok(())
    }
}
