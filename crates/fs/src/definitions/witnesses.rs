//! Traits and abstractions for folding scheme witnesses.

use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};
use ark_std::fmt::Debug;
use sonobe_primitives::{
    arithmetizations::ArithConfig,
    circuits::linkage::CF,
    commitments::{CommitmentDef, CommitmentDefGadget},
    traits::Dummy,
};

use super::utils::TaggedVec;

/// [`FoldingWitness`] defines the operations that a folding scheme's witness
/// should support.
pub trait FoldingWitness<CM: CommitmentDef>: Debug + for<'a> Dummy<&'a ArithConfig> {
    /// [`FoldingWitness::N_OPENINGS`] defines the number of openings contained
    /// in the witness.
    const N_OPENINGS: usize;

    /// [`FoldingWitness::openings`] returns the reference to all openings
    /// contained in the witness, where each opening a tuple of the values being
    /// committed to and the randomness used in the commitment.
    fn openings(&self) -> Vec<(&[CM::Unit], &CM::Randomness)>;
}

/// [`PlainWitness`] is a vector of field elements that are the witnesses to a
/// constraint system.
/// We provide this type for folding schemes that support such simple witnesses,
/// enabling compatibility with the definition of accumulation schemes (i.e.,
/// running x plain -> running).
///
/// To distinguish it from the instance vector, we use a tagged vector with tag
/// `'w'` for it.
pub type PlainWitness<V> = TaggedVec<V, 'w'>;

impl<V: Default + Clone> Dummy<&ArithConfig> for PlainWitness<V> {
    fn dummy(cfg: &ArithConfig) -> Self {
        vec![V::default(); cfg.n_witnesses].into()
    }
}

impl<CM: CommitmentDef> FoldingWitness<CM> for PlainWitness<CM::Unit> {
    const N_OPENINGS: usize = 0;

    fn openings(&self) -> Vec<(&[CM::Unit], &CM::Randomness)> {
        vec![]
    }
}

/// [`FoldingWitnessVar`] is the in-circuit variable of [`FoldingWitness`].
pub trait FoldingWitnessVar<CM: CommitmentDefGadget>:
    AllocVar<Self::Value, CF<CM>> + GR1CSVar<CF<CM>, Value: FoldingWitness<CM::Widget>>
{
}

impl<CM: CommitmentDefGadget, T> FoldingWitnessVar<CM> for T where
    T: AllocVar<Self::Value, CF<CM>> + GR1CSVar<CF<CM>, Value: FoldingWitness<CM::Widget>>
{
}

/// [`PlainWitnessVar`] is the in-circuit variable of [`PlainWitness`].
// TODO (@winderica): use a different tag?
pub type PlainWitnessVar<V> = PlainWitness<V>;
