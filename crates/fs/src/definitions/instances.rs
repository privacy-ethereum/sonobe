//! Traits and abstractions for folding scheme instances.

use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, select::CondSelectGadget};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::fmt::Debug;
use sonobe_primitives::{
    arithmetizations::ArithConfig,
    circuits::linkage::CF,
    commitments::{CommitmentDef, CommitmentDefGadget},
    traits::Dummy,
    transcripts::{Absorbable, AbsorbableVar},
};

use super::utils::TaggedVec;

/// [`FoldingInstance`] defines the operations that a folding scheme's instance
/// should support.
pub trait FoldingInstance<CM: CommitmentDef>:
    Clone + Debug + PartialEq + Eq + Absorbable + for<'a> Dummy<&'a ArithConfig>
{
    /// [`FoldingInstance::N_COMMITMENTS`] defines the number of commitments
    /// contained in the instance.
    const N_COMMITMENTS: usize;

    /// [`FoldingInstance::commitments`] returns the commitments contained in
    /// the instance.
    // TODO (@winderica): consider the scenario where the instance has multiple
    // commitments of different types.
    fn commitments(&self) -> Vec<&CM::Commitment>;

    /// [`FoldingInstance::public_inputs`] returns the reference to the public
    /// inputs contained in the instance.
    fn public_inputs(&self) -> &[CM::Unit];

    /// [`FoldingInstance::public_inputs_mut`] returns the mutable reference to
    /// the public inputs contained in the instance.
    fn public_inputs_mut(&mut self) -> &mut [CM::Unit];
}

/// [`PlainInstance`] is a vector of field elements that are the statements /
/// public inputs to a constraint system.
/// We provide this type for folding schemes that support such simple instances,
/// enabling compatibility with the definition of accumulation schemes (i.e.,
/// running x plain -> running).
///
/// To distinguish it from the witness vector, we use a tagged vector with tag
/// `'u'` for it.
pub type PlainInstance<V> = TaggedVec<V, 'u'>;

impl<V: Default + Clone> Dummy<&ArithConfig> for PlainInstance<V> {
    fn dummy(cfg: &ArithConfig) -> Self {
        vec![V::default(); cfg.n_public_inputs].into()
    }
}

impl<CM: CommitmentDef> FoldingInstance<CM> for PlainInstance<CM::Unit> {
    const N_COMMITMENTS: usize = 0;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![]
    }

    fn public_inputs(&self) -> &[CM::Unit] {
        self
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Unit] {
        self
    }
}

/// [`FoldingInstanceVar`] is the in-circuit variable of [`FoldingInstance`].
pub trait FoldingInstanceVar<CM: CommitmentDefGadget>:
    AllocVar<Self::Value, CF<CM>>
    + GR1CSVar<CF<CM>, Value: FoldingInstance<CM::Widget>>
    + AbsorbableVar<CF<CM>>
    + CondSelectGadget<CF<CM>>
{
    /// [`FoldingInstanceVar::commitments`] returns the commitments contained in
    /// the instance variable.
    fn commitments(&self) -> Vec<&CM::CommitmentVar>;

    /// [`FoldingInstanceVar::public_inputs`] returns the reference to the
    /// public inputs contained in the instance variable.
    fn public_inputs(&self) -> &Vec<CM::UnitVar>;

    /// [`FoldingInstanceVar::new_witness_with_public_inputs`] allocates a
    /// folding instance in the circuit as a witness variable, with the given
    /// pre-allocated public inputs.
    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<CF<CM>>>,
        u: &Self::Value,
        x: Vec<CM::UnitVar>,
    ) -> Result<Self, SynthesisError>;
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for PlainInstanceVar<CM::UnitVar> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![]
    }

    fn public_inputs(&self) -> &Vec<CM::UnitVar> {
        self
    }

    fn new_witness_with_public_inputs(
        _cs: impl Into<Namespace<CF<CM>>>,
        _u: &Self::Value,
        x: Vec<CM::UnitVar>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self(x))
    }
}

/// [`PlainInstanceVar`] is the in-circuit variable of [`PlainInstance`].
// TODO (@winderica): use a different tag?
pub type PlainInstanceVar<V> = PlainInstance<V>;
