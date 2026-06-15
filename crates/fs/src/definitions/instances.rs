//! Traits and abstractions for folding scheme instances.

use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, select::CondSelectGadget};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::fmt::Debug;
use sonobe_primitives::{
    arithmetizations::ArithConfig,
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
    /// [`FoldingInstance::commitments`] returns the commitments contained in
    /// the instance.
    // TODO (@winderica): consider the scenario where the instance has multiple
    // commitments of different types.
    fn commitments(&self) -> Vec<CM::Commitment>;
}

pub trait FoldingIncomingInstance<CM: CommitmentDef>:
    FoldingInstance<CM>
{
    type PublicInput;

    /// [`FoldingInstance::public_inputs`] returns the reference to the public
    /// inputs contained in the instance.
    fn public_inputs(&self) -> &[Self::PublicInput];
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

impl<CM: CommitmentDef> FoldingInstance<CM> for PlainInstance<CM::Scalar> {
    fn commitments(&self) -> Vec<CM::Commitment> {
        vec![]
    }
}

impl<CM: CommitmentDef> FoldingIncomingInstance<CM> for PlainInstance<CM::Scalar> {
    type PublicInput = CM::Scalar;

    fn public_inputs(&self) -> &[CM::Scalar] {
        self
    }
}

/// [`FoldingInstanceVar`] is the in-circuit variable of [`FoldingInstance`].
pub trait FoldingInstanceVar<CM: CommitmentDefGadget>:
    AllocVar<Self::Value, CM::ConstraintField>
    + GR1CSVar<CM::ConstraintField, Value: FoldingInstance<CM::Widget>>
    + AbsorbableVar<CM::ConstraintField>
    + CondSelectGadget<CM::ConstraintField>
{
    /// [`FoldingInstanceVar::commitments`] returns the commitments contained in
    /// the instance variable.
    fn commitments(&self) -> Vec<&CM::CommitmentVar>;

    /// [`FoldingInstanceVar::public_inputs`] returns the reference to the
    /// public inputs contained in the instance variable.
    fn public_inputs(&self) -> &Vec<CM::ScalarVar>;

    /// [`FoldingInstanceVar::new_witness_with_public_inputs`] allocates a
    /// folding instance in the circuit as a witness variable, with the given
    /// pre-allocated public inputs.
    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        u: &Self::Value,
        x: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError>;
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for PlainInstanceVar<CM::ScalarVar> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![]
    }

    fn public_inputs(&self) -> &Vec<CM::ScalarVar> {
        self
    }

    fn new_witness_with_public_inputs(
        _cs: impl Into<Namespace<CM::ConstraintField>>,
        _u: &Self::Value,
        x: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self(x))
    }
}

/// [`PlainInstanceVar`] is the in-circuit variable of [`PlainInstance`].
// TODO (@winderica): use a different tag?
pub type PlainInstanceVar<V> = PlainInstance<V>;
