//! Traits that define variants of folding schemes based on different underlying
//! mathematical structures.

use sonobe_primitives::{
    algebra::group::{BF, SF},
    circuits::linkage::{CircuitRepr, Gadget, HasGadget},
    commitments::{FieldFriendly, GroupBasedCommitment, GroupFriendly},
};

use crate::{
    FoldingSchemeDef, FoldingSchemeDefGadget, FoldingSchemeFullVerifierGadget, FoldingSchemeOps,
    FoldingSchemePartialVerifierGadget,
};

pub enum Primary {}

pub enum Secondary {}

impl CircuitRepr for Primary {}
impl CircuitRepr for Secondary {}

/// [`GroupBasedFoldingSchemePrimaryDef`] defines a folding scheme based on
/// groups (elliptic curves), whose transcript field is the scalar field of its
/// group-based commitment scheme.
pub trait GroupBasedFoldingSchemePrimaryDef:
    FoldingSchemeDef<CM: GroupBasedCommitment, TranscriptField = SF<<Self as FoldingSchemeDef>::CM>>
    + HasGadget<Primary, Gadget: FoldingSchemeDefGadget<CM = Gadget<Self::CM, FieldFriendly>>>
{
}

/// [`GroupBasedFoldingSchemePrimary`] is a convenience trait that combines the
/// definition [`GroupBasedFoldingSchemePrimaryDef`] and operations
/// [`FoldingSchemeOps`].
pub trait GroupBasedFoldingSchemePrimary<const M: usize, const N: usize>:
    GroupBasedFoldingSchemePrimaryDef<Gadget: FoldingSchemePartialVerifierGadget<M, N>>
    + FoldingSchemeOps<M, N>
{
}

impl<FS, const M: usize, const N: usize> GroupBasedFoldingSchemePrimary<M, N> for FS where
    FS: GroupBasedFoldingSchemePrimaryDef<Gadget: FoldingSchemePartialVerifierGadget<M, N>>
{
}

/// [`GroupBasedFoldingSchemeSecondaryDef`] defines a folding scheme based on
/// groups (elliptic curves), whose transcript field is the base field of its
/// group-based commitment scheme.
pub trait GroupBasedFoldingSchemeSecondaryDef:
    FoldingSchemeDef<CM: GroupBasedCommitment, TranscriptField = BF<<Self as FoldingSchemeDef>::CM>>
    + HasGadget<Secondary, Gadget: FoldingSchemeDefGadget<CM = Gadget<Self::CM, GroupFriendly>>>
{
}

/// [`GroupBasedFoldingSchemeSecondary`] is a convenience trait that combines
/// the definition [`GroupBasedFoldingSchemeSecondaryDef`] and operations
/// [`FoldingSchemeOps`].
pub trait GroupBasedFoldingSchemeSecondary<const M: usize, const N: usize>:
    GroupBasedFoldingSchemeSecondaryDef<Gadget: FoldingSchemeFullVerifierGadget<M, N>>
    + FoldingSchemeOps<M, N>
{
}

impl<FS, const M: usize, const N: usize> GroupBasedFoldingSchemeSecondary<M, N> for FS where
    FS: GroupBasedFoldingSchemeSecondaryDef<Gadget: FoldingSchemeFullVerifierGadget<M, N>>
{
}
