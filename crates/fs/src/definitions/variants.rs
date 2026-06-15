//! Traits that define variants of folding schemes based on different underlying
//! mathematical structures.

use sonobe_primitives::{
    arithmetizations::Arith,
    commitments::{CommitmentDef, GroupBasedCommitment},
    traits::CF2,
};

use crate::{
    FoldingInstance, FoldingSchemeDef, FoldingSchemeDefGadget, FoldingSchemeFullVerifierGadget,
    FoldingSchemeOps, FoldingSchemePartialVerifierGadget, definitions::instances::FoldingIncomingInstance,
};

/// [`GroupBasedFoldingSchemePrimaryDef`] defines a folding scheme based on
/// groups (elliptic curves), whose transcript field is the scalar field of its
/// group-based commitment scheme.
pub trait GroupBasedFoldingSchemePrimaryDef:
    FoldingSchemeDef<
        CM: GroupBasedCommitment,
        Arith: Arith<Field = <<Self as FoldingSchemeDef>::CM as CommitmentDef>::Scalar>,
        TranscriptField = <<Self as FoldingSchemeDef>::CM as CommitmentDef>::Scalar,
        IU: FoldingIncomingInstance<
            <Self as FoldingSchemeDef>::CM,
            PublicInput = <<Self as FoldingSchemeDef>::CM as CommitmentDef>::Scalar,
        >,
    >
{
    /// [`GroupBasedFoldingSchemePrimaryDef::Gadget`] is the in-circuit gadget
    /// that defines the folding scheme.
    type Gadget: FoldingSchemeDefGadget<Widget = Self, CM = <Self::CM as GroupBasedCommitment>::Gadget2>;
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
    FoldingSchemeDef<
        CM: GroupBasedCommitment,
        Arith: Arith<Field = <<Self as FoldingSchemeDef>::CM as CommitmentDef>::Scalar>,
        TranscriptField = CF2<<<Self as FoldingSchemeDef>::CM as CommitmentDef>::Commitment>,
    >
{
    /// [`GroupBasedFoldingSchemeSecondaryDef::Gadget`] is the in-circuit gadget
    /// that defines the folding scheme.
    type Gadget: FoldingSchemeDefGadget<Widget = Self, CM = <Self::CM as GroupBasedCommitment>::Gadget1>;
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
