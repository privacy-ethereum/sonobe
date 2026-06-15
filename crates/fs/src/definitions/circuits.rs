//! Traits that define in-circuit gadgets for folding scheme algorithms, mainly
//! for proof verification.

use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    commitments::CommitmentDefGadget, relations::RelationGadget, transcripts::TranscriptGadget,
};

use super::{FoldingSchemeDefGadget, algorithms::FoldingSchemeOps};

/// [`FoldingSchemePartialVerifierGadget`] is the partial in-circuit verifier.
///
/// For schemes that have circuit-unfriendly parts in their verification, the
/// implementation can choose to only implement this partial verifier gadget and
/// use some other techniques for the remaining verification work.
/// For example, group-based folding schemes can defer the expensive elliptic
/// curve operations on commitments to an external CycleFold circuit.
pub trait FoldingSchemePartialVerifierGadget<const M: usize, const N: usize>:
    FoldingSchemeDefGadget<Widget: FoldingSchemeOps<M, N>>
{
    /// [`FoldingSchemePartialVerifierGadget::verify_hinted`] defines the proof
    /// verification gadget that matches its out-of-circuit widget
    /// [`crate::FoldingSchemeVerifier::verify`].
    ///
    /// The implementation is allowed to create hints for the missing parts of
    /// the verification that are not performed inside the constraint system,
    /// and it is unnecessary to constrain these hints inside the circuit.
    /// However, it is the caller's responsibility to ensure that these hints
    /// are later verified using other techniques (e.g., CycleFold helper).
    #[allow(non_snake_case)]
    fn verify_hinted(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<<Self::CM as CommitmentDefGadget>::ConstraintField>,
        Us: [&Self::RU; M],
        us: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, SynthesisError>;
}

/// [`FoldingSchemeFullVerifierGadget`] is the full in-circuit verifier.
///
/// Extends [`FoldingSchemePartialVerifierGadget`] by performing everything
/// required for proof verification inside the constraint system.
pub trait FoldingSchemeFullVerifierGadget<const M: usize, const N: usize>:
    FoldingSchemePartialVerifierGadget<M, N>
{
    /// [`FoldingSchemeFullVerifierGadget::verify`] defines the proof
    /// verification gadget that matches its out-of-circuit widget
    /// [`crate::FoldingSchemeVerifier::verify`].
    ///
    /// Unlike [`FoldingSchemePartialVerifierGadget::verify_hinted`], the
    /// implementation is expected to perform all necessary verification steps
    /// and constrain all required variables inside the circuit.
    #[allow(non_snake_case)]
    fn verify(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<<Self::CM as CommitmentDefGadget>::ConstraintField>,
        Us: [&Self::RU; M],
        us: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, SynthesisError>;
}

pub trait FoldingSchemeDeciderGadget:
    FoldingSchemeDefGadget<
    DeciderKey: RelationGadget<Self::RW, Self::RU> + RelationGadget<Self::IW, Self::IU>,
>
{
    #[allow(non_snake_case)]
    fn decide_running(
        dk: &Self::DeciderKey,
        W: &Self::RW,
        U: &Self::RU,
    ) -> Result<(), SynthesisError> {
        RelationGadget::<Self::RW, Self::RU>::check_relation(dk, W, U)
    }

    fn decide_incoming(
        dk: &Self::DeciderKey,
        w: &Self::IW,
        u: &Self::IU,
    ) -> Result<(), SynthesisError> {
        RelationGadget::<Self::IW, Self::IU>::check_relation(dk, w, u)
    }
}

impl<
    FS: FoldingSchemeDefGadget<
        DeciderKey: RelationGadget<Self::RW, Self::RU> + RelationGadget<Self::IW, Self::IU>,
    >,
> FoldingSchemeDeciderGadget for FS
{
}
