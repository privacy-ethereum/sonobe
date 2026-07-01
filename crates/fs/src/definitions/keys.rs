//! Traits and abstractions for folding scheme keys.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sonobe_primitives::arithmetizations::ArithConfig;

/// [`DeciderKey`] defines the information that a folding scheme's decider key
/// should include or provide access to.
pub trait DeciderKey: CanonicalSerialize + CanonicalDeserialize {
    /// [`DeciderKey::ProverKey`] is the type of the prover key contained in the
    /// decider key.
    type ProverKey;
    /// [`DeciderKey::VerifierKey`] is the type of the verifier key contained in
    /// the decider key.
    type VerifierKey: Clone;

    /// [`DeciderKey::to_pk`] returns the reference to the prover key.
    fn to_pk(&self) -> &Self::ProverKey;
    /// [`DeciderKey::to_vk`] returns the reference to the verifier key.
    fn to_vk(&self) -> &Self::VerifierKey;
    /// [`DeciderKey::to_arith_config`] returns the constraint system
    /// configuration.
    fn to_arith_config(&self) -> ArithConfig;
}
