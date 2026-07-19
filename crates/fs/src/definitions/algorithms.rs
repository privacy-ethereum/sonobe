//! Traits that define out-of-circuit widgets for folding scheme algorithms
//! (preprocessing, key generation, proof generation, proof verification, and
//! deciding).

use ark_std::{borrow::Borrow, rand::RngCore};
use sonobe_primitives::{relations::Relation, transcripts::Transcript};

use super::{FoldingSchemeDef, errors::Error, keys::DeciderKey};

/// [`FoldingSchemePreprocessor`] is the trait for folding scheme preprocessor.
pub trait FoldingSchemePreprocessor: FoldingSchemeDef {
    /// [`FoldingSchemePreprocessor::preprocess`] defines the preprocessing
    /// algorithm, which is a randomized algorithm that takes as input the
    /// config / parameterization `config` of the folding scheme (e.g., size
    /// bounds of the folding scheme) and outputs the public parameters.
    ///
    /// Here, the randomness source is controlled by `rng`.
    ///
    /// The security parameter is implicitly specified by the size of underlying
    /// fields and groups.
    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;
}

/// [`FoldingSchemeKeyGenerator`] is the trait for folding scheme key generator.
pub trait FoldingSchemeKeyGenerator: FoldingSchemeDef {
    /// [`FoldingSchemeKeyGenerator::generate_keys`] defines the key generation
    /// algorithm, which is a deterministic algorithm that takes as input the
    /// public parameters `pp` and the arithmetization `arith`, and outputs a
    /// prover key and a verifier key.
    fn generate_keys(pp: Self::PublicParam, arith: Self::Arith) -> Result<Self::DeciderKey, Error>;
}

/// [`FoldingSchemeProver`] is the trait for folding scheme prover.
pub trait FoldingSchemeProver<const M: usize, const N: usize>: FoldingSchemeDef {
    /// [`FoldingSchemeProver::prove`] defines the proof generation algorithm,
    /// which is a (probably) randomized algorithm that takes as input the
    /// prover key `pk`, the transcript `transcript` between the prover and the
    /// verifier, `M` running witnesses `Ws`, `M` running instances `Us`, `N`
    /// incoming witnesses `ws`, and `N` incoming instances `us`, and outputs
    /// the folded witness and instance, the proof, and the challenges.
    ///
    /// Here, although the challenges can usually be derived by `transcript` and
    /// thus do not necessarily need to be returned for verification, we still
    /// have the prover return them explicitly so that they can be used for the
    /// construction of CycleFold circuits in our CycleFold-based folding-to-IVC
    /// compiler without re-deriving them from the transcript.
    ///
    /// The prover may further use `rng` as the randomness source, e.g., for
    /// the hiding/zero-knowledge property.
    #[allow(non_snake_case, clippy::type_complexity)]
    fn prove(
        pk: &<Self::DeciderKey as DeciderKey>::ProverKey,
        transcript: &mut impl Transcript<Field = Self::TranscriptField>,
        Ws: &[impl Borrow<Self::RW>; M],
        Us: &[impl Borrow<Self::RU>; M],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<M, N>), Error>;
}

/// [`FoldingSchemeVerifier`] is the trait for folding scheme verifier.
pub trait FoldingSchemeVerifier<const M: usize, const N: usize>: FoldingSchemeDef {
    /// [`FoldingSchemeVerifier::verify`] defines the proof verification
    /// algorithm, which is a deterministic algorithm that takes as input the
    /// verifier key `vk`, the transcript `transcript` between the prover and
    /// the verifier, `M` running instances `Us`, `N` incoming instances `us`,
    /// and the proof `proof`, and outputs the folded instance.
    #[allow(non_snake_case)]
    fn verify(
        vk: &<Self::DeciderKey as DeciderKey>::VerifierKey,
        transcript: &mut impl Transcript<Field = Self::TranscriptField>,
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, Error>;
}

/// [`FoldingSchemeDecider`] is the trait for folding scheme decider.
pub trait FoldingSchemeDecider: FoldingSchemeDef {
    /// [`FoldingSchemeDecider::decide_running`] defines the deciding algorithm
    /// for running witness-instance pairs, which is a deterministic algorithm
    /// that takes as input the decider key `dk`, a running witness `W` and a
    /// running instance `U`, and outputs whether the witness-instance pair
    /// satisfies the running relation.
    #[allow(non_snake_case)]
    fn decide_running(dk: &Self::DeciderKey, W: &Self::RW, U: &Self::RU) -> Result<(), Error> {
        Relation::<Self::RW, Self::RU>::check_relation(dk, W, U)
    }

    /// [`FoldingSchemeDecider::decide_running`] defines the deciding algorithm
    /// for incoming witness-instance pairs, which is a deterministic algorithm
    /// that takes as input the decider key `dk`, an incoming witness `W` and an
    /// incoming instance `U`, and outputs whether the witness-instance pair
    /// satisfies the incoming relation.
    fn decide_incoming(dk: &Self::DeciderKey, w: &Self::IW, u: &Self::IU) -> Result<(), Error> {
        Relation::<Self::IW, Self::IU>::check_relation(dk, w, u)
    }
}

impl<FS: FoldingSchemeDef> FoldingSchemeDecider for FS {}

/// [`FoldingSchemeOps`] is a convenience super-trait bundling all algorithms.
pub trait FoldingSchemeOps<const M: usize, const N: usize>:
    FoldingSchemePreprocessor
    + FoldingSchemeKeyGenerator
    + FoldingSchemeProver<M, N>
    + FoldingSchemeVerifier<M, N>
    + FoldingSchemeDecider
{
}

impl<FS, const M: usize, const N: usize> FoldingSchemeOps<M, N> for FS where
    FS: FoldingSchemePreprocessor
        + FoldingSchemeKeyGenerator
        + FoldingSchemeProver<M, N>
        + FoldingSchemeVerifier<M, N>
        + FoldingSchemeDecider
{
}
