use ark_ff::Field;
use ark_std::{borrow::Borrow, rand::RngCore};

pub mod legogroth16;

pub trait CPSNARK {
    type Field: Field;

    type Relation;

    type CommitmentKey;
    type CommitmentOpening;
    type Commitment;

    type ProverKey;
    type VerifierKey;

    type Proof;

    type Error;

    fn generate_keys(
        relation: Self::Relation,
        commitment_key: &[impl Borrow<Self::CommitmentKey> + Sync],
        rng: impl RngCore,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), Self::Error>;

    fn prove(
        pk: &Self::ProverKey,
        x: &[Self::Field],
        w: &[Self::Field],
        o: &[Self::CommitmentOpening],
        rng: impl RngCore,
    ) -> Result<Self::Proof, Self::Error>;

    fn verify(
        vk: &Self::VerifierKey,
        x: &[Self::Field],
        c: &[Self::Commitment],
        proof: &Self::Proof,
    ) -> Result<(), Self::Error>;
}
