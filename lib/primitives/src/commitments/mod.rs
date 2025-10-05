use ark_r1cs_std::alloc::AllocVar;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::Debug;
use ark_std::rand::RngCore;
use thiserror::Error;

use sonobe_traits::Curve;

pub mod pedersen;
// TODO: add back other commitment schemes

#[derive(Debug, Error)]
pub enum Error {
    // Commitment errors
    #[error("The message being committed to has length {1}, which exceeds the maximum supported length of {0}")]
    MessageTooLong(usize, usize),
    #[error("Blinding factor not 0 for Commitment without hiding")]
    BlindingNotZero,
    #[error("Blinding factors incorrect, blinding is set to {0} but blinding values are {1}")]
    IncorrectBlinding(bool, String),
    #[error("Commitment verification failed")]
    CommitmentVerificationFail,
}

pub trait VectorCommitment {
    const IS_HIDING: bool;

    type Key;
    type Scalar;
    type Commitment;
    type Randomness;

    fn generate_key(rng: &mut impl RngCore, len: usize) -> Result<Self::Key, Error>;

    fn commit(
        ck: &Self::Key,
        v: &[Self::Scalar],
        rng: &mut impl RngCore,
    ) -> Result<(Self::Commitment, Self::Randomness), Error>;

    fn open(
        ck: &Self::Key,
        v: &[Self::Scalar],
        r: &Self::Randomness,
        cm: &Self::Commitment,
    ) -> Result<bool, Error>;
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use ark_std::error::Error;

    use super::*;

    pub fn test_commitment_opt<VC: VectorCommitment<Scalar: UniformRand>>(
        rng: &mut impl RngCore,
        len: usize,
    ) -> Result<(), Box<dyn Error>> {
        let v = (0..len).map(|_| VC::Scalar::rand(rng)).collect::<Vec<_>>();

        let ck = VC::generate_key(rng, len)?;
        let (cm, r) = VC::commit(&ck, &v, rng)?;
        assert!(VC::open(&ck, &v, &r, &cm)?);
        Ok(())
    }
}
