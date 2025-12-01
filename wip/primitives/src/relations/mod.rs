use ark_std::{error::Error, rand::RngCore};

pub trait Relation<W, U> {
    type Error: Error;

    /// Checks if witness `w` and instance `u` satisfy the relation `self`
    fn check_relation(&self, w: &W, u: &U) -> Result<(), Self::Error>;
}

/// `WitnessInstanceSampler` allows sampling a random witness-instance pair that
/// satisfies the relation `self`.
pub trait WitnessInstanceSampler<W, U> {
    type Source;
    type Error: Error + 'static;

    fn sample(&self, source: Self::Source, rng: &mut impl RngCore) -> Result<(W, U), Self::Error>;
}
