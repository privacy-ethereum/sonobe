use ark_std::{error::Error, rand::RngCore};

use crate::traits::Dummy;

pub trait Relation<W, U> {
    type Error: Error;

    /// Checks if witness `w` and instance `u` satisfy the relation `self`
    fn check_relation(&self, w: &W, u: &U) -> Result<(), Self::Error>;
}

pub trait WitnessInstanceExtractor<W, U> {
    type Source;
    type Error: Error + 'static;

    fn extract(&self, source: Self::Source) -> Result<(W, U), Self::Error>;
}

pub trait WitnessInstanceInitializer<W, U> {
    fn dummy_witness_instance<'a>(&'a self) -> (W, U)
    where
        W: Dummy<&'a Self>,
        U: Dummy<&'a Self>,
    {
        (W::dummy(self), U::dummy(self))
    }
}

/// `WitnessInstanceSampler` allows sampling a random witness-instance pair that
/// satisfies the relation `self`.
pub trait WitnessInstanceSampler<W, U> {
    type Source;
    type Error: Error + 'static;

    fn sample(&self, source: Self::Source, rng: impl RngCore) -> Result<(W, U), Self::Error>;
}
