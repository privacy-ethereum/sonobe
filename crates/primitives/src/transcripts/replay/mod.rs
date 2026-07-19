//! Implementation of transcripts that always produces designated challenge
//! values.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

use super::{
    AbsorbableVar, Transcript, TranscriptVar,
    recording::{RecordingTranscript, RecordingTranscriptVar},
};
use crate::{
    circuits::linkage::{CF, Canonical, HasConstraintField, HasValue, HasVar},
    transcripts::{TranscriptTypes, TranscriptVarTypes},
};

/// [`ReplayTranscript`] is a convenience struct that generates specific values
/// as challenges without running the actual hash function.
///
/// WARNING: This struct itself is insecure. The caller is responsible for
/// checking the validity of the designated challenge values.
#[derive(Clone)]
pub struct ReplayTranscript<F> {
    cached_challenges: Vec<F>,
}

impl<T: Transcript> From<RecordingTranscript<T>> for ReplayTranscript<T::Field> {
    fn from(value: RecordingTranscript<T>) -> Self {
        Self::new(value.cached_challenges)
    }
}

impl<F: PrimeField> HasVar<Canonical> for ReplayTranscript<F> {
    type Var = ReplayTranscriptVar<F>;
}

impl<F: PrimeField> TranscriptTypes for ReplayTranscript<F> {
    type Field = F;
    type Config = Vec<F>;
}

impl<F: PrimeField> Transcript for ReplayTranscript<F> {
    fn new(mut cached_challenges: Self::Config) -> Self {
        cached_challenges.reverse();
        Self { cached_challenges }
    }

    fn add_field_elements(&mut self, _: &[F]) -> &mut Self {
        self
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let mut result = vec![];
        for _ in 0..num_elements {
            result.push(self.cached_challenges.pop().unwrap())
        }
        result
    }
}

/// [`ReplayTranscriptVar`] is the in-circuit variable of [`ReplayTranscript`].
#[derive(Clone)]
pub struct ReplayTranscriptVar<F: PrimeField> {
    cached_challenges: Vec<FpVar<F>>,
}

impl<T: TranscriptVar> From<RecordingTranscriptVar<T>> for ReplayTranscriptVar<CF<T>> {
    fn from(value: RecordingTranscriptVar<T>) -> Self {
        Self::new(value.cached_challenges)
    }
}

impl<F: PrimeField> HasConstraintField for ReplayTranscriptVar<F> {
    type ConstraintField = F;
}

impl<F: PrimeField> HasValue for ReplayTranscriptVar<F> {
    type Value = ReplayTranscript<F>;
}

impl<F: PrimeField> TranscriptVarTypes for ReplayTranscriptVar<F> {
    type Config = Vec<FpVar<F>>;
}

impl<F: PrimeField> TranscriptVar for ReplayTranscriptVar<F> {
    fn new(mut cached_challenges: Vec<FpVar<F>>) -> Self {
        cached_challenges.reverse();
        Self { cached_challenges }
    }

    fn add<A: AbsorbableVar<F> + ?Sized>(&mut self, _: &A) -> Result<&mut Self, SynthesisError> {
        Ok(self)
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut result = vec![];
        for _ in 0..num_elements {
            result.push(self.cached_challenges.pop().unwrap())
        }
        Ok(result)
    }
}
