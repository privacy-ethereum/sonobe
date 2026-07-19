//! Implementation of transcripts that can automatically record generated
//! challenges, eliminating the need to pass challenges throughout protocols.

use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

use super::{AbsorbableVar, Transcript, TranscriptVar};
use crate::{
    circuits::linkage::{CF, Canonical, HasConstraintField, HasValue, HasVar},
    transcripts::{TranscriptTypes, TranscriptVarTypes},
};

/// [`RecordingTranscript`] wraps a regular transcript to record all challenges
/// it produces.
#[derive(Clone)]
pub struct RecordingTranscript<T: TranscriptTypes> {
    inner: T,
    pub(super) cached_challenges: Vec<T::Field>,
}

impl<T: Transcript> HasVar<Canonical> for RecordingTranscript<T> {
    type Var = RecordingTranscriptVar<T::Var>;
}

impl<T: TranscriptTypes> TranscriptTypes for RecordingTranscript<T> {
    type Field = T::Field;
    type Config = T;
}

impl<T: Transcript> Transcript for RecordingTranscript<T> {
    fn new(inner: Self::Config) -> Self {
        Self {
            inner,
            cached_challenges: vec![],
        }
    }

    fn add_field_elements(&mut self, input: &[T::Field]) -> &mut Self {
        self.inner.add_field_elements(input);
        self
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<T::Field> {
        let v = self.inner.get_field_elements(num_elements);
        self.cached_challenges.extend_from_slice(&v);
        v
    }
}

/// [`RecordingTranscriptVar`] is the in-circuit variable of [`RecordingTranscript`].
#[derive(Clone)]
pub struct RecordingTranscriptVar<T: TranscriptVar> {
    inner: T,
    pub(super) cached_challenges: Vec<FpVar<CF<T>>>,
}

impl<T: TranscriptVar> HasConstraintField for RecordingTranscriptVar<T> {
    type ConstraintField = CF<T>;
}

impl<T: TranscriptVar> HasValue for RecordingTranscriptVar<T> {
    type Value = RecordingTranscript<T::Value>;
}

impl<T: TranscriptVar> TranscriptVarTypes for RecordingTranscriptVar<T> {
    type Config = T;
}

impl<T: TranscriptVar> TranscriptVar for RecordingTranscriptVar<T> {
    fn new(inner: Self::Config) -> Self {
        Self {
            inner,
            cached_challenges: vec![],
        }
    }

    fn add<A: AbsorbableVar<CF<T>>>(&mut self, input: &A) -> Result<&mut Self, SynthesisError> {
        self.inner.add(input)?;
        Ok(self)
    }

    fn get_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<CF<T>>>, SynthesisError> {
        let v = self.inner.get_field_elements(num_elements)?;
        self.cached_challenges.extend_from_slice(&v);
        Ok(v)
    }
}
