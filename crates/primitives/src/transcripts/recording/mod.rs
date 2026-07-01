//! Implementation of transcripts that can automatically record generated
//! challenges, eliminating the need to pass challenges throughout protocols.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

use super::{AbsorbableVar, Transcript, TranscriptGadget};

/// [`RecordingTranscript`] wraps a regular transcript to record all challenges
/// it produces.
#[derive(Clone)]
pub struct RecordingTranscript<F: PrimeField, T: Transcript<F>> {
    inner: T,
    /// [`RecordingTranscript::cached_challenges`] contains the challenge field
    /// elements recorded so far.
    pub cached_challenges: Vec<F>,
}

impl<F: PrimeField, T: Transcript<F>> Transcript<F> for RecordingTranscript<F, T> {
    type Config = T;
    type Gadget = RecordingTranscriptVar<F, T::Gadget>;

    fn new(inner: Self::Config) -> Self {
        Self {
            inner,
            cached_challenges: vec![],
        }
    }

    fn add_field_elements(&mut self, input: &[F]) -> &mut Self {
        self.inner.add_field_elements(input);
        self
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let v = self.inner.get_field_elements(num_elements);
        self.cached_challenges.extend_from_slice(&v);
        v
    }
}

/// [`RecordingTranscriptVar`] is the in-circuit variable of [`RecordingTranscript`].
#[derive(Clone)]
pub struct RecordingTranscriptVar<F: PrimeField, T: TranscriptGadget<F>> {
    inner: T,
    /// [`RecordingTranscriptVar::cached_challenges`] contains the challenge
    /// field element variables recorded so far.
    pub cached_challenges: Vec<FpVar<F>>,
}

impl<F: PrimeField, T: TranscriptGadget<F>> TranscriptGadget<F> for RecordingTranscriptVar<F, T> {
    type Config = T;
    type Widget = RecordingTranscript<F, T::Widget>;

    fn new(inner: Self::Config) -> Self {
        Self {
            inner,
            cached_challenges: vec![],
        }
    }

    fn add<A: AbsorbableVar<F>>(&mut self, input: &A) -> Result<&mut Self, SynthesisError> {
        self.inner.add(input)?;
        Ok(self)
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let v = self.inner.get_field_elements(num_elements)?;
        self.cached_challenges.extend_from_slice(&v);
        Ok(v)
    }
}
