//! Implementation of transcripts that always produces designated challenge
//! values.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

use super::{AbsorbableVar, Transcript, TranscriptGadget};
use crate::transcripts::{Absorbable, recording::{RecordingTranscript, RecordingTranscriptVar}};

/// [`ReplayTranscript`] is a convenience struct that generates specific values
/// as challenges without running the actual hash function.
///
/// WARNING: This struct itself is insecure. The caller is responsible for
/// checking the validity of the designated challenge values.
#[derive(Clone)]
pub struct ReplayTranscript<F> {
    cached_challenges: Vec<F>,
}

impl<F: PrimeField + Absorbable, T: Transcript<F>> From<RecordingTranscript<F, T>> for ReplayTranscript<F> {
    fn from(value: RecordingTranscript<F, T>) -> Self {
        Self {
            cached_challenges: value.cached_challenges,
        }
    }
}

impl<F: PrimeField + Absorbable> Transcript<F> for ReplayTranscript<F> {
    type Config = Vec<F>;
    type Gadget = ReplayTranscriptVar<F>;

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

impl<F: PrimeField + Absorbable, T: TranscriptGadget<F>> From<RecordingTranscriptVar<F, T>>
    for ReplayTranscriptVar<F>
{
    fn from(value: RecordingTranscriptVar<F, T>) -> Self {
        Self {
            cached_challenges: value.cached_challenges,
        }
    }
}

impl<F: PrimeField + Absorbable> TranscriptGadget<F> for ReplayTranscriptVar<F> {
    type Config = Vec<FpVar<F>>;
    type Widget = ReplayTranscript<F>;

    fn new(mut cached_challenges: Vec<FpVar<F>>) -> Self
    where
        Self: Sized,
    {
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
