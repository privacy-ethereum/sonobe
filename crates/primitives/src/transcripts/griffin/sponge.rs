//! Implementation of transcript traits for Griffin sponge.

use ark_crypto_primitives::sponge::DuplexSpongeMode;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::gr1cs::SynthesisError;
use ark_std::sync::Arc;

use super::{Griffin, GriffinGadget, GriffinParams};
use crate::{
    circuits::linkage::{Canonical, HasConstraintField, HasValue, HasVar},
    transcripts::{AbsorbableVar, Transcript, TranscriptTypes, TranscriptVar, TranscriptVarTypes},
};

/// [`GriffinSponge`] is a duplex sponge built on the Griffin permutation.
///
/// The implementation mirrors arkworks' [`ark_crypto_primitives::sponge::poseidon::PoseidonSponge`].
#[derive(Clone)]
pub struct GriffinSponge<F: PrimeField> {
    params: Arc<GriffinParams<F>>,
    state: Vec<F>,
    mode: DuplexSpongeMode,
}

impl<F: PrimeField> GriffinSponge<F> {
    fn permute(&mut self) {
        Griffin::permute(&self.params, &mut self.state);
    }

    // Absorbs everything in elements, this does not end in an absorption.
    fn absorb_internal(&mut self, mut rate_start_index: usize, elements: &[F]) {
        let mut remaining_elements = elements;

        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.params.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.params.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return;
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.params.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.params.capacity + i + rate_start_index] += element;
            }
            self.permute();
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(&mut self, mut rate_start_index: usize, output: &mut [F]) {
        let mut output_remaining = output;
        loop {
            // if we can finish in this call
            if rate_start_index + output_remaining.len() <= self.params.rate {
                output_remaining.clone_from_slice(
                    &self.state[self.params.capacity + rate_start_index
                        ..(self.params.capacity + output_remaining.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + output_remaining.len(),
                };
                return;
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.params.rate - rate_start_index;
            output_remaining[..num_elements_squeezed].clone_from_slice(
                &self.state[self.params.capacity + rate_start_index
                    ..(self.params.capacity + num_elements_squeezed + rate_start_index)],
            );

            // Repeat with updated output slices
            output_remaining = &mut output_remaining[num_elements_squeezed..];
            // Unless we are done with squeezing in this call, permute.
            if !output_remaining.is_empty() {
                self.permute();
            }

            rate_start_index = 0;
        }
    }
}

/// [`GriffinSpongeVar`] is the in-circuit variable of [`GriffinSponge`].
///
/// The implementation mirrors arkworks' [`ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar`].
#[derive(Clone)]
pub struct GriffinSpongeVar<F: PrimeField> {
    params: Arc<GriffinParams<F>>,
    state: Vec<FpVar<F>>,
    mode: DuplexSpongeMode,
}

impl<F: PrimeField> GriffinSpongeVar<F> {
    fn permute(&mut self) -> Result<(), SynthesisError> {
        self.state = GriffinGadget::permute(&self.params, &self.state)?;
        Ok(())
    }

    fn absorb_internal(
        &mut self,
        mut rate_start_index: usize,
        elements: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        let mut remaining_elements = elements;
        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.params.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.params.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return Ok(());
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.params.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.params.capacity + i + rate_start_index] += element;
            }
            self.permute()?;
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(
        &mut self,
        mut rate_start_index: usize,
        output: &mut [FpVar<F>],
    ) -> Result<(), SynthesisError> {
        let mut remaining_output = output;
        loop {
            // if we can finish in this call
            if rate_start_index + remaining_output.len() <= self.params.rate {
                remaining_output.clone_from_slice(
                    &self.state[self.params.capacity + rate_start_index
                        ..(self.params.capacity + remaining_output.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + remaining_output.len(),
                };
                return Ok(());
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.params.rate - rate_start_index;
            remaining_output[..num_elements_squeezed].clone_from_slice(
                &self.state[self.params.capacity + rate_start_index
                    ..(self.params.capacity + num_elements_squeezed + rate_start_index)],
            );

            // Repeat with updated output slices and rate start index
            remaining_output = &mut remaining_output[num_elements_squeezed..];

            // Unless we are done with squeezing in this call, permute.
            if !remaining_output.is_empty() {
                self.permute()?;
            }
            rate_start_index = 0;
        }
    }
}

impl<F: PrimeField> HasVar<Canonical> for GriffinSponge<F> {
    type Var = GriffinSpongeVar<F>;
}

impl<F: PrimeField> TranscriptTypes for GriffinSponge<F> {
    type Field = F;
    type Config = Arc<GriffinParams<F>>;
}

impl<F: PrimeField> Transcript for GriffinSponge<F> {
    fn new(parameters: Arc<GriffinParams<F>>) -> Self {
        let state = vec![F::zero(); parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            params: parameters.clone(),
            state,
            mode,
        }
    }

    fn add_field_elements(&mut self, elems: &[F]) -> &mut Self {
        if elems.is_empty() {
            return self;
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.params.rate {
                    self.permute();
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, elems);
            }
            DuplexSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.absorb_internal(0, elems);
            }
        };
        self
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let mut squeezed_elems = vec![F::zero(); num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute();
                self.squeeze_internal(0, &mut squeezed_elems);
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.params.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };

        squeezed_elems
    }
}

impl<F: PrimeField> HasConstraintField for GriffinSpongeVar<F> {
    type ConstraintField = F;
}

impl<F: PrimeField> HasValue for GriffinSpongeVar<F> {
    type Value = GriffinSponge<F>;
}

impl<F: PrimeField> TranscriptVarTypes for GriffinSpongeVar<F> {
    type Config = Arc<GriffinParams<F>>;
}

impl<F: PrimeField> TranscriptVar for GriffinSpongeVar<F> {
    fn new(parameters: Arc<GriffinParams<F>>) -> Self
    where
        Self: Sized,
    {
        let zero = FpVar::<F>::zero();
        let state = vec![zero; parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            params: parameters.clone(),
            state,
            mode,
        }
    }

    fn add<A: AbsorbableVar<F>>(&mut self, input: &A) -> Result<&mut Self, SynthesisError> {
        let input = {
            let mut result = Vec::new();
            input.absorb_into(&mut result)?;
            result
        };

        if input.is_empty() {
            return Ok(self);
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.params.rate {
                    self.permute()?;
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, input.as_slice())?;
            }
            DuplexSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.absorb_internal(0, input.as_slice())?;
            }
        };

        Ok(self)
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let zero = FpVar::zero();
        let mut squeezed_elems = vec![zero; num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute()?;
                self.squeeze_internal(0, &mut squeezed_elems)?;
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.params.rate {
                    self.permute()?;
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems)?;
            }
        };

        Ok(squeezed_elems)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Projective as G1, g1::Config};
    use ark_ff::UniformRand;
    use ark_r1cs_std::{
        GR1CSVar, alloc::AllocVar, fields::fp::FpVar,
        groups::curves::short_weierstrass::ProjectiveVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, rand::thread_rng};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::algebra::group::emulated::EmulatedAffineVar;

    #[test]
    fn test_challenge_field_element() -> Result<(), Box<dyn Error>> {
        // Create a transcript outside of the circuit
        let config = Arc::new(GriffinParams::<Fr>::new(3, 5, 12));
        let mut tr = GriffinSponge::<Fr>::new(config.clone());
        tr.add(&Fr::from(42_u32));
        let c = tr.challenge_field_element();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = GriffinSpongeVar::<Fr>::new(config);
        let v = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(42_u32)))?;
        tr_var.add(&v)?;
        let c_var = tr_var.challenge_field_element()?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_challenge_bits() -> Result<(), Box<dyn Error>> {
        let nbits = 128;

        // Create a transcript outside of the circuit
        let config = Arc::new(GriffinParams::<Fq>::new(3, 5, 12));
        let mut tr = GriffinSponge::<Fq>::new(config.clone());
        tr.add(&Fq::from(42_u32));
        let c = tr.challenge_bits(nbits);

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = GriffinSpongeVar::<Fq>::new(config);
        let v = FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(42_u32)))?;
        tr_var.add(&v)?;
        let c_var = tr_var.challenge_bits(nbits)?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_absorb_canonical_point() -> Result<(), Box<dyn Error>> {
        // Create a transcript outside of the circuit
        let config = Arc::new(GriffinParams::<Fq>::new(3, 5, 12));
        let mut tr = GriffinSponge::<Fq>::new(config.clone());
        let rng = &mut thread_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge_field_element();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = GriffinSpongeVar::<Fq>::new(config);
        let p_var = ProjectiveVar::<Config, FpVar<Fq>>::new_witness(cs, || Ok(p))?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_absorb_emulated_point() -> Result<(), Box<dyn Error>> {
        // Create a transcript outside of the circuit
        let config = Arc::new(GriffinParams::<Fr>::new(3, 5, 12));
        let mut tr = GriffinSponge::<Fr>::new(config.clone());
        let rng = &mut thread_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge_field_element();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = GriffinSpongeVar::<Fr>::new(config);
        let p_var = EmulatedAffineVar::new_witness(cs, || Ok(p))?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }
}
