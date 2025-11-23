use ark_crypto_primitives::sponge::DuplexSpongeMode;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldVar},
    prelude::{Boolean, ToBitsGadget},
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::sync::Arc;

use crate::transcripts::{griffin::GriffinParams, AbsorbableGadget, Transcript, TranscriptVar};

#[derive(Clone)]
pub struct GriffinSponge<F: PrimeField> {
    /// Sponge Config
    pub griffin: Arc<GriffinParams<F>>,

    // Sponge State
    /// Current sponge's state (current elements in the permutation block)
    pub state: Vec<F>,
    /// Current mode (whether its absorbing or squeezing)
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> GriffinSponge<F> {
    fn permute(&mut self) {
        self.griffin.permute(&mut self.state);
    }

    // Absorbs everything in elements, this does not end in an absorbtion.
    fn absorb_internal(&mut self, mut rate_start_index: usize, elements: &[F]) {
        let mut remaining_elements = elements;

        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.griffin.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.griffin.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return;
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.griffin.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.griffin.capacity + i + rate_start_index] += element;
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
            if rate_start_index + output_remaining.len() <= self.griffin.rate {
                output_remaining.clone_from_slice(
                    &self.state[self.griffin.capacity + rate_start_index
                        ..(self.griffin.capacity + output_remaining.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + output_remaining.len(),
                };
                return;
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.griffin.rate - rate_start_index;
            output_remaining[..num_elements_squeezed].clone_from_slice(
                &self.state[self.griffin.capacity + rate_start_index
                    ..(self.griffin.capacity + num_elements_squeezed + rate_start_index)],
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

#[derive(Clone)]
pub struct GriffinSpongeVar<F: PrimeField> {
    /// Sponge Parameters
    pub griffin: Arc<GriffinParams<F>>,

    // Sponge State
    /// The sponge's state
    pub state: Vec<FpVar<F>>,
    /// The mode
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> GriffinSpongeVar<F> {
    fn permute(&mut self) -> Result<(), SynthesisError> {
        self.state = self.griffin.permute_gadget(&self.state)?;
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
            if rate_start_index + remaining_elements.len() <= self.griffin.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.griffin.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return Ok(());
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.griffin.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.griffin.capacity + i + rate_start_index] += element;
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
            if rate_start_index + remaining_output.len() <= self.griffin.rate {
                remaining_output.clone_from_slice(
                    &self.state[self.griffin.capacity + rate_start_index
                        ..(self.griffin.capacity + remaining_output.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + remaining_output.len(),
                };
                return Ok(());
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.griffin.rate - rate_start_index;
            remaining_output[..num_elements_squeezed].clone_from_slice(
                &self.state[self.griffin.capacity + rate_start_index
                    ..(self.griffin.capacity + num_elements_squeezed + rate_start_index)],
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

impl<F: PrimeField> Transcript<F> for GriffinSponge<F> {
    type Config = Arc<GriffinParams<F>>;
    type Var = GriffinSpongeVar<F>;

    fn new(parameters: &Arc<GriffinParams<F>>) -> Self {
        let state = vec![F::zero(); parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            griffin: parameters.clone(),
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
                if absorb_index == self.griffin.rate {
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

    fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let usable_bits = (F::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = num_bits.div_ceil(usable_bits);
        let src_elements = self.get_field_elements(num_elements);

        let mut bits: Vec<bool> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            let elem_bits = elem.into_bigint().to_bits_le();
            bits.extend_from_slice(&elem_bits[..usable_bits]);
        }

        bits.truncate(num_bits);
        bits
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
                if squeeze_index == self.griffin.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };

        squeezed_elems
    }
}

impl<F: PrimeField> TranscriptVar<F> for GriffinSpongeVar<F> {
    type Native = GriffinSponge<F>;

    fn new(parameters: &Arc<GriffinParams<F>>) -> Self
    where
        Self: Sized,
    {
        let zero = FpVar::<F>::zero();
        let state = vec![zero; parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            griffin: parameters.clone(),
            state,
            mode,
        }
    }

    fn add<A: AbsorbableGadget<F> + ?Sized>(
        &mut self,
        input: &A,
    ) -> Result<&mut Self, SynthesisError> {
        let input = input.to_absorbable()?;
        if input.is_empty() {
            return Ok(self);
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.griffin.rate {
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

    fn get_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let usable_bits = (F::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = num_bits.div_ceil(usable_bits);
        let src_elements = self.get_field_elements(num_elements)?;

        let mut bits: Vec<Boolean<F>> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            bits.extend_from_slice(&elem.to_bits_le()?[..usable_bits]);
        }

        bits.truncate(num_bits);
        Ok(bits)
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
                if squeeze_index == self.griffin.rate {
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
pub mod tests {
    use ark_bn254::{constraints::GVar, g1::Config, Fq, Fr, G1Projective as G1};
    use ark_ec::PrimeGroup;
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::fp::FpVar,
        groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
        GR1CSVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, test_rng};

    use super::*;
    use crate::algebra::{group::emulated::EmulatedAffineVar, ops::bits::FromBits};

    #[test]
    fn test_transcript_and_transcriptvar_absorb_native_point() -> Result<(), Box<dyn Error>> {
        // use 'native' transcript
        let config = Arc::new(GriffinParams::<Fq>::new(3, 5, 12));
        let mut tr = GriffinSponge::<Fq>::new(&config);
        let rng = &mut test_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge_field_element();

        // use 'gadget' transcript
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = GriffinSpongeVar::<Fq>::new(&config);
        let p_var = ProjectiveVar::<Config, FpVar<Fq>>::new_witness(cs, || Ok(p))?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // assert that native & gadget transcripts return the same challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_transcript_and_transcriptvar_absorb_nonnative_point() -> Result<(), Box<dyn Error>> {
        // use 'native' transcript
        let config = Arc::new(GriffinParams::<Fr>::new(3, 5, 12));
        let mut tr = GriffinSponge::<Fr>::new(&config);
        let rng = &mut test_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge_field_element();

        // use 'gadget' transcript
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = GriffinSpongeVar::<Fr>::new(&config);
        let p_var = EmulatedAffineVar::new_witness(cs, || Ok(p))?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // assert that native & gadget transcripts return the same challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_transcript_and_transcriptvar_get_challenge() -> Result<(), Box<dyn Error>> {
        // use 'native' transcript
        let config = Arc::new(GriffinParams::<Fr>::new(3, 5, 12));
        let mut tr = GriffinSponge::<Fr>::new(&config);
        tr.add(&Fr::from(42_u32));
        let c = tr.challenge_field_element();

        // use 'gadget' transcript
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = GriffinSpongeVar::<Fr>::new(&config);
        let v = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(42_u32)))?;
        tr_var.add(&v)?;
        let c_var = tr_var.challenge_field_element()?;

        // assert that native & gadget transcripts return the same challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_transcript_and_transcriptvar_nbits() -> Result<(), Box<dyn Error>> {
        let nbits = 128;

        // use 'native' transcript
        let config = Arc::new(GriffinParams::<Fq>::new(3, 5, 12));
        let mut tr = GriffinSponge::<Fq>::new(&config);
        tr.add(&Fq::from(42_u32));

        // get challenge from native transcript
        let c_bits = tr.challenge_bits(nbits);

        // use 'gadget' transcript
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = GriffinSpongeVar::<Fq>::new(&config);
        let v = FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(42_u32)))?;
        tr_var.add(&v)?;

        // get challenge from circuit transcript
        let c_var = tr_var.challenge_bits(nbits)?;

        let p = G1::generator();
        let p_var = GVar::new_witness(cs.clone(), || Ok(p))?;

        // multiply point P by the challenge in different formats, to ensure that we get the same
        // result natively and in-circuit
        let c = Fr::from_bits_le(&c_bits);

        // check that native c*P and in-circuit c*P using scalar_mul_le are equal
        assert_eq!(p * c, p_var.scalar_mul_le(c_var.iter())?.value()?);
        // check that native c*P using mul_bits_be and in-circuit c*P using scalar_mul_le are equal
        // (notice the .rev to convert the LE to BE)
        assert_eq!(
            p.mul_bits_be(c_bits.into_iter().rev()),
            p_var.scalar_mul_le(c_var.iter())?.value()?
        );
        Ok(())
    }
}
