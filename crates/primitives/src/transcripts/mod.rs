//! Abstractions of sponges and Fiat-Shamir transcripts.
//!
//! This module defines the traits that unify hash functions (Poseidon, Griffin,
//! etc.) behind a common absorb / squeeze interface suitable for building
//! non-interactive proofs.
//!
//! Concrete implementations live in the [`poseidon`] and [`griffin`]
//! sub-modules.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{boolean::Boolean, convert::ToBitsGadget, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

pub use self::absorbable::{Absorbable, AbsorbableVar};
use crate::circuits::linkage::{Canonical, HasValue, HasVar};

pub mod absorbable;
pub mod griffin;
pub mod poseidon;
pub mod recording;
pub mod replay;

pub trait TranscriptTypes: Clone {
    type Field: PrimeField;
    type Config: Clone;
}

/// [`Transcript`] is the out-of-circuit widget for transcripts and sponges.
///
/// Provers and verifiers can use this trait to absorb messages and squeeze
/// challenges in a way that is agnostic to the underlying hash function.
pub trait Transcript:
    TranscriptTypes + HasVar<Canonical, Var: TranscriptVar<ConstraintField = Self::Field, Value = Self>>
{
    /// [`Transcript::new`] creates a new transcript / sponge under the given
    /// configuration `config`.
    fn new(config: Self::Config) -> Self;

    /// [`Transcript::new_with_pp_hash`] is a convenience method for creating a
    /// new transcript / sponge under the given configuration `config` and
    /// additionally absorbing a hash of the public parameters `pp_hash`.
    fn new_with_pp_hash(config: Self::Config, pp_hash: Self::Field) -> Self {
        let mut sponge = Self::new(config);
        sponge.add_field_elements(&[pp_hash]);
        sponge
    }

    /// [`Transcript::add`] absorbs a message `input` that can be any type
    /// implementing the [`Absorbable`] trait into the transcript / sponge.
    fn add<A: Absorbable + ?Sized>(&mut self, input: &A) -> &mut Self {
        let mut elems = Vec::new();
        input.absorb_into(&mut elems);

        self.add_field_elements(&elems)
    }

    /// [`Transcript::add_field_elements`] absorbs a message `input` that is
    /// represented as field elements into the transcript / sponge.
    fn add_field_elements(&mut self, input: &[Self::Field]) -> &mut Self;

    /// [`Transcript::get_bits`] squeezes `num_bits` bits from the transcript /
    /// sponge.
    fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let usable_bits = (Self::Field::MODULUS_BIT_SIZE - 1) as usize;

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

    /// [`Transcript::get_field_element`] squeezes a single field element from
    /// the transcript / sponge.
    fn get_field_element(&mut self) -> Self::Field {
        self.get_field_elements(1)[0]
    }

    /// [`Transcript::get_field_elements`] squeezes `num_elements` field
    /// elements from the transcript / sponge.
    fn get_field_elements(&mut self, num_elements: usize) -> Vec<Self::Field>;

    /// [`Transcript::separate_domain`] creates a new transcript / sponge by
    /// applying domain separation using the provided `domain` byte sequence.
    fn separate_domain(&self, domain: &[u8]) -> Self {
        let mut new_sponge = self.clone();

        // Encode the domain length with a fixed-width `u64` so the derived
        // challenges are identical across targets.
        let mut input = (domain.len() as u64).to_le_bytes().to_vec();
        input.extend_from_slice(domain);

        // Chunk into `(MODULUS_BIT_SIZE - 1) / 8` bytes so a full chunk is
        // always `< 2^(MODULUS_BIT_SIZE - 1) <= MODULUS`
        let limbs = input
            .chunks((Self::Field::MODULUS_BIT_SIZE as usize - 1) / 8)
            .map(PrimeField::from_le_bytes_mod_order)
            .collect::<Vec<_>>();

        new_sponge.add_field_elements(&limbs);

        new_sponge
    }

    /// [`Transcript::challenge_field_element`] squeezes a challenge from the
    /// transcript as a field element.
    ///
    /// Internally, it first squeezes a field element and then absorbs it back
    /// into the transcript to ensure security.
    fn challenge_field_element(&mut self) -> Self::Field {
        let c = self.get_field_elements(1);
        self.add_field_elements(&c);
        c[0]
    }

    /// [`Transcript::challenge_bits`] squeezes a challenge from the transcript
    /// as a bit vector.
    ///
    /// Internally, it squeezes several field elements, absorbs them back to the
    /// transcript (for strong Fiat-Shamir), and decomposes them into bits.
    fn challenge_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let usable_bits = (Self::Field::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = num_bits.div_ceil(usable_bits);
        let src_elements = self.challenge_field_elements(num_elements);

        let mut bits = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            let elem_bits = elem.into_bigint().to_bits_le();
            bits.extend_from_slice(&elem_bits[..usable_bits]);
        }

        bits.truncate(num_bits);
        bits
    }

    /// [`Transcript::challenge_field_elements`] squeezes `n` challenges from
    /// the transcript as field elements.
    ///
    /// Internally, it first squeezes the field elements and then absorbs them
    /// back into the transcript to ensure security.
    fn challenge_field_elements(&mut self, n: usize) -> Vec<Self::Field> {
        let c = self.get_field_elements(n);
        self.add_field_elements(&c);
        c
    }
}

pub trait TranscriptVarTypes: Clone + HasValue<Value: TranscriptTypes> {
    type Config: Clone;
}

/// [`TranscriptVar`] is the in-circuit variable for transcripts and sponges.
pub trait TranscriptVar: TranscriptVarTypes {
    /// [`TranscriptVar::new`] creates a new transcript / sponge variable
    /// under the given configuration `config`.
    fn new(config: Self::Config) -> Self;

    /// [`TranscriptVar::new_with_pp_hash`] is a convenience method for
    /// creating a new transcript / sponge variable under the given
    /// configuration `config` and additionally absorbing a hash of the public
    /// parameters `pp_hash`.
    fn new_with_pp_hash(
        config: Self::Config,
        pp_hash: &FpVar<Self::ConstraintField>,
    ) -> Result<Self, SynthesisError> {
        let mut sponge = Self::new(config);
        sponge.add(&pp_hash)?;
        Ok(sponge)
    }

    /// [`TranscriptVar::add`] absorbs a message `input` that can be any type
    /// implementing the [`AbsorbableGadget`] trait into the transcript / sponge
    /// variable.
    fn add<A: AbsorbableVar<Self::ConstraintField>>(
        &mut self,
        input: &A,
    ) -> Result<&mut Self, SynthesisError>;

    /// [`TranscriptVar::get_bits`] squeezes `num_bits` bit variables from
    /// the transcript / sponge variable.
    fn get_bits(
        &mut self,
        num_bits: usize,
    ) -> Result<Vec<Boolean<Self::ConstraintField>>, SynthesisError> {
        let usable_bits = (Self::ConstraintField::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = num_bits.div_ceil(usable_bits);
        let src_elements = self.get_field_elements(num_elements)?;

        let mut bits = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            bits.extend_from_slice(&elem.to_bits_le()?[..usable_bits]);
        }

        bits.truncate(num_bits);
        Ok(bits)
    }

    /// [`TranscriptVar::get_field_element`] squeezes a single field element
    /// variable from the transcript / sponge variable.
    fn get_field_element(&mut self) -> Result<FpVar<Self::ConstraintField>, SynthesisError> {
        Ok(self.get_field_elements(1)?.swap_remove(0))
    }

    /// [`TranscriptVar::get_field_elements`] squeezes `num_elements` field
    /// element variables from the transcript / sponge variable.
    fn get_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<Self::ConstraintField>>, SynthesisError>;

    /// [`TranscriptVar::separate_domain`] creates a new transcript / sponge
    /// variable by applying domain separation using the provided `domain` byte
    /// sequence.
    fn separate_domain(&self, domain: &[u8]) -> Result<Self, SynthesisError> {
        let mut new_sponge = self.clone();

        // Encode the domain length with a fixed-width `u64` so the derived
        // challenges are identical across targets.
        let mut input = (domain.len() as u64).to_le_bytes().to_vec();
        input.extend_from_slice(domain);

        // Chunk into `(MODULUS_BIT_SIZE - 1) / 8` bytes so a full chunk is
        // always `< 2^(MODULUS_BIT_SIZE - 1) <= MODULUS`
        let limbs = input
            .chunks((Self::ConstraintField::MODULUS_BIT_SIZE as usize - 1) / 8)
            .map(|chunk| FpVar::Constant(PrimeField::from_le_bytes_mod_order(chunk)))
            .collect::<Vec<_>>();

        new_sponge.add(&limbs)?;

        Ok(new_sponge)
    }

    /// [`TranscriptVar::challenge_field_element`] squeezes a challenge from
    /// the transcript variable as a field element variable.
    ///
    /// Internally, it first squeezes a field element variable and then absorbs
    /// it back into the transcript variable to ensure security.
    fn challenge_field_element(&mut self) -> Result<FpVar<Self::ConstraintField>, SynthesisError> {
        let mut c = self.get_field_elements(1)?;
        self.add(&c[0])?;
        Ok(c.swap_remove(0))
    }

    /// [`TranscriptVar::challenge_bits`] squeezes a challenge from the
    /// transcript variable as a vector of bit variables.
    ///
    /// Internally, it squeezes several field element variables, absorbs them
    /// back to the transcript variable (for strong Fiat-Shamir), and decomposes
    /// them into bit variables.
    fn challenge_bits(
        &mut self,
        num_bits: usize,
    ) -> Result<Vec<Boolean<Self::ConstraintField>>, SynthesisError> {
        let usable_bits = (Self::ConstraintField::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = num_bits.div_ceil(usable_bits);
        let src_elements = self.challenge_field_elements(num_elements)?;

        let mut bits = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            bits.extend_from_slice(&elem.to_bits_le()?[..usable_bits]);
        }

        bits.truncate(num_bits);
        Ok(bits)
    }

    /// [`TranscriptVar::challenge_field_elements`] squeezes `n` challenges
    /// from the transcript variable as field element variables.
    ///
    /// Internally, it first squeezes the field element variables and then
    /// absorbs them back into the transcript variable to ensure
    /// security.
    fn challenge_field_elements(
        &mut self,
        n: usize,
    ) -> Result<Vec<FpVar<Self::ConstraintField>>, SynthesisError> {
        let c = self.get_field_elements(n)?;
        self.add(&c)?;
        Ok(c)
    }
}
