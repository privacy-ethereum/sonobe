use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, CryptographicSponge, FieldElementSize,
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, groups::CurveVar};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

pub use absorbable::{Absorbable, AbsorbableGadget};

pub mod absorbable;
pub mod poseidon;

pub trait Transcript<F: PrimeField> {
    /// `new_with_pp_hash` creates a new transcript / sponge with the given
    /// hash of the public parameters.
    fn new_with_pp_hash(config: &Self::Config, pp_hash: F) -> Self
    where
        F: Absorbable<F>,
        Self: CryptographicSponge,
    {
        let mut sponge = Self::new(config);
        sponge.add(&pp_hash);
        sponge
    }

    fn add<A: Absorbable<F> + ?Sized>(&mut self, input: &A);

    /// Squeeze `num_bits` bits from the sponge.
    fn get_bits(&mut self, num_bits: usize) -> Vec<bool>;

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F>;

    /// Creates a new sponge with applied domain separation.
    fn separate_domain(&self, domain: &[u8]) -> Self
    where
        F: Absorbable<F>,
        Self: CryptographicSponge,
    {
        let mut new_sponge = self.clone();

        let mut input = domain.len().to_le_bytes().to_vec();
        input.extend_from_slice(domain);

        let limbs = input
            .chunks(F::MODULUS_BIT_SIZE.div_ceil(8) as usize)
            .map(|chunk| F::from_le_bytes_mod_order(chunk))
            .collect::<Vec<_>>();

        new_sponge.add(&limbs);

        new_sponge
    }

    fn challenge_field_element(&mut self) -> F
    where
        F: Absorbable<F>,
    {
        let c = self.get_field_elements(1);
        self.add(&c[0]);
        c[0]
    }
    fn challenge_bits(&mut self, nbits: usize) -> Vec<bool>
    where
        F: Absorbable<F>,
    {
        let bits = self.get_bits(nbits);
        self.add(&F::from(F::BigInt::from_bits_le(&bits)));
        bits
    }
    fn challenge_field_elements(&mut self, n: usize) -> Vec<F>
    where
        F: Absorbable<F>,
    {
        let c = self.get_field_elements(n);
        self.add(&c);
        c
    }
}

pub trait TranscriptVar<F: PrimeField> {
    type Native;

    /// `new_with_pp_hash` creates a new transcript / sponge with the given
    /// hash of the public parameters.
    fn new_with_pp_hash(
        config: &Self::Parameters,
        pp_hash: &FpVar<F>,
    ) -> Result<Self, SynthesisError>
    where
        Self: CryptographicSpongeVar<F, Self::Native>,
        Self::Native: CryptographicSponge,
    {
        let mut sponge = Self::new(ConstraintSystemRef::None, config);
        sponge.add(&pp_hash)?;
        Ok(sponge)
    }

    fn add<A: AbsorbableGadget<FpVar<F>>>(&mut self, input: &A) -> Result<(), SynthesisError>;

    /// Squeeze `num_bits` bits from the sponge.
    fn get_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F>>, SynthesisError>;

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError>;

    /// Creates a new sponge with applied domain separation.
    fn separate_domain(&self, domain: &[u8]) -> Result<Self, SynthesisError>
    where
        Self: CryptographicSponge,
    {
        let mut new_sponge = self.clone();

        let mut input = domain.len().to_le_bytes().to_vec();
        input.extend_from_slice(domain);

        let limbs = input
            .chunks(F::MODULUS_BIT_SIZE.div_ceil(8) as usize)
            .map(|chunk| FpVar::Constant(F::from_le_bytes_mod_order(chunk)))
            .collect::<Vec<_>>();

        new_sponge.add(&limbs)?;

        Ok(new_sponge)
    }

    fn challenge_field_element(&mut self) -> Result<FpVar<F>, SynthesisError> {
        let mut c = self.get_field_elements(1)?;
        self.add(&c[0])?;
        Ok(c.pop().unwrap())
    }
    fn challenge_bits(&mut self, nbits: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let bits = self.get_bits(nbits)?;
        self.add(&Boolean::le_bits_to_fp(&bits)?)?;
        Ok(bits)
    }

    fn challenge_field_elements(&mut self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let c = self.get_field_elements(n)?;
        self.add(&c)?;
        Ok(c)
    }
}
