pub use absorbable::{Absorbable, AbsorbableGadget};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

pub mod absorbable;
pub mod griffin;
pub mod poseidon;

pub trait Transcript<F: PrimeField> {
    type Config;

    fn new(config: &Self::Config) -> Self;

    /// `new_with_pp_hash` creates a new transcript / sponge with the given
    /// hash of the public parameters.
    fn new_with_pp_hash(config: &Self::Config, pp_hash: F) -> Self
    where
        Self: Sized,
    {
        let mut sponge = Self::new(config);
        sponge.add_field_elements(&[pp_hash]);
        sponge
    }

    fn add<A: Absorbable + ?Sized>(&mut self, input: &A) -> &mut Self {
        let elems = input.to_absorbable();

        self.add_field_elements(&elems)
    }

    fn add_field_elements(&mut self, input: &[F]) -> &mut Self;

    /// Squeeze `num_bits` bits from the sponge.
    fn get_bits(&mut self, num_bits: usize) -> Vec<bool>;

    fn get_field_element(&mut self) -> F {
        self.get_field_elements(1)[0]
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F>;

    /// Creates a new sponge with applied domain separation.
    fn separate_domain(&self, domain: &[u8]) -> Self
    where
        Self: Clone,
    {
        let mut new_sponge = self.clone();

        let mut input = domain.len().to_le_bytes().to_vec();
        input.extend_from_slice(domain);

        let limbs = input
            .chunks(F::MODULUS_BIT_SIZE.div_ceil(8) as usize)
            .map(|chunk| F::from_le_bytes_mod_order(chunk))
            .collect::<Vec<_>>();

        new_sponge.add_field_elements(&limbs);

        new_sponge
    }

    fn challenge_field_element(&mut self) -> F {
        let c = self.get_field_elements(1);
        self.add_field_elements(&c);
        c[0]
    }

    fn challenge_bits(&mut self, nbits: usize) -> Vec<bool> {
        let bits = self.get_bits(nbits);
        self.add_field_elements(
            &bits
                .chunks(F::MODULUS_BIT_SIZE as usize - 1)
                .map(F::BigInt::from_bits_le)
                .map(F::from)
                .collect::<Vec<_>>(),
        );
        bits
    }

    fn challenge_field_elements(&mut self, n: usize) -> Vec<F> {
        let c = self.get_field_elements(n);
        self.add_field_elements(&c);
        c
    }
}

pub trait TranscriptVar<F: PrimeField> {
    type Native: Transcript<F>;

    fn new(config: &<Self::Native as Transcript<F>>::Config) -> Self
    where
        Self: Sized;

    /// `new_with_pp_hash` creates a new transcript / sponge with the given
    /// hash of the public parameters.
    fn new_with_pp_hash(
        config: &<Self::Native as Transcript<F>>::Config,
        pp_hash: &FpVar<F>,
    ) -> Result<Self, SynthesisError>
    where
        Self: Sized,
    {
        let mut sponge = Self::new(config);
        sponge.add(&pp_hash)?;
        Ok(sponge)
    }

    fn add<A: AbsorbableGadget<F> + ?Sized>(
        &mut self,
        input: &A,
    ) -> Result<&mut Self, SynthesisError>;

    /// Squeeze `num_bits` bits from the sponge.
    fn get_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F>>, SynthesisError>;

    fn get_field_element(&mut self) -> Result<FpVar<F>, SynthesisError> {
        Ok(self.get_field_elements(1)?.pop().unwrap())
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError>;

    /// Creates a new sponge with applied domain separation.
    fn separate_domain(&self, domain: &[u8]) -> Result<Self, SynthesisError>
    where
        Self: Clone,
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
        self.add(
            &bits
                .chunks(F::MODULUS_BIT_SIZE as usize - 1)
                .map(Boolean::le_bits_to_fp)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        Ok(bits)
    }

    fn challenge_field_elements(&mut self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let c = self.get_field_elements(n)?;
        self.add(&c)?;
        Ok(c)
    }
}
