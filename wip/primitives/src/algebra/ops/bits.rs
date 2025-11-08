use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, GR1CSVar};
use ark_relations::gr1cs::SynthesisError;

use crate::algebra::field::emulated::Bound;

pub trait FromBitsGadget<F: PrimeField>: Sized {
    fn from_bits_le(bits: &[Boolean<F>], bound: Bound) -> Result<Self, SynthesisError>;
}

pub trait ToBitsGadgetExt<F: PrimeField>: Sized {
    fn to_n_bits_le(&self, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError>;

    fn enforce_bit_length(&self, n: usize) -> Result<(), SynthesisError> {
        self.to_n_bits_le(n)?;
        Ok(())
    }
}
impl<F: PrimeField> FromBitsGadget<F> for FpVar<F> {
    fn from_bits_le(bits: &[Boolean<F>], _bound: Bound) -> Result<Self, SynthesisError> {
        Boolean::le_bits_to_fp(bits)
    }
}

impl<F: PrimeField> ToBitsGadgetExt<F> for FpVar<F> {
    fn to_n_bits_le(&self, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let mut bits = self.value().unwrap_or_default().into_bigint().to_bits_le();
        bits.resize(n, false);
        let bits = Vec::new_variable_with_inferred_mode(self.cs(), || Ok(bits))?;

        Boolean::le_bits_to_fp(&bits)?.enforce_equal(self)?;

        Ok(bits)
    }
}
