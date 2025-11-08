use ark_ff::{BigInteger, Field, Fp, FpConfig, PrimeField};
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{any::TypeId, mem::transmute_copy};

use crate::{
    circuits::var::Var,
    traits::{Inputize, InputizeEmulated},
    transcripts::{Absorbable, AbsorbableGadget},
};

// pub mod nonnative;
pub mod emulated;

/// `Field` trait is a wrapper around `PrimeField` that also includes the
/// necessary bounds for the field to be used conveniently in folding schemes.
pub trait SonobeField:
    PrimeField<BasePrimeField = Self> + Absorbable + Inputize<Self>
{
    const BITS_PER_LIMB: usize;
    /// The in-circuit variable type for this field.
    type Var: FieldVar<Self, Self> + AbsorbableGadget<Self>;
}

impl<P: FpConfig<N>, const N: usize> SonobeField for Fp<P, N> {
    // For a `F` with order > 250 bits, 55 is chosen for optimizing the most
    // expensive part `Az∘Bz` when checking the R1CS relation for CycleFold.
    // Consider using `NonNativeUintVar` to represent the base field `Fq`.
    // Since 250 / 55 = 4.46, the `NonNativeUintVar` has 5 limbs.
    // Now, the multiplication of two `NonNativeUintVar`s has 9 limbs, and
    // each limb has at most 2^{55 * 2} * 5 = 112.3 bits.
    // For a 1400x1400 matrix `A`, the multiplication of `A`'s row and `z`
    // is the sum of 1400 `NonNativeUintVar`s, each with 9 limbs.
    // Thus, the maximum bit length of limbs of each element in `Az` is
    // 2^{55 * 2} * 5 * 1400 = 122.7 bits.
    // Finally, in the hadamard product of `Az` and `Bz`, every element has
    // 17 limbs, whose maximum bit length is (2^{55 * 2} * 5 * 1400)^2 * 9
    // = 248.7 bits and is less than the native field `Fr`.
    // Thus, 55 allows us to compute `Az∘Bz` without the expensive alignment
    // operation.
    //
    // TODO: either make it a global const, or compute an optimal value
    // based on the modulus size.
    const BITS_PER_LIMB: usize = 55; // TODO: make this configurable
    type Var = FpVar<Self>;
}

impl<P: FpConfig<N>, const N: usize> Absorbable for Fp<P, N> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        if TypeId::of::<F>() == TypeId::of::<Self>() {
            // Safe because `F` and `Self` have the same type
            // TODO (@winderica): specialization when???
            dest.push(unsafe { transmute_copy::<Self, F>(self) });
        } else {
            let bits_per_limb = F::MODULUS_BIT_SIZE - 1;
            let num_limbs = Self::MODULUS_BIT_SIZE.div_ceil(bits_per_limb);

            let mut limbs = self
                .into_bigint()
                .to_bits_le()
                .chunks(bits_per_limb as usize)
                .map(|chunk| F::from(F::BigInt::from_bits_le(chunk)))
                .collect::<Vec<F>>();
            limbs.resize(num_limbs as usize, F::zero());

            dest.extend(&limbs)
        }
    }
}

impl<F: PrimeField> AbsorbableGadget<F> for FpVar<F> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        dest.push(self.clone());
        Ok(())
    }
}

impl<F: PrimeField> Var<F> for FpVar<F> {
    type Native = F;
}

impl<P: FpConfig<N>, const N: usize> Inputize<Self> for Fp<P, N> {
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `FpVar::new_input`.
    fn inputize(&self) -> Vec<Self> {
        vec![*self]
    }
}

impl<F: SonobeField, P: SonobeField> InputizeEmulated<F> for P {
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `NonNativeUintVar::new_input`.
    fn inputize_emulated(&self) -> Vec<F> {
        self.into_bigint()
            .to_bits_le()
            .chunks(F::BITS_PER_LIMB)
            .map(|chunk| F::from(F::BigInt::from_bits_le(chunk)))
            .collect()
    }
}
