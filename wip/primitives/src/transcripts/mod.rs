use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, CryptographicSponge, FieldElementSize,
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, groups::CurveVar};
use ark_relations::gr1cs::SynthesisError;

use crate::traits::{AbsorbNonNativeGadget, Absorbable};

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

    /// Squeeze `num_bytes` bytes from the sponge.
    fn get_bytes(&mut self, num_bytes: usize) -> Vec<u8>;

    /// Squeeze `num_bits` bits from the sponge.
    fn get_bits(&mut self, num_bits: usize) -> Vec<bool>;

    fn get_field_elements_with_sizes(&mut self, sizes: &[FieldElementSize]) -> Vec<F>;

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
            .collect::<Vec<F>>();

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

pub trait TranscriptVar<F: PrimeField, S: CryptographicSponge>:
    CryptographicSpongeVar<F, S>
{
    /// `new_with_pp_hash` creates a new transcript / sponge with the given
    /// hash of the public parameters.
    fn new_with_pp_hash(
        config: &Self::Parameters,
        pp_hash: &FpVar<F>,
    ) -> Result<Self, SynthesisError>;

    /// `absorb_point` is for absorbing points whose `BaseField` is the field of
    /// the sponge, i.e., the type `C` of these points should satisfy
    /// `C::BaseField = F`.
    ///
    /// If the sponge field `F` is `C::ScalarField`, call `absorb_nonnative`
    /// instead.
    fn absorb_point<C: CurveGroup<BaseField = F>, GC: CurveVar<C, F>>(
        &mut self,
        v: &GC,
    ) -> Result<(), SynthesisError>;
    /// `absorb_nonnative` is for structs that contain non-native (field or
    /// group) elements, including:
    ///
    /// - A field element of type `T: PrimeField` that will be absorbed into a
    ///   sponge that operates in another field `F != T`.
    /// - A group element of type `C: CurveGroup` that will be absorbed into a
    ///   sponge that operates in another field `F != C::BaseField`, e.g.,
    ///   `F = C::ScalarField`.
    /// - A `CommittedInstance` on the secondary curve (used for CycleFold) that
    ///   will be absorbed into a sponge that operates in the (scalar field of
    ///   the) primary curve.
    ///
    ///   Note that although a `CommittedInstance` for `AugmentedFCircuit` on
    ///   the primary curve also contains non-native elements, we still regard
    ///   it as native, because the sponge is on the same curve.
    fn absorb_nonnative<V: AbsorbNonNativeGadget<F>>(
        &mut self,
        v: &V,
    ) -> Result<(), SynthesisError>;

    fn get_challenge(&mut self) -> Result<FpVar<F>, SynthesisError>;
    /// returns the bit representation of the challenge, we use its output in-circuit for the
    /// `GC.scalar_mul_le` method.
    fn get_challenge_nbits(&mut self, nbits: usize) -> Result<Vec<Boolean<F>>, SynthesisError>;
    fn get_challenges(&mut self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError>;
}
