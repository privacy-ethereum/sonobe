//! Implementation of transcript traits for arkworks' Poseidon sponge.

use ark_crypto_primitives::sponge::{
    Absorb, CryptographicSponge, DuplexSpongeMode, FieldBasedCryptographicSponge,
    constraints::CryptographicSpongeVar,
    poseidon::{PoseidonConfig, PoseidonSponge, constraints::PoseidonSpongeVar},
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::mem::transmute_copy;

use crate::transcripts::{Absorbable, AbsorbableVar, Transcript, TranscriptGadget};

impl<F: PrimeField + Absorbable> Transcript<F> for PoseidonSponge<F> {
    type Config = PoseidonConfig<F>;
    type Gadget = PoseidonSpongeVar<F>;

    fn new(config: Self::Config) -> Self {
        Self {
            state: vec![F::zero(); config.rate + config.capacity],
            parameters: config,
            mode: DuplexSpongeMode::Absorbing {
                next_absorb_index: 0,
            },
        }
    }

    fn add_field_elements(&mut self, input: &[F]) -> &mut Self {
        struct Hack<I>(I);
        impl<F> Absorb for Hack<&[F]> {
            fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
                // Unreachable because `PoseidonSponge::absorb` only calls
                // `to_sponge_field_elements_as_vec::<F>`
                unreachable!()
            }

            fn to_sponge_field_elements<T: PrimeField>(&self, dest: &mut Vec<T>) {
                // Safe because `F` in `to_sponge_field_elements_as_vec::<F>`,
                // which is called by `PoseidonSponge::absorb`, is the same as
                // `T` here.
                dest.extend(unsafe { transmute_copy::<&[F], &[T]>(&self.0) });
            }
        }
        CryptographicSponge::absorb(self, &Hack(input));
        self
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        self.squeeze_native_field_elements(num_elements)
    }
}

impl<F: PrimeField + Absorbable> TranscriptGadget<F> for PoseidonSpongeVar<F> {
    type Config = PoseidonConfig<F>;
    type Widget = PoseidonSponge<F>;

    fn new(config: PoseidonConfig<F>) -> Self
    where
        Self: Sized,
    {
        Self {
            cs: ConstraintSystemRef::None,
            state: vec![FpVar::<F>::zero(); config.rate + config.capacity],
            parameters: config,
            mode: DuplexSpongeMode::Absorbing {
                next_absorb_index: 0,
            },
        }
    }

    fn add<A: AbsorbableVar<F>>(&mut self, input: &A) -> Result<&mut Self, SynthesisError> {
        let mut result = Vec::new();
        input.absorb_into(&mut result)?;

        self.absorb(&result)?;
        Ok(self)
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.squeeze_field_elements(num_elements)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Projective as G1, g1::Config};
    use ark_crypto_primitives::sponge::poseidon::{PoseidonSponge, constraints::PoseidonSpongeVar};
    use ark_ff::UniformRand;
    use ark_r1cs_std::{
        GR1CSVar, alloc::AllocVar, fields::fp::FpVar,
        groups::curves::short_weierstrass::ProjectiveVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, rand::thread_rng, str::FromStr};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use crate::{
        algebra::group::emulated::EmulatedAffineVar,
        transcripts::{Transcript, TranscriptGadget, poseidon::poseidon_circom_config},
    };

    // Test with value taken from https://github.com/iden3/circomlibjs/blob/43cc582b100fc3459cf78d903a6f538e5d7f38ee/test/poseidon.js#L32
    #[test]
    fn check_against_circom_poseidon() -> Result<(), Box<dyn Error>> {
        let config = poseidon_circom_config::<Fr>();
        let mut poseidon_sponge = PoseidonSponge::new(config);
        let v = vec![1, 2, 3, 4]
            .into_iter()
            .map(Fr::from)
            .collect::<Vec<_>>();
        poseidon_sponge.add(&v);
        poseidon_sponge.get_field_elements(1);
        assert_eq!(
            poseidon_sponge.state[0],
            Fr::from_str(
                "18821383157269793795438455681495246036402687001665670618754263018637548127333"
            )
            .unwrap()
        );
        Ok(())
    }

    #[test]
    fn test_challenge_field_element() -> Result<(), Box<dyn Error>> {
        // Create a transcript outside of the circuit
        let config = poseidon_circom_config::<Fr>();
        let mut tr = PoseidonSponge::<Fr>::new(config.clone());
        tr.add(&Fr::from(42_u32));
        let c = tr.challenge::<Fr>();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fr>::new(config);
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
        let config = poseidon_circom_config::<Fq>();
        let mut tr = PoseidonSponge::<Fq>::new(config.clone());
        tr.add(&Fq::from(42_u32));
        let c = tr.challenge_bits(nbits);

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fq>::new(config);
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
        let config = poseidon_circom_config::<Fq>();
        let mut tr = PoseidonSponge::<Fq>::new(config.clone());
        let rng = &mut thread_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge::<Fq>();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fq>::new(config);
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
        let config = poseidon_circom_config::<Fr>();
        let mut tr = PoseidonSponge::<Fr>::new(config.clone());
        let rng = &mut thread_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge::<Fr>();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fr>::new(config);
        let p_var = EmulatedAffineVar::new_witness(cs, || Ok(p))?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }
}
