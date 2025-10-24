use std::mem::transmute_copy;

use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{
        constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
    },
    Absorb, CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, groups::CurveVar};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

use crate::transcripts::{Absorbable, FieldElementSize};

use super::{AbsorbableGadget, Transcript, TranscriptVar};

impl<F: PrimeField> Transcript<F> for PoseidonSponge<F> {
    fn add<A: Absorbable<F> + ?Sized>(&mut self, input: &A) {
        struct Hack<I>(I);
        impl<F> Absorb for Hack<Vec<F>> {
            fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
                // Unreachable because `PoseidonSponge::absorb` only calls
                // `to_sponge_field_elements_as_vec::<F>`
                unreachable!()
            }

            fn to_sponge_field_elements<T: PrimeField>(&self, dest: &mut Vec<T>) {
                // Safe because `F` in `to_sponge_field_elements_as_vec::<F>`,
                // which is called by `PoseidonSponge::absorb`, is the same as
                // `T` here.
                dest.extend(unsafe { transmute_copy::<&[F], &[T]>(&self.0.as_ref()) });
            }
        }
        let v = input.to_absorbable();
        CryptographicSponge::absorb(self, &Hack(v));
    }

    fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        CryptographicSponge::squeeze_bits(self, num_bits)
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        self.squeeze_native_field_elements(num_elements)
    }
}

impl<F: PrimeField> TranscriptVar<F> for PoseidonSpongeVar<F> {
    type Native = PoseidonSponge<F>;

    fn add<A: AbsorbableGadget<FpVar<F>>>(&mut self, input: &A) -> Result<(), SynthesisError> {
        self.absorb(&input.to_absorbable()?)
    }

    fn get_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        self.squeeze_bits(num_bits)
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.squeeze_field_elements(num_elements)
    }
}

/// This Poseidon configuration generator produces a Poseidon configuration with custom parameters
pub fn poseidon_custom_config<F: PrimeField>(
    full_rounds: usize,
    partial_rounds: usize,
    alpha: u64,
    rate: usize,
    capacity: usize,
) -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}

/// This Poseidon configuration generator agrees with Circom's Poseidon(4) in the case of BN254's scalar field
pub fn poseidon_canonical_config<F: PrimeField>() -> PoseidonConfig<F> {
    // 120 bit security target as in
    // https://eprint.iacr.org/2019/458.pdf
    // t = rate + 1

    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5;
    let rate = 4;

    poseidon_custom_config(full_rounds, partial_rounds, alpha, rate, 1)
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::{constraints::GVar, g1::Config, Fq, Fr, G1Projective as G1};
    use ark_ec::PrimeGroup;
    use ark_ff::{BigInteger, UniformRand};
    use ark_r1cs_std::{
        alloc::AllocVar, groups::curves::short_weierstrass::ProjectiveVar, GR1CSVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, test_rng};

    use crate::algebra::group::nonnative::NonNativeAffineVar;

    use super::*;

    // Test with value taken from https://github.com/iden3/circomlibjs/blob/43cc582b100fc3459cf78d903a6f538e5d7f38ee/test/poseidon.js#L32
    #[test]
    fn check_against_circom_poseidon() -> Result<(), Box<dyn Error>> {
        use std::str::FromStr;

        let config = poseidon_canonical_config::<Fr>();
        let mut poseidon_sponge: PoseidonSponge<_> = CryptographicSponge::new(&config);
        let v = vec![1, 2, 3, 4]
            .into_iter()
            .map(Fr::from)
            .collect::<Vec<_>>();
        poseidon_sponge.add(&v);
        poseidon_sponge.get_field_elements(1);
        assert!(
            poseidon_sponge.state[0]
                == Fr::from_str(
                    "18821383157269793795438455681495246036402687001665670618754263018637548127333"
                )
                .unwrap()
        );
        Ok(())
    }

    #[test]
    fn test_transcript_and_transcriptvar_absorb_native_point() -> Result<(), Box<dyn Error>> {
        // use 'native' transcript
        let config = poseidon_canonical_config::<Fq>();
        let mut tr = PoseidonSponge::<Fq>::new(&config);
        let rng = &mut test_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge_field_element();

        // use 'gadget' transcript
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fq>::new(cs.clone(), &config);
        let p_var = ProjectiveVar::<Config, FpVar<Fq>>::new_witness(
            ConstraintSystem::<Fq>::new_ref(),
            || Ok(p),
        )?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // assert that native & gadget transcripts return the same challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_transcript_and_transcriptvar_absorb_nonnative_point() -> Result<(), Box<dyn Error>> {
        // use 'native' transcript
        let config = poseidon_canonical_config::<Fr>();
        let mut tr = PoseidonSponge::<Fr>::new(&config);
        let rng = &mut test_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge_field_element();

        // use 'gadget' transcript
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fr>::new(cs.clone(), &config);
        let p_var =
            NonNativeAffineVar::<G1>::new_witness(ConstraintSystem::<Fr>::new_ref(), || Ok(p))?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // assert that native & gadget transcripts return the same challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_transcript_and_transcriptvar_get_challenge() -> Result<(), Box<dyn Error>> {
        // use 'native' transcript
        let config = poseidon_canonical_config::<Fr>();
        let mut tr = PoseidonSponge::<Fr>::new(&config);
        tr.add(&Fr::from(42_u32));
        let c = tr.challenge_field_element();

        // use 'gadget' transcript
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fr>::new(cs.clone(), &config);
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
        let config = poseidon_canonical_config::<Fq>();
        let mut tr = PoseidonSponge::<Fq>::new(&config);
        tr.add(&Fq::from(42_u32));

        // get challenge from native transcript
        let c_bits = tr.challenge_bits(nbits);

        // use 'gadget' transcript
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fq>::new(cs.clone(), &config);
        let v = FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(42_u32)))?;
        tr_var.add(&v)?;

        // get challenge from circuit transcript
        let c_var = tr_var.challenge_bits(nbits)?;

        let p = G1::generator();
        let p_var = GVar::new_witness(cs.clone(), || Ok(p))?;

        // multiply point P by the challenge in different formats, to ensure that we get the same
        // result natively and in-circuit
        let c = Fr::from(<Fr as PrimeField>::BigInt::from_bits_le(&c_bits));

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
