/// Heavily inspired from testudo: https://github.com/cryptonetlab/testudo/tree/master
/// Some changes:
/// - Typings to better stick to ark_poly's API
/// - Uses `folding-schemes`' own `TranscriptVar` trait and `PoseidonTranscriptVar` struct
/// - API made closer to gadgets found in `folding-schemes`
use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    poly::polynomial::univariate::dense::DensePolynomialVar,
};
use ark_relations::gr1cs::SynthesisError;

use crate::{sumcheck::utils::VPAuxInfo, transcripts::TranscriptVar};

pub struct IOPSumCheckGadget;

impl IOPSumCheckGadget {
    pub fn verify<F: PrimeField>(
        claimed_sum: FpVar<F>,
        proofs: &Vec<Vec<FpVar<F>>>,
        aux_info: &VPAuxInfo,
        transcript: &mut impl TranscriptVar<F>,
    ) -> Result<(FpVar<F>, Vec<FpVar<F>>), SynthesisError> {
        transcript.add(&FpVar::constant(F::from(aux_info.num_variables as u64)))?;
        transcript.add(&FpVar::constant(F::from(aux_info.max_degree as u64)))?;
        if proofs.len() != aux_info.num_variables {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut challenges = Vec::with_capacity(aux_info.num_variables);
        let mut expected = claimed_sum;

        for coeffs in proofs {
            if coeffs.len() - 1 != aux_info.max_degree {
                return Err(SynthesisError::Unsatisfiable);
            }

            let eval_at_zero = &coeffs[0];
            let eval_at_one = coeffs.iter().sum::<FpVar<F>>();

            (eval_at_zero + eval_at_one).enforce_equal(&expected)?;

            transcript.add(&coeffs)?;
            let challenge = transcript.challenge_field_element()?;

            expected = DensePolynomialVar::from_coefficients_slice(coeffs).evaluate(&challenge)?;
            challenges.push(challenge);
        }

        Ok((expected, challenges))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::sponge::{
        poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
        CryptographicSponge,
    };
    use ark_ff::{One, Zero};
    use ark_poly::{
        univariate::DensePolynomial, DenseMultilinearExtension, DenseUVPolynomial,
        MultilinearExtension, Polynomial,
    };
    use ark_r1cs_std::{alloc::AllocVar, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, test_rng};

    use super::*;
    use crate::{
        sumcheck::{utils::VirtualPolynomial, IOPSumCheck},
        transcripts::poseidon::poseidon_canonical_config,
    };

    #[test]
    fn test_sum_check_circuit() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let poseidon_config = poseidon_canonical_config::<Fr>();
        for num_vars in 1..15 {
            let mut transcript_p = PoseidonSponge::new(&poseidon_config);
            let mut transcript_v = PoseidonSponge::new(&poseidon_config);

            let poly_mle = DenseMultilinearExtension::rand(num_vars, &mut rng);
            let virtual_poly = VirtualPolynomial::new_from_mle(poly_mle, One::one());
            let aux_info = virtual_poly.aux_info.clone();

            let (proofs, challenges, _) = IOPSumCheck::prove(virtual_poly, &mut transcript_p)?;

            let poly = DensePolynomial::from_coefficients_slice(&proofs[0]);
            let claimed_sum = poly.evaluate(&One::one()) + poly.evaluate(&Zero::zero());

            let (expected, _) =
                IOPSumCheck::verify(claimed_sum, &proofs, &aux_info, &mut transcript_v)?;

            let cs = ConstraintSystem::new_ref();
            let mut transcript_var = PoseidonSpongeVar::new(&poseidon_config);

            let (expected_var, challenges_var) = IOPSumCheckGadget::verify(
                FpVar::new_witness(cs.clone(), || Ok(claimed_sum))?,
                &proofs
                    .into_iter()
                    .map(|v| Vec::new_witness(cs.clone(), || Ok(v)))
                    .collect::<Result<_, _>>()?,
                &aux_info,
                &mut transcript_var,
            )?;

            assert!(cs.is_satisfied()?);

            assert_eq!(expected_var.value()?, expected);
            assert_eq!(challenges_var.value()?, challenges);
        }
        Ok(())
    }
}
