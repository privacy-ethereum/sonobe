//! In-circuit verifier gadget for the sumcheck protocol.
//!
//! The code is forked from Testudo's sumcheck circuit [implementation] and
//! modified to fit Sonobe's design & use case.
//!
//! [implementation]: https://github.com/cryptonetlab/testudo/blob/7db2d30972ce72ee7622070a1debc3b72580f4c7/src/constraints.rs#L116-L143

// Below we attach Testudo's original license notice.
// (Note: since the Testudo repo was forked from Microsoft's Spartan repo but no
// modifications were made to the license in Testudo, their copyright notice
// still credits Microsoft.)
//
// MIT License
//
// Copyright (c) Microsoft Corporation.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    poly::polynomial::univariate::dense::DensePolynomialVar,
};
use ark_relations::gr1cs::SynthesisError;

use crate::{
    sumcheck::utils::VPAuxInfo,
    transcripts::{Absorbable, TranscriptGadget},
};

/// [`SumCheckGadget`] is the in-circuit sumcheck verifier gadget.
pub struct SumCheckGadget;

impl SumCheckGadget {
    /// [`SumCheckGadget::verify`] provides an implementation of the sumcheck
    /// verification algorithm in circuit.
    ///
    /// Given the claimed sum `claimed_sum = z`, the proof `proofs` (i.e., round
    /// polynomials `g_1, ..., g_n`), the auxiliary info `aux_info`, and the
    /// transcript `transcript`.
    /// It returns the final evaluation `z_{n+1} = f(r_1, ..., r_n)` and the
    /// Fiat-Shamir challenges `r_1, ..., r_n`.
    ///
    /// It mirrors the verifier widget [`super::SumCheck::verify`] with exactly
    /// the same logic.
    pub fn verify<F: PrimeField + Absorbable>(
        mut claimed_sum: FpVar<F>,
        proofs: &Vec<Vec<FpVar<F>>>,
        aux_info: &VPAuxInfo,
        transcript: &mut impl TranscriptGadget<F>,
    ) -> Result<(FpVar<F>, Vec<FpVar<F>>), SynthesisError> {
        transcript.add(&FpVar::constant(F::from(aux_info.num_variables as u64)))?;
        transcript.add(&FpVar::constant(F::from(aux_info.max_degree as u64)))?;
        if proofs.len() != aux_info.num_variables {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut challenges = Vec::with_capacity(aux_info.num_variables);

        for coeffs in proofs {
            if coeffs.len() - 1 != aux_info.max_degree {
                return Err(SynthesisError::Unsatisfiable);
            }

            let eval_at_zero = &coeffs[0];
            let eval_at_one = coeffs.iter().sum::<FpVar<F>>();

            (eval_at_zero + eval_at_one).enforce_equal(&claimed_sum)?;

            transcript.add(&coeffs)?;
            let challenge = transcript.challenge_field_element()?;

            claimed_sum =
                DensePolynomialVar::from_coefficients_slice(coeffs).evaluate(&challenge)?;
            challenges.push(challenge);
        }

        Ok((claimed_sum, challenges))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::sponge::poseidon::{PoseidonSponge, constraints::PoseidonSpongeVar};
    use ark_ff::{One, Zero};
    use ark_poly::{
        DenseMultilinearExtension, DenseUVPolynomial, MultilinearExtension, Polynomial,
        univariate::DensePolynomial,
    };
    use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, rand::thread_rng};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{
        sumcheck::{SumCheck, utils::VirtualPolynomial},
        transcripts::{Transcript, poseidon::poseidon_circom_config},
    };

    #[test]
    fn test_sum_check_circuit() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let poseidon_config = poseidon_circom_config::<Fr>();
        for num_vars in 1..15 {
            let mut transcript_p = PoseidonSponge::new(poseidon_config.clone());
            let mut transcript_v = PoseidonSponge::new(poseidon_config.clone());

            let poly_mle = DenseMultilinearExtension::rand(num_vars, &mut rng);
            let virtual_poly = VirtualPolynomial::new_from_mle(poly_mle, One::one());
            let aux_info = virtual_poly.aux_info.clone();

            let (proofs, challenges, _) = SumCheck::prove(virtual_poly, &mut transcript_p)?;

            let poly = DensePolynomial::from_coefficients_slice(&proofs[0]);
            let claimed_sum = poly.evaluate(&One::one()) + poly.evaluate(&Zero::zero());

            let (expected, _) =
                SumCheck::verify(claimed_sum, &proofs, &aux_info, &mut transcript_v)?;

            let cs = ConstraintSystem::new_ref();
            let mut transcript_var = PoseidonSpongeVar::new(poseidon_config.clone());

            let (expected_var, challenges_var) = SumCheckGadget::verify(
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
