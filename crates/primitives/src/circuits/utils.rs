//! This module provides utility circuits.

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    fields::fp::{AllocatedFp, FpVar},
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};

use super::Assignments;
use crate::{arithmetizations::r1cs::R1CS, circuits::FCircuit, traits::SonobePrimeField};

/// [`CircuitForTest`] implements a simple test circuit computing
/// `y = x^3 + x + 5` with 4 R1CS constraints.
///
/// It is used in unit tests to verify constraint extraction and witness
/// generation.
pub struct CircuitForTest<F: PrimeField> {
    /// [`CircuitForTest::x`] is the input variable `x` of the circuit.
    pub x: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CircuitForTest<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Variable 0 (implicitly added by arkworks as 1)
        // Variable 1
        let x = AllocatedFp::new_input(cs.clone(), || Ok(self.x))?;
        // Variable 2
        let y = AllocatedFp::new_witness(cs.clone(), || Ok(self.x.pow([3]) + self.x + F::from(5)))?;

        // Variable 3, Constraint 0
        let x_square = x.square()?;
        // Variable 4, Constraint 1
        let x_cube = x_square.mul(&x);
        // Variable 5
        let t = AllocatedFp::new_witness(cs.clone(), || Ok(self.x.pow([3]) + self.x))?;
        let x_cube_plus_x = x.add(&x_cube);
        // Constraint 2
        cs.enforce_r1cs_constraint(
            || x_cube_plus_x.variable.into(),
            || Variable::one().into(),
            || t.variable.into(),
        )?;
        let x_cube_plus_x_plus_5 = t.add_constant(F::from(5));
        // Constraint 3
        cs.enforce_r1cs_constraint(
            || x_cube_plus_x_plus_5.variable.into(),
            || Variable::one().into(),
            || y.variable.into(),
        )?;
        Ok(())
    }
}

impl<F: SonobePrimeField> FCircuit for CircuitForTest<F> {
    type Field = F;
    type State = [F; 1];
    type StateVar = [FpVar<F>; 1];

    type ExternalInputs = ();
    type ExternalOutputs = ();

    fn dummy_state(&self) -> Self::State {
        [F::zero(); 1]
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {}

    fn synthesize_step(
        &self,
        _i: FpVar<Self::Field>,
        z_i: Self::StateVar,
        _external_inputs: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        let cs = z_i.cs();

        // Variable 0 (implicitly added by arkworks as 1)
        // Variable 1
        let x = if let FpVar::Var(x) = z_i[0].clone() {
            x
        } else {
            unreachable!()
        };
        // Variable 2
        let y = AllocatedFp::new_witness(cs.clone(), || {
            Ok(x.value()?.pow([3]) + x.value()? + F::from(5))
        })?;

        // Variable 3, Constraint 0
        let x_square = x.square()?;
        // Variable 4, Constraint 1
        let x_cube = x_square.mul(&x);
        // Variable 5
        let t = AllocatedFp::new_witness(cs.clone(), || Ok(x.value()?.pow([3]) + x.value()?))?;
        let x_cube_plus_x = x.add(&x_cube);
        // Constraint 2
        cs.enforce_r1cs_constraint(
            || x_cube_plus_x.variable.into(),
            || Variable::one().into(),
            || t.variable.into(),
        )?;
        let x_cube_plus_x_plus_5 = t.add_constant(F::from(5));
        // Constraint 3
        cs.enforce_r1cs_constraint(
            || x_cube_plus_x_plus_5.variable.into(),
            || Variable::one().into(),
            || y.variable.into(),
        )?;
        Ok(([FpVar::Var(x_cube_plus_x_plus_5)], ()))
    }
}

/// [`constraints_for_test`] returns the R1CS constraints for the test circuit.
#[allow(non_snake_case)]
pub fn constraints_for_test<F: Field>() -> R1CS<F> {
    // R1CS for: x^3 + x + 5 = y (example from article
    // https://vitalik.eth.limo/general/2016/12/10/qap.html)
    let A = vec![
        vec![(F::one(), 1)],
        vec![(F::one(), 3)],
        vec![(F::one(), 1), (F::one(), 4)],
        vec![(F::from(5), 0), (F::one(), 5)],
    ];
    let B = vec![
        vec![(F::one(), 1)],
        vec![(F::one(), 1)],
        vec![(F::one(), 0)],
        vec![(F::one(), 0)],
    ];
    let C = vec![
        vec![(F::one(), 3)],
        vec![(F::one(), 4)],
        vec![(F::one(), 5)],
        vec![(F::one(), 2)],
    ];

    R1CS::<F>::new_without_validity_check(4, 6, 1, [A, B, C])
}

/// [`satisfying_assignments_for_test`] returns a satisfying assignment for the
/// test circuit given an input `x`.
pub fn satisfying_assignments_for_test<F: Field>(x: F) -> Assignments<F, Vec<F>> {
    Assignments::from((
        F::one(),
        vec![x],
        vec![
            x * x * x + x + F::from(5), // x^3 + x + 5
            x * x,                      // x^2
            x * x * x,                  // x^2 * x
            x * x * x + x,              // x^3 + x
        ],
    ))
}
