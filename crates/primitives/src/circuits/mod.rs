//! This module defines circuits and helpers used by Sonobe.

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode,
};
use ark_std::{
    fmt::Debug,
    ops::{Deref, Index, IndexMut},
};

use crate::transcripts::{Absorbable, AbsorbableVar};

pub mod utils;

/// [`FCircuit`] defines the trait of step circuits being proven by IVC schemes.
///
/// In IVC, a step circuit is repeatedly invoked to update some state persisted
/// throughout the execution.
/// For flexibility, we further allow each step to take some external inputs
/// and produce some external outputs that are not part of the state, which may
/// or may not be constrained inside the step circuit.
///
/// Such a design has several advantages:
/// 1. It allows the implementation to keep the state minimal, only including
///    the parts that need to be preserved and constrained across steps, while
///    step-specific inputs that might be large are not part of the state.
///
///    For example, in a Merkle tree update circuit, the state may only contain
///    the root of the tree, while the leaf value and authentication path which
///    are large can be provided as external inputs at each step.
///
/// 2. The caller of the step circuit can peek into the circuit execution at
///    each step via the external outputs by having the circuit return
///    `var.value()` for desired variables.
///
///    For example, in a Merkle tree update circuit, the circuit can return the
///    intermediate hashes computed at each step as external outputs, allowing
///    the caller to test if the hash computation is correct.
///
/// 3. The implementation can mix out-of-circuit and in-circuit logic in this
///    structure, where the out-of-circuit logic may consume external inputs and
///    produce external outputs for the next step.
///    This is why the implementation may choose to constrain or not constrain
///    the external inputs/outputs inside the step circuit.
///    Such a mixed design can be helpful if the out-of-circuit logic and the
///    in-circuit logic are highly interdependent.
///
///    For example, in a Merkle tree update circuit, one may write both the
///    Merkle proof generation (out-of-circuit) and verification (in-circuit)
///    logic in a single [`FCircuit::generate_step_constraints`].
///    In this case, the external inputs contain the leaf value to be added, as
///    well as all the existing tree nodes.
///    The latter will be used by the out-of-circuit logic to compute the path,
///    but will not be constrained inside the circuit.
///    The external outputs contain the new tree nodes after the update, which
///    will be used as the inputs to the next step.
///
/// To summarize, the step circuit takes as input the current state and some
/// external inputs, and returns the next state and some external outputs.
pub trait FCircuit {
    /// [`FCircuit::Field`] is the field over which the circuit is defined.
    type Field: PrimeField;
    /// [`FCircuit::State`] is the type of the state.
    ///
    /// It is usually an array of field elements, but we make our design quite
    /// flexible so that the implementation is free to choose any structure for
    /// it.
    type State: Clone + PartialEq + Absorbable;
    /// [`FCircuit::StateVar`] is the in-circuit variable type for the state.
    ///
    /// If the implementation chooses custom structures for the state, it should
    /// implement the required traits for the corresponding variable type.
    type StateVar: GR1CSVar<Self::Field, Value = Self::State>
        + AllocVar<Self::State, Self::Field>
        + AbsorbableVar<Self::Field>
        + EqGadget<Self::Field>;
    /// [`FCircuit::ExternalInputs`] is the type of external inputs provided to
    /// each step of the circuit.
    type ExternalInputs;
    /// [`FCircuit::ExternalOutputs`] is the type of external outputs produced
    /// by each step of the circuit.
    type ExternalOutputs;

    /// [`FCircuit::same_state_shape`] returns whether two states `a` and `b`
    /// have the same shape/structure.
    ///
    /// This allows the verifier to check whether the prover's claimed states
    /// have the desired shape.
    ///
    /// The implementation should perform the checks carefully to ensure that
    /// all fields/members of the provided states are consistent. Specifically,
    /// if all fields/members of [`FCircuit::State`] have fixed size, then the
    /// shape consistency is trivially `true`. However, if [`FCircuit::State`]
    /// contains variable-length fields/members (e.g., `Vec<F>`, `Vec<Vec<F>>`),
    /// then the implementation must examine all of such fields/members and
    /// return `false` when any of them are differently sized in `a` and `b`.
    fn same_state_shape(a: &Self::State, b: &Self::State) -> bool;

    /// [`FCircuit::dummy_state`] returns a dummy state for the circuit.
    ///
    /// The dummy state should have the same shape as states in real IVC
    /// executions.
    fn dummy_state(&self) -> Self::State;

    /// [`FCircuit::dummy_external_inputs`] returns dummy external inputs for
    /// the circuit.
    fn dummy_external_inputs(&self) -> Self::ExternalInputs;

    /// [`FCircuit::generate_step_constraints`] generates the constraints for
    /// the `i`-th step of invocation of the step circuit with the current state
    /// `state` and external inputs `external_inputs`, producing the next state
    /// and external outputs.
    ///
    /// ### Tips
    ///
    /// - Since this method uses `self`, the implementation can store some fixed
    ///   info that is shared across all steps inside `self`.
    /// - Variables in the implementation should be allocated as witnesses (not
    ///   public inputs) in the implementation.
    /// - If needed, the constraint system `cs` can be accessed via `i.cs()` or
    ///   `state.cs()` using arkworks' [`GR1CSVar::cs`] method.
    fn generate_step_constraints(
        &self,
        i: FpVar<Self::Field>,
        state: Self::StateVar,
        external_inputs: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError>;
}

/// [`Assignments`] represents a full assignment vector `z = (u, x, w)` for a
/// constraint system.
#[derive(Clone, Debug, PartialEq)]
pub struct Assignments<F, V> {
    /// [`Assignments::constant`] is the "constant" part (leading scalar) of the
    /// assignment, which is usually 1 but might be relaxed in some cases.
    pub constant: F,
    /// [`Assignments::public`] contains the public inputs.
    pub public: V,
    /// [`Assignments::private`] contains the witnesses.
    pub private: V,
}

/// [`AssignmentsOwned`] is a convenience alias for owned assignment vectors.
pub type AssignmentsOwned<F> = Assignments<F, Vec<F>>;

impl<F, V> From<(F, V, V)> for Assignments<F, V> {
    fn from((u, x, w): (F, V, V)) -> Self {
        Self {
            constant: u,
            public: x,
            private: w,
        }
    }
}

impl<F, V: AsRef<[F]>> Index<usize> for Assignments<F, V> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        let public = self.public.as_ref();
        let private = self.private.as_ref();
        if index == 0 {
            &self.constant
        } else if index <= public.len() {
            &public[index - 1]
        } else {
            &private[index - 1 - public.len()]
        }
    }
}

impl<F, V: AsRef<[F]> + AsMut<[F]>> IndexMut<usize> for Assignments<F, V> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let public = self.public.as_mut();
        let private = self.private.as_mut();
        if index == 0 {
            &mut self.constant
        } else if index <= public.len() {
            &mut public[index - 1]
        } else {
            &mut private[index - 1 - public.len()]
        }
    }
}

/// [`ConstraintSystemExt`] wraps a `ConstraintSystemRef` with compile-time
/// flags that control whether constraint matrices (`ARITH_ENABLED`) and / or
/// assignment vectors (`ASSIGNMENTS_ENABLED`) are collected during synthesis.
pub struct ConstraintSystemExt<F: Field, const ARITH_ENABLED: bool, const ASSIGNMENTS_ENABLED: bool>
{
    cs: ConstraintSystemRef<F>,
}

impl<F: Field, const ARITH_ENABLED: bool, const ASSIGNMENTS_ENABLED: bool> Deref
    for ConstraintSystemExt<F, ARITH_ENABLED, ASSIGNMENTS_ENABLED>
{
    type Target = ConstraintSystemRef<F>;

    fn deref(&self) -> &Self::Target {
        &self.cs
    }
}

impl<F: Field, const ARITH_ENABLED: bool, const ASSIGNMENTS_ENABLED: bool>
    ConstraintSystemExt<F, ARITH_ENABLED, ASSIGNMENTS_ENABLED>
{
    /// [`ConstraintSystemExt::new`] creates a new constraint system wrapper
    /// with the specified flags.
    pub fn new() -> Self {
        let cs = ConstraintSystem::<F>::new_ref();
        let mode = if ASSIGNMENTS_ENABLED {
            SynthesisMode::Prove {
                construct_matrices: ARITH_ENABLED,
                generate_lc_assignments: ARITH_ENABLED,
            }
        } else {
            SynthesisMode::Setup
        };
        cs.set_mode(mode);
        Self { cs }
    }

    /// [`ConstraintSystemExt::execute_synthesizer`] executes a circuit inside
    /// the constraint system, where the circuit should implement the
    /// [`ConstraintSynthesizer`] trait.
    pub fn execute_synthesizer(
        &self,
        circuit: impl ConstraintSynthesizer<F>,
    ) -> Result<(), SynthesisError> {
        self.execute_fn(|cs| circuit.generate_constraints(cs))
    }

    /// [`ConstraintSystemExt::execute_fn`] executes a circuit inside the
    /// constraint system, where the circuit should be defined as a closure that
    /// takes as input a `ConstraintSystemRef` and returns a result of type `R`.
    /// The return value of the closure will be returned by this method.
    pub fn execute_fn<R>(
        &self,
        circuit: impl FnOnce(ConstraintSystemRef<F>) -> Result<R, SynthesisError>,
    ) -> Result<R, SynthesisError> {
        let result = circuit(self.cs.clone())?;
        if ARITH_ENABLED {
            self.cs.finalize();
        }
        Ok(result)
    }
}

impl<F: Field, const ARITH_ENABLED: bool, const ASSIGNMENTS_ENABLED: bool> Default
    for ConstraintSystemExt<F, ARITH_ENABLED, ASSIGNMENTS_ENABLED>
{
    fn default() -> Self {
        Self::new()
    }
}

/// [`ArithExtractor`] collects only the constraint matrices (no assignments)
/// from a synthesized circuit.
pub type ArithExtractor<F> = ConstraintSystemExt<F, true, false>;
/// [`AssignmentsExtractor`] collects only the assignments (no constraint
/// matrices) from a synthesized circuit.
pub type AssignmentsExtractor<F> = ConstraintSystemExt<F, false, true>;

impl<F: Field> ArithExtractor<F> {
    /// [`ArithExtractor::arith`] extracts the constraint matrices from the
    /// circuit and returns them as an arithmetization / constraint system
    /// structure of type `A`.
    pub fn arith<A: From<ConstraintSystem<F>>>(self) -> Result<A, SynthesisError> {
        Ok(self.cs.into_inner().unwrap().into())
    }
}

impl<F: Field> AssignmentsExtractor<F> {
    /// [`AssignmentsExtractor::assignments`] extracts the assignments from the
    /// circuit and returns them as `Assignments`.
    pub fn assignments(self) -> Result<Assignments<F, Vec<F>>, SynthesisError> {
        let witness = self.cs.witness_assignment()?.to_vec();
        // skip the first element which is '1'
        let instance = self.cs.instance_assignment()?[1..].to_vec();

        Ok((F::one(), instance, witness).into())
    }
}

/// [`WitnessToPublic`] defines a helper trait for marking witness variables as
/// public inputs in the constraint system.
pub trait WitnessToPublic {
    /// [`WitnessToPublic::mark_as_public`] marks a witness variable as public.
    fn mark_as_public(&self) -> Result<(), SynthesisError>;
}

impl<T: WitnessToPublic> WitnessToPublic for [T] {
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        self.iter().try_for_each(|x| x.mark_as_public())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_relations::gr1cs::ConstraintSynthesizer;
    use ark_std::{error::Error, rand::thread_rng};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::{
        utils::{CircuitForTest, constraints_for_test, satisfying_assignments_for_test},
        *,
    };
    use crate::arithmetizations::r1cs::R1CS;

    #[test]
    fn test_satisfiability() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let circuit = CircuitForTest::<Fr> {
            x: Fr::rand(&mut rng),
        };
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone())?;
        assert!(cs.is_satisfied()?);

        Ok(())
    }

    #[test]
    fn test_constraint_extraction() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let circuit = CircuitForTest::<Fr> {
            x: Fr::rand(&mut rng),
        };
        let cs = ArithExtractor::new();
        cs.execute_synthesizer(circuit)?;
        assert_eq!(cs.arith::<R1CS<_>>()?, constraints_for_test());
        Ok(())
    }

    #[test]
    fn test_witness_extraction() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let x = Fr::rand(&mut rng);
        let circuit = CircuitForTest::<Fr> { x };

        let cs = AssignmentsExtractor::new();
        cs.execute_synthesizer(circuit)?;
        assert_eq!(cs.assignments()?, satisfying_assignments_for_test(x));
        Ok(())
    }
}
