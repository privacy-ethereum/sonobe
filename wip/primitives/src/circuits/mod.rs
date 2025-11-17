use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode,
};
use ark_std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Index, IndexMut},
};

pub mod utils;

/// FCircuit defines the trait of the circuit of the F function, which is the one being folded (ie.
/// inside the agmented F' function).
/// The parameter z_i denotes the current state, and z_{i+1} denotes the next state after applying
/// the step.
/// Note that the external inputs for the specific circuit are defined at the implementation of
/// both `FCircuit::ExternalInputs` and `FCircuit::ExternalInputsVar`, where the `Default` trait
/// implementation for the `ExternalInputs` returns the initialized data structure (ie. if the type
/// contains a vector, it is initialized at the expected length).
pub trait FCircuit {
    type Field: PrimeField;
    type ExternalInputs;

    fn dummy_external_inputs(&self) -> Self::ExternalInputs;

    /// returns the number of elements in the state of the FCircuit, which corresponds to the
    /// FCircuit inputs.
    fn state_len(&self) -> usize;

    /// generates the constraints for the step of F for the given z_i
    fn generate_step_constraints(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        cs: ConstraintSystemRef<Self::Field>,
        i: FpVar<Self::Field>,
        z_i: Vec<FpVar<Self::Field>>,
        external_inputs: Self::ExternalInputs, // inputs that are not part of the state
    ) -> Result<Vec<FpVar<Self::Field>>, SynthesisError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Assignments<F, V> {
    pub constant: F,
    pub public: V,
    pub private: V,
}

pub type AssignmentsOwned<F> = Assignments<F, Vec<F>>;
pub type AssignmentsRef<'a, F> = Assignments<F, &'a [F]>;

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

pub struct ConstraintSystemBuilder<F, C> {
    _f: PhantomData<F>,
    mode: SynthesisMode,
    circuit: C,
}

impl ConstraintSystemBuilder<(), ()> {
    pub fn new() -> Self {
        Self {
            _f: PhantomData,
            mode: SynthesisMode::Prove {
                construct_matrices: true,
                generate_lc_assignments: true,
            },
            circuit: (),
        }
    }
}

impl Default for ConstraintSystemBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<X, Y> ConstraintSystemBuilder<X, Y> {
    pub fn with_setup_mode(self) -> Self {
        Self {
            _f: PhantomData,
            mode: SynthesisMode::Setup,
            circuit: self.circuit,
        }
    }

    pub fn with_prove_mode(self) -> Self {
        Self {
            _f: PhantomData,
            mode: SynthesisMode::Prove {
                construct_matrices: true,
                generate_lc_assignments: true,
            },
            circuit: self.circuit,
        }
    }

    pub fn with_circuit<F: Field, C: ConstraintSynthesizer<F>>(
        self,
        circuit: C,
    ) -> ConstraintSystemBuilder<F, C> {
        ConstraintSystemBuilder {
            _f: PhantomData,
            mode: self.mode,
            circuit,
        }
    }
}

impl<F: Field, C: ConstraintSynthesizer<F>> ConstraintSystemBuilder<F, C> {
    pub fn synthesize(self) -> Result<ConstraintSystem<F>, SynthesisError> {
        let cs = ConstraintSystem::<F>::new_ref();
        cs.set_mode(self.mode);
        self.circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        Ok(cs.into_inner().unwrap())
    }
}

pub trait ConstraintSystemExt<F> {
    fn assignments(&self) -> Result<Assignments<F, Vec<F>>, SynthesisError>;
}

impl<F: Field> ConstraintSystemExt<F> for ConstraintSystem<F> {
    fn assignments(&self) -> Result<Assignments<F, Vec<F>>, SynthesisError> {
        let witness = self.witness_assignment()?.to_vec();
        // skip the first element which is '1'
        let instance = self.instance_assignment()?[1..].to_vec();

        Ok((F::one(), instance, witness).into())
    }
}
