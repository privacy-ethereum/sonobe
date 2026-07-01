//! This module provides algebraic abstractions used across Sonobe, including
//! field and group type enhancements, in-circuit (both canonical and emulated)
//! variables, and common algebraic operations.

use ark_ff::PrimeField;
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};

use crate::algebra::field::SonobeField;

pub mod field;
pub mod group;
pub mod ops;

/// [`Val`] associates a type with its in-circuit variables.
pub trait Val {
    /// [`Val::PreferredConstraintField`] is the preferred constraint field for
    /// expressing `Self` in-circuit.
    type PreferredConstraintField: PrimeField;

    /// [`Val::Var`] is the *canonical* in-circuit variable.
    ///
    /// In this case, the circuit is defined over the preferred constraint field
    /// and can represent `Self` directly (i.e., without emulation).
    type Var: AllocVar<Self, Self::PreferredConstraintField>
        + GR1CSVar<Self::PreferredConstraintField, Value = Self>;

    /// [`Val::EmulatedVar`] is the *emulated* in-circuit variable.
    ///
    /// In this case, the circuit is defined over an arbitrary field `F` which
    /// may differ from the preferred constraint field, and `Self` is
    /// represented in-circuit via emulation.
    type EmulatedVar<F: SonobeField>: AllocVar<Self, F> + GR1CSVar<F, Value = Self>;
}
