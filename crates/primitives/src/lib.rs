#![warn(missing_docs)]

//! This crate provides the foundational primitives used throughout Sonobe's
//! folding scheme and IVC implementations.
//!
//! It includes algebraic abstractions (fields, groups, and their in-circuit
//! emulated counterparts), constraint system arithmetizations (R1CS, CCS),
//! commitment schemes, transcript/sponge constructions, sum-check protocols,
//! and various utility types.

pub mod algebra;
pub mod arithmetizations;
pub mod circuits;
pub mod commitments;
pub mod relations;
pub mod transcripts;
pub mod utils;
