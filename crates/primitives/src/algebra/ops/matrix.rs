//! This module defines in-circuit sparse matrix types and implements operations
//! over them.

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::gr1cs::{Matrix, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, ops::Index};

use crate::algebra::ops::vector::VectorMulGadget;

/// [`MatrixGadget`] defines operations on in-circuit matrix variables.
pub trait MatrixGadget<FV> {
    /// [`MatrixGadget::mul_vector`] computes the product of `self` and a column
    /// vector `v`.
    fn mul_vector(&self, v: &impl Index<usize, Output = FV>) -> Result<Vec<FV>, SynthesisError>;
}

/// [`SparseMatrixVar`] is a sparse matrix represented as a vector of rows,
/// where each row is a vector of `(value, column_index)` pairs.
///
/// This follows the same format as [`ark_relations::gr1cs::Matrix`].
#[derive(Debug, Clone)]
pub struct SparseMatrixVar<FV>(pub Vec<Vec<(FV, usize)>>);

impl<F: Field, CF: Field, FV: AllocVar<F, CF>> AllocVar<Matrix<F>, CF> for SparseMatrixVar<FV> {
    fn new_variable<T: Borrow<Matrix<F>>>(
        cs: impl Into<Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            let mut coeffs: Vec<Vec<(FV, usize)>> = Vec::new();
            for row in val.borrow().iter() {
                coeffs.push(
                    row.iter()
                        .map(|&(value, col)| {
                            Ok((FV::new_variable(cs.clone(), || Ok(value), mode)?, col))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }

            Ok(Self(coeffs))
        })
    }
}

impl<F: PrimeField> MatrixGadget<FpVar<F>> for SparseMatrixVar<FpVar<F>> {
    fn mul_vector(
        &self,
        v: &impl Index<usize, Output = FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.0.iter().map(|row| row.mul(v)).collect()
    }
}
