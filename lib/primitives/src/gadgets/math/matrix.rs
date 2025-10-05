use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::{fp::FpVar, FieldVar},
    GR1CSVar,
};
use ark_relations::gr1cs::{Matrix, Namespace, SynthesisError};
use ark_std::borrow::Borrow;

use std::ops::Index;

pub trait MatrixGadget<FV> {
    fn mul_vector(&self, v: &impl Index<usize, Output = FV>) -> Result<Vec<FV>, SynthesisError>;
}

// same format as the native SparseMatrix (which follows ark_relations::gr1cs::Matrix format)
#[derive(Debug, Clone)]
pub struct SparseMatrixVar<FV>(pub Vec<Vec<(FV, usize)>>);

impl<F: PrimeField, CF: PrimeField, FV: AllocVar<F, CF>> AllocVar<Matrix<F>, CF>
    for SparseMatrixVar<FV>
{
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
        Ok(self
            .0
            .iter()
            .map(|row| {
                let products = row
                    .iter()
                    .map(|(value, col_i)| value * &v[*col_i])
                    .collect::<Vec<_>>();
                if products.is_constant() {
                    FpVar::constant(products.value().unwrap_or_default().into_iter().sum())
                } else {
                    products.iter().sum()
                }
            })
            .collect())
    }
}
