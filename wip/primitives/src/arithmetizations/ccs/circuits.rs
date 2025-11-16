use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;

use super::{CCSVariant, CCS};
use crate::algebra::ops::matrix::SparseMatrixVar;

/// CCSMatricesVar contains the matrices 'M' of the CCS without the rest of CCS parameters.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct CCSMatricesVar<F: PrimeField> {
    // we only need native representation, so the constraint field==F
    pub M: Vec<SparseMatrixVar<FpVar<F>>>,
}

impl<F: PrimeField, V: CCSVariant> AllocVar<CCS<F, V>, F> for CCSMatricesVar<F> {
    fn new_variable<T: Borrow<CCS<F, V>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            Ok(Self {
                M: val
                    .borrow()
                    .M
                    .iter()
                    .map(|m| SparseMatrixVar::new_constant(cs.clone(), m))
                    .collect::<Result<_, _>>()?,
            })
        })
    }
}
