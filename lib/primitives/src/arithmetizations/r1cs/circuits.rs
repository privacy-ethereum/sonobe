use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, marker::PhantomData, One};

use crate::{
    arithmetizations::ArithRelationGadget,
    circuits::Assignments,
    gadgets::math::{
        eq::EquivalenceGadget,
        matrix::{MatrixGadget, SparseMatrixVar},
        vector::VectorGadget,
    },
};

use super::R1CS;

/// An in-circuit representation of the `R1CS` struct.
///
/// `M` is for the modulo operation involved in the satisfiability check when
/// the underlying `FVar` is `NonNativeUintVar`.
#[derive(Debug, Clone)]
pub struct R1CSMatricesVar<M, FVar> {
    _m: PhantomData<M>,
    pub A: SparseMatrixVar<FVar>,
    pub B: SparseMatrixVar<FVar>,
    pub C: SparseMatrixVar<FVar>,
}

impl<F: PrimeField, ConstraintF: PrimeField, FVar: AllocVar<F, ConstraintF>>
    AllocVar<R1CS<F>, ConstraintF> for R1CSMatricesVar<F, FVar>
{
    fn new_variable<T: Borrow<R1CS<F>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            Ok(Self {
                _m: PhantomData,
                A: SparseMatrixVar::<FVar>::new_constant(cs.clone(), &val.borrow().A)?,
                B: SparseMatrixVar::<FVar>::new_constant(cs.clone(), &val.borrow().B)?,
                C: SparseMatrixVar::<FVar>::new_constant(cs.clone(), &val.borrow().C)?,
            })
        })
    }
}

impl<M, FVar> R1CSMatricesVar<M, FVar>
where
    SparseMatrixVar<FVar>: MatrixGadget<FVar>,
    [FVar]: VectorGadget<FVar>,
{
    pub fn eval_assignments(
        &self,
        z: Assignments<FVar, impl AsRef<[FVar]>>,
    ) -> Result<(Vec<FVar>, Vec<FVar>), SynthesisError> {
        // Multiply Cz by z[0] (u) here, allowing this method to be reused for
        // both relaxed and unrelaxed R1CS.
        let Az = self.A.mul_vector(&z)?;
        let Bz = self.B.mul_vector(&z)?;
        let Cz = self.C.mul_vector(&z)?;
        let uCz = Cz.scale(&z[0])?;
        let AzBz = Az.hadamard(&Bz)?;
        Ok((AzBz, uCz))
    }
}

impl<M, FVar, WVar: AsRef<[FVar]>, UVar: AsRef<[FVar]>> ArithRelationGadget<WVar, UVar>
    for R1CSMatricesVar<M, FVar>
where
    SparseMatrixVar<FVar>: MatrixGadget<FVar>,
    [FVar]: VectorGadget<FVar> + EquivalenceGadget<M>,
    FVar: Clone + One,
{
    /// Evaluation is a tuple of two vectors (`AzBz` and `uCz`) instead of a
    /// single vector `AzBz - uCz`, because subtraction is not supported for
    /// `FVar = NonNativeUintVar`.
    type Evaluation = (Vec<FVar>, Vec<FVar>);

    fn eval_relation(&self, w: &WVar, u: &UVar) -> Result<Self::Evaluation, SynthesisError> {
        self.eval_assignments((FVar::one(), u.as_ref(), w.as_ref()).into())
    }

    fn enforce_evaluation(
        _w: &WVar,
        _u: &UVar,
        (lhs, rhs): Self::Evaluation,
    ) -> Result<(), SynthesisError> {
        lhs.enforce_equivalent(&rhs)
    }
}

// TODO: add back tests
