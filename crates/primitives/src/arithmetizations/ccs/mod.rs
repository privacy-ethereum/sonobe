//! This module implements the Customizable Constraint System (CCS) and its
//! relation checks against plain witnesses and instances.
//!
//! Proposed in the CCS [paper], it is a generalization of R1CS as well as many
//! other constraint systems.
//! A CCS structure is defined by the following components:
//! - The number of constraints `m`, the number of variables `n`, and the number
//!   of public inputs `l`.
//! - The degree `d`.
//! - A sequence of `t` matrices `M`.
//! - A sequence of `q` multisets `S`, where each multiset `S_i` has at most `d`
//!   elements and each element is an index in `[0, t - 1]` pointing to a matrix
//!   `M_j`.
//! - A sequence of `q` coefficients `c`.
//!
//! A vector of assignments `z` satisfies the CCS if its evaluation
//! `Σ_{i ∈ {0, q-1}} (c_i · 〇_{j ∈ S_i} (M_j · z))` is zero, where `〇` denotes
//! the Hadamard product among all `M_j · z`.
//!
//! [paper]: https://eprint.iacr.org/2023/552.pdf

use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_relations::gr1cs::{ConstraintSystem, Matrix, SynthesisError};
use ark_std::{cfg_into_iter, cfg_iter, ops::Index};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{Arith, Error};
use crate::{
    algebra::{
        field::TwoStageFieldVar,
        ops::{matrix::SparseMatrixVar, poly::MLEHelper, vector::VectorMulGadget},
    },
    circuits::Assignments,
};

/// [`CCS`] is an abstract trait that defines the behavior of all CCS variants,
/// including but not limited to R1CS.
pub trait CCS:
    Arith + for<'a> From<&'a ConstraintSystem<Self::Field>> + From<ConstraintSystem<Self::Field>>
{
    /// [`CCS::matrices`] returns the matrices contained in a concrete CCS
    /// instance `self`.
    fn matrices(&self) -> &[Matrix<Self::Field>];

    fn multisets() -> Vec<Vec<usize>>;

    fn coefficients() -> Vec<Self::Field>;

    /// [`CCS::evaluate_ccs`] evaluates the CCS relation at a given vector of
    /// assignments, multisets, and coefficients.
    fn evaluate_ccs<const Q: usize>(
        &self,
        z: Assignments<Self::Field, impl AsRef<[Self::Field]> + Sync>,
        multisets: [Vec<usize>; Q],
        coefficients: [Self::Field; Q],
    ) -> Result<Vec<Self::Field>, Error> {
        let cfg = self.config();
        let matrices = self.matrices();

        let public_len = z.public.as_ref().len();
        let private_len = z.private.as_ref().len();
        if public_len != cfg.n_public_inputs {
            return Err(Error::MalformedAssignments(format!(
                "The number of public inputs in R1CS ({}) does not match the length of the provided public inputs ({}).",
                cfg.n_public_inputs, public_len
            )));
        }
        if private_len != cfg.n_witnesses {
            return Err(Error::MalformedAssignments(format!(
                "The number of witnesses in R1CS ({}) does not match the length of the provided witnesses ({}).",
                cfg.n_witnesses, private_len
            )));
        }

        // Recall that the evaluation of CCS at z is defined as:
        // `Σ_{i ∈ {0, q-1}} (c_i · 〇_{j ∈ S_i} (M_j · z))`,
        // where $\prod$ denotes the Hadamard product.
        //
        // Below, we manually expand the vector and matrix operations for less
        // allocations and better efficiency.
        // Specifically, we independently compute each entry of the resulting
        // vector, and collect them at the end.
        // We parallelize the outer loop over rows (when the `parallel` feature
        // is enabled), since the number of constraints in the CCS is typically
        // large in practice.
        Ok(cfg_into_iter!(0..cfg.n_constraints)
            .map(|row| {
                // The `row`-th entry of the resulting vector is:
                // `Σ_{i ∈ {0, q-1}} (c_i · 〇_{j ∈ S_i} (M_j[row] · z))`
                multisets
                    .iter()
                    .zip(coefficients)
                    .map(|(s, c)| {
                        // Each term in the sum is:
                        // `c_i · 〇_{j ∈ S_i} (M_j[row] · z)`
                        c * s
                            .iter()
                            .map(|&i| {
                                // Each factor in the product is `M_j[row] · z`,
                                // i.e., the dot product of `M_j[row]` and `z`.
                                matrices[i][row]
                                    .iter()
                                    .map(|(val, col)| z[*col] * val)
                                    .sum::<Self::Field>()
                            })
                            .product::<Self::Field>()
                    })
                    .sum()
            })
            .collect())
    }

    /// [`CCS::mles`] returns the multilinear extensions of all CCS matrices
    /// `M_i` evaluated over the assignments `z`.
    fn mles(
        &self,
        z: Assignments<Self::Field, impl AsRef<[Self::Field]> + Sync>,
    ) -> Vec<DenseMultilinearExtension<Self::Field>> {
        self.matrices()
            .iter()
            .map(|matrix| {
                DenseMultilinearExtension::from_evaluations(
                    &cfg_iter!(matrix)
                        .map(|row| row.iter().map(|(val, col)| z[*col] * val).sum())
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }
}

pub trait CCSGadget {
    type FieldVar: TwoStageFieldVar;

    /// [`CCS::matrices`] returns the matrices contained in a concrete CCS
    /// instance `self`.
    fn matrices(&self) -> &[SparseMatrixVar<Self::FieldVar>];

    /// [`CCS::evaluate_ccs`] evaluates the CCS relation at a given vector of
    /// assignments, multisets, and coefficients.
    fn evaluate_ccs<A: Index<usize, Output = Self::FieldVar>, const Q: usize>(
        &self,
        z: A,
        multisets: [Vec<usize>; Q],
        coefficients: [impl Clone + Into<<Self::FieldVar as TwoStageFieldVar>::Intermediate>; Q],
    ) -> Result<Vec<<Self::FieldVar as TwoStageFieldVar>::Intermediate>, SynthesisError>
    where
        [(Self::FieldVar, usize)]:
            VectorMulGadget<A, Output = <Self::FieldVar as TwoStageFieldVar>::Intermediate>,
    {
        let matrices = self.matrices();

        // Recall that the evaluation of CCS at z is defined as:
        // `Σ_{i ∈ {0, q-1}} (c_i · 〇_{j ∈ S_i} (M_j · z))`,
        // where $\prod$ denotes the Hadamard product.
        (0..matrices[0].0.len())
            .map(|row| {
                // The `row`-th entry of the resulting vector is:
                // `Σ_{i ∈ {0, q-1}} (c_i · 〇_{j ∈ S_i} (M_j[row] · z))`
                let mut sum = None;

                for (s, c) in multisets.iter().zip(&coefficients) {
                    // Each term in the sum is:
                    // `c_i · 〇_{j ∈ S_i} (M_j[row] · z)`
                    let mut prod = c.clone().into();
                    for i in s {
                        prod = prod * matrices[*i].0[row].mul(&z)?;
                    }
                    sum = match sum {
                        Some(sum) => Some(sum + prod),
                        None => Some(prod),
                    };
                }
                Ok(sum.unwrap())
            })
            .collect()
    }
}
