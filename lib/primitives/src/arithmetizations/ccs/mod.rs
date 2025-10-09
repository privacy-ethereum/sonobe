use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_relations::gr1cs::Matrix;
use ark_std::{cfg_into_iter, log2};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::circuits::Assignments;

use super::{r1cs::R1CS, Arith, ArithRelation, Error};

pub mod circuits;

/// CCS represents the Customizable Constraint Systems structure defined in
/// the [CCS paper](https://eprint.iacr.org/2023/552)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CCS<F: Field> {
    /// m: number of rows in M_i (such that M_i \in F^{m, n})
    pub m: usize,
    /// n = |z|, number of cols in M_i
    pub n: usize,
    /// l = |io|, size of public input/output
    pub l: usize,
    /// t = |M|, number of matrices
    pub t: usize,
    /// d: max degree in each variable
    pub d: usize,
    /// s = log(m), dimension of x
    pub s: usize,

    /// vector of matrices
    pub M: Vec<Matrix<F>>,
    /// vector of multisets
    pub S: Vec<Vec<usize>>,
    /// vector of coefficients
    pub c: Vec<F>,
}

impl<F: Field> CCS<F> {
    /// Evaluates the CCS relation at a given vector of assignments `z`
    pub fn eval_assignments(
        &self,
        z: Assignments<F, impl AsRef<[F]> + Sync>,
    ) -> Result<Vec<F>, Error> {
        let public_len = z.public.as_ref().len();
        let private_len = z.private.as_ref().len();
        if public_len != self.n_public_inputs() {
            return Err(Error::MalformedAssignments(
                format!("The number of public inputs in R1CS ({}) does not match the length of the provided public inputs ({}).", self.n_public_inputs(), public_len)
            ));
        }
        if private_len != self.n_witnesses() {
            return Err(Error::MalformedAssignments(
                format!("The number of witnesses in R1CS ({}) does not match the length of the provided witnesses ({}).", self.n_witnesses(), private_len)
            ));
        }

        // Recall that the evaluation of CCS at z is defined as:
        // $\sum_{j=0}^{q - 1} (c_j * \prod_{i \in S_j} (M_i * z))$,
        // where $\prod$ denotes the Hadamard product.
        //
        // Below, we manually expand the vector and matrix operations for less
        // allocations and better efficiency.
        // Specifically, we independently compute each entry of the resulting
        // vector, and collect them at the end.
        // We parallelize the outer loop over rows (when the `parallel` feature
        // is enabled), because `m`, the number of constraints in the CCS, is
        // typically large in practice.
        Ok(cfg_into_iter!(0..self.m)
            .map(|row| {
                // The row-th entry of the resulting vector is:
                // $\sum_{j=0}^{q - 1} (c_j * \prod_{i \in S_j} (M_i[row] * z))$
                self.S
                    .iter()
                    .zip(&self.c)
                    .map(|(s, &c)| {
                        // Each term in the sum is:
                        // $c_j * \prod_{i \in S_j} (M_i[row] * z)$
                        c * s
                            .iter()
                            .map(|&i| {
                                // Each factor in the product is $M_i[row] * z$,
                                // i.e., the dot product of $M_i[row]$ and $z$.
                                self.M[i][row]
                                    .iter()
                                    .map(|(val, col)| z[*col] * val)
                                    .sum::<F>()
                            })
                            .product::<F>()
                    })
                    .sum()
            })
            .collect())
    }

    pub fn mle(
        &self,
        i: usize,
        z: Assignments<F, impl AsRef<[F]>>,
    ) -> DenseMultilinearExtension<F> {
        DenseMultilinearExtension {
            num_vars: self.s,
            evaluations: self.M[i]
                .iter()
                .map(|row| row.iter().map(|(val, col)| z[*col] * val).sum())
                .chain(vec![F::zero(); (1 << self.s) - self.m])
                .collect(),
        }
    }
}

impl<F: Field> Arith for CCS<F> {
    #[inline]
    fn degree(&self) -> usize {
        self.d
    }

    #[inline]
    fn n_constraints(&self) -> usize {
        self.m
    }

    #[inline]
    fn n_variables(&self) -> usize {
        self.n
    }

    #[inline]
    fn n_public_inputs(&self) -> usize {
        self.l
    }

    #[inline]
    fn n_witnesses(&self) -> usize {
        self.n_variables() - self.n_public_inputs() - 1
    }
}

impl<F: Field> ArithRelation<Vec<F>, Vec<F>> for CCS<F> {
    type Evaluation = Vec<F>;

    fn eval_relation(&self, w: &[F], u: &[F]) -> Result<Self::Evaluation, Error> {
        self.eval_assignments((F::one(), u, w).into())
    }

    fn check_evaluation(_w: &[F], _u: &[F], e: Self::Evaluation) -> Result<(), Error> {
        cfg_into_iter!(e)
            .all(|i| i.is_zero())
            .then_some(())
            .ok_or(Error::UnsatisfiedAssignments(
                "Evaluation contains non-zero values".into(),
            ))
    }
}

impl<F: Field> From<R1CS<F>> for CCS<F> {
    fn from(r1cs: R1CS<F>) -> Self {
        let m = r1cs.n_constraints();
        let n = r1cs.n_variables();
        CCS {
            m,
            n,
            l: r1cs.n_public_inputs(),
            s: log2(m) as usize,
            t: 3,
            d: r1cs.degree(),

            S: vec![vec![0, 1], vec![2]],
            c: vec![F::one(), F::one().neg()],
            M: vec![r1cs.A, r1cs.B, r1cs.C],
        }
    }
}

// TODO: add back tests
