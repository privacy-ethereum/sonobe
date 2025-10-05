use ark_ff::Field;
use ark_relations::gr1cs::Matrix;
use ark_std::{cfg_into_iter, log2};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::arithmetizations::{Assignments, Error};

use super::{r1cs::R1CS, Arith, ArithRelation, ArithSerializer};

pub mod circuits;

/// CCS represents the Customizable Constraint Systems structure defined in
/// the [CCS paper](https://eprint.iacr.org/2023/552)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CCS<F: Field> {
    /// m: number of rows in M_i (such that M_i \in F^{m, n})
    m: usize,
    /// n = |z|, number of cols in M_i
    n: usize,
    /// l = |io|, size of public input/output
    l: usize,
    /// t = |M|, number of matrices
    pub t: usize,
    /// q = |c| = |S|, number of multisets
    q: usize,
    /// d: max degree in each variable
    d: usize,
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
    pub fn eval_at_z(&self, z: Assignments<F>) -> Result<Vec<F>, Error> {
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

impl<F: Field, W: AsRef<[F]>, U: AsRef<[F]>> ArithRelation<W, U> for CCS<F> {
    type Evaluation = Vec<F>;

    fn eval_relation(&self, w: &W, u: &U) -> Result<Self::Evaluation, Error> {
        self.eval_at_z((F::one(), u.as_ref(), w.as_ref()).into())
    }

    fn check_evaluation(_w: &W, _u: &U, e: Self::Evaluation) -> Result<(), Error> {
        cfg_into_iter!(e)
            .all(|i| i.is_zero())
            .then_some(())
            .ok_or(Error::UnsatisfiedAssignments(
                "Evaluation contains non-zero values".into(),
            ))
    }
}

impl<F: Field> ArithSerializer for CCS<F> {
    fn params_to_le_bytes(&self) -> Vec<u8> {
        [
            self.l.to_le_bytes(),
            self.m.to_le_bytes(),
            self.n.to_le_bytes(),
            self.t.to_le_bytes(),
            self.q.to_le_bytes(),
            self.d.to_le_bytes(),
        ]
        .concat()
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
            q: 2,
            d: r1cs.degree(),

            S: vec![vec![0, 1], vec![2]],
            c: vec![F::one(), F::one().neg()],
            M: vec![r1cs.A, r1cs.B, r1cs.C],
        }
    }
}

// TODO: add back tests