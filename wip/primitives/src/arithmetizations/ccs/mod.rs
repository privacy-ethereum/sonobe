use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_relations::gr1cs::Matrix;
use ark_std::{cfg_into_iter, cfg_iter, log2};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{r1cs::R1CS, Arith, ArithRelation, Error};
use crate::{arithmetizations::ArithConfig, circuits::Assignments};

pub mod circuits;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CCSConfig<F> {
    /// m: number of rows in M_i (such that M_i \in F^{m, n})
    m: usize,
    /// n = |z|, number of cols in M_i
    n: usize,
    /// l = |io|, size of public input/output
    l: usize,
    /// d: max degree in each variable
    d: usize,
    /// t = |M|, number of matrices
    pub t: usize,
    /// vector of multisets
    pub S: Vec<Vec<usize>>,
    /// vector of coefficients
    pub c: Vec<F>,
}

impl<F: Clone> ArithConfig for CCSConfig<F> {
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

/// CCS represents the Customizable Constraint Systems structure defined in
/// the [CCS paper](https://eprint.iacr.org/2023/552)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CCS<F: Field> {
    cfg: CCSConfig<F>,

    /// vector of matrices
    pub M: Vec<Matrix<F>>,
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
        // is enabled), since the number of constraints in the CCS is typically
        // large in practice.
        Ok(cfg_into_iter!(0..self.n_constraints())
            .map(|row| {
                // The row-th entry of the resulting vector is:
                // $\sum_{j=0}^{q - 1} (c_j * \prod_{i \in S_j} (M_i[row] * z))$
                self.cfg
                    .S
                    .iter()
                    .zip(&self.cfg.c)
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

    fn mle(
        &self,
        i: usize,
        z: Assignments<F, impl AsRef<[F]> + Sync>,
    ) -> DenseMultilinearExtension<F> {
        let s = log2(self.n_constraints()) as usize;
        DenseMultilinearExtension {
            num_vars: s,
            evaluations: cfg_iter!(self.M[i])
                .map(|row| row.iter().map(|(val, col)| z[*col] * val).sum())
                .chain(vec![F::zero(); (1 << s) - self.n_constraints()])
                .collect(),
        }
    }

    pub fn mles(
        &self,
        z: Assignments<F, impl AsRef<[F]> + Sync>,
    ) -> Vec<DenseMultilinearExtension<F>> {
        let s = log2(self.n_constraints()) as usize;
        (0..self.cfg.t).map(|i| DenseMultilinearExtension {
            num_vars: s,
            evaluations: cfg_iter!(self.M[i])
                .map(|row| row.iter().map(|(val, col)| z[*col] * val).sum())
                .chain(vec![F::zero(); (1 << s) - self.n_constraints()])
                .collect(),
        }).collect()
    }
}

impl<F: Field> Arith for CCS<F> {
    type Config = CCSConfig<F>;

    #[inline]
    fn config(&self) -> &Self::Config {
        &self.cfg
    }
}

impl<F: Field, W: AsRef<[F]>, U: AsRef<[F]>> ArithRelation<W, U> for CCS<F> {
    type Evaluation = Vec<F>;

    fn eval_relation(&self, w: &W, u: &U) -> Result<Self::Evaluation, Error> {
        self.eval_assignments((F::one(), u.as_ref(), w.as_ref()).into())
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

impl<F: Field> From<R1CS<F>> for CCS<F> {
    fn from(r1cs: R1CS<F>) -> Self {
        let m = r1cs.n_constraints();
        let n = r1cs.n_variables();
        CCS {
            cfg: CCSConfig {
                m,
                n,
                l: r1cs.n_public_inputs(),
                t: 3,
                d: r1cs.degree(),
                S: vec![vec![0, 1], vec![2]],
                c: vec![F::one(), F::one().neg()],
            },
            M: vec![r1cs.A, r1cs.B, r1cs.C],
        }
    }
}

// TODO: add back tests
