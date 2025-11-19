use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_relations::gr1cs::{ConstraintSystem, Matrix};
use ark_std::{borrow::Borrow, cfg_into_iter, cfg_iter, fmt::Debug, marker::PhantomData};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{r1cs::R1CS, Arith, ArithRelation, Error};
use crate::{
    algebra::ops::poly::MLEHelper,
    arithmetizations::{r1cs::R1CSConfig, ArithConfig},
    circuits::Assignments,
};

pub mod circuits;

pub trait CCSVariant: Clone + Debug + PartialEq + Default + Sync {
    fn n_matrices() -> usize;

    fn degree() -> usize;

    fn multisets_vec() -> Vec<Vec<usize>>;

    fn coefficients_vec<F: Field>() -> Vec<F>;
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CCSConfig<V: CCSVariant> {
    _v: PhantomData<V>,
    /// m: number of rows in M_i (such that M_i \in F^{m, n})
    m: usize,
    /// n = |z|, number of cols in M_i
    n: usize,
    /// l = |io|, size of public input/output
    l: usize,
}

impl<V: CCSVariant> ArithConfig for CCSConfig<V> {
    #[inline]
    fn degree(&self) -> usize {
        V::degree()
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

    #[inline]
    fn set_n_public_inputs(&mut self, l: usize) {
        self.l = l;
    }
}

impl<Cfg: Borrow<R1CSConfig>, V: CCSVariant> From<Cfg> for CCSConfig<V> {
    fn from(cfg: Cfg) -> Self {
        let cfg = cfg.borrow();
        Self {
            _v: PhantomData,
            m: cfg.n_constraints(),
            n: cfg.n_variables(),
            l: cfg.n_public_inputs(),
        }
    }
}

impl<F: Field, V: CCSVariant> From<&ConstraintSystem<F>> for CCSConfig<V> {
    fn from(cs: &ConstraintSystem<F>) -> Self {
        R1CSConfig::from(cs).into()
    }
}

/// CCS represents the Customizable Constraint Systems structure defined in
/// the [CCS paper](https://eprint.iacr.org/2023/552)
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct CCS<F: Field, V: CCSVariant> {
    cfg: CCSConfig<V>,

    /// vector of matrices
    pub M: Vec<Matrix<F>>,
}

impl<F: Field, V: CCSVariant> CCS<F, V> {
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

        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<F>();

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
                S.iter()
                    .zip(c)
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

    pub fn mles(
        &self,
        z: Assignments<F, impl AsRef<[F]> + Sync>,
    ) -> Vec<DenseMultilinearExtension<F>> {
        (0..V::n_matrices())
            .map(|i| {
                DenseMultilinearExtension::from_evaluations(
                    &cfg_iter!(self.M[i])
                        .map(|row| row.iter().map(|(val, col)| z[*col] * val).sum())
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }
}

impl<F: Field, V: CCSVariant> Default for CCS<F, V> {
    #[inline]
    fn default() -> Self {
        Self {
            cfg: CCSConfig::default(),
            M: vec![vec![]; V::n_matrices()],
        }
    }
}

impl<F: Field, V: CCSVariant> Arith for CCS<F, V> {
    type Config = CCSConfig<V>;

    #[inline]
    fn config(&self) -> &Self::Config {
        &self.cfg
    }

    #[inline]
    fn config_mut(&mut self) -> &mut Self::Config {
        &mut self.cfg
    }
}

impl<F: Field, W: AsRef<[F]>, U: AsRef<[F]>, V: CCSVariant> ArithRelation<W, U> for CCS<F, V> {
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

impl<F: Field> From<R1CS<F>> for CCS<F, R1CSConfig> {
    fn from(r1cs: R1CS<F>) -> Self {
        Self {
            cfg: r1cs.config().into(),
            M: vec![r1cs.A, r1cs.B, r1cs.C],
        }
    }
}

impl<F: Field> From<&ConstraintSystem<F>> for CCS<F, R1CSConfig> {
    fn from(cs: &ConstraintSystem<F>) -> Self {
        R1CS::from(cs).into()
    }
}

impl<F: Field> From<ConstraintSystem<F>> for CCS<F, R1CSConfig> {
    fn from(cs: ConstraintSystem<F>) -> Self {
        Self::from(&cs)
    }
}

// TODO: add back tests
