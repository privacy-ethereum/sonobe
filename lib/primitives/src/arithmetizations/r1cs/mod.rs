use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSystem, Matrix};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, rand::Rng};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use sonobe_traits::Dummy;

use super::{ccs::CCS, Arith, ArithRelation, ArithSerializer};
use crate::arithmetizations::{Assignments, Error};

pub mod circuits;

#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CS<F: Field> {
    l: usize, // io len
    m: usize, // number of constraints
    n: usize, // number of variables
    pub A: Matrix<F>,
    pub B: Matrix<F>,
    pub C: Matrix<F>,
}

impl<F: Field> R1CS<F> {
    /// Evaluates the R1CS relation at a given vector of variables `z`
    pub fn eval_at_z(&self, z: Assignments<F>) -> Result<Vec<F>, Error> {
        if z.public.len() != self.n_public_inputs() {
            return Err(Error::MalformedAssignments(
                format!("The number of public inputs in R1CS ({}) does not match the length of the provided public inputs ({}).", self.n_public_inputs(), z.public.len())
            ));
        }
        if z.private.len() != self.n_witnesses() {
            return Err(Error::MalformedAssignments(
                format!("The number of witnesses in R1CS ({}) does not match the length of the provided witnesses ({}).", self.n_witnesses(), z.private.len())
            ));
        }

        Ok(cfg_iter!(self.A)
            .zip(&self.B)
            .zip(&self.C)
            .map(|((a, b), c)| {
                let az = a.iter().map(|(val, col)| z[*col] * val).sum::<F>();
                let bz = b.iter().map(|(val, col)| z[*col] * val).sum::<F>();
                let cz = c.iter().map(|(val, col)| z[*col] * val).sum::<F>();
                az * bz - z[0] * cz
            })
            .collect())
    }
}

impl<F: Field> Arith for R1CS<F> {
    #[inline]
    fn degree(&self) -> usize {
        2
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

impl<F: Field, W: AsRef<[F]>, U: AsRef<[F]>> ArithRelation<W, U> for R1CS<F> {
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

impl<F: Field> ArithSerializer for R1CS<F> {
    fn params_to_le_bytes(&self) -> Vec<u8> {
        [
            self.l.to_le_bytes(),
            self.m.to_le_bytes(),
            self.n.to_le_bytes(),
        ]
        .concat()
    }
}

impl<F: Field> Dummy<(usize, usize, usize)> for R1CS<F> {
    fn dummy((n_constraints, n_variables, n_public_inputs): (usize, usize, usize)) -> Self {
        Self {
            m: n_constraints,
            n: n_variables,
            l: n_public_inputs,
            A: vec![],
            B: vec![],
            C: vec![],
        }
    }
}

impl<F: Field> R1CS<F> {
    pub fn empty() -> Self {
        Self::dummy((0, 0, 0))
    }

    pub fn new(
        (n_constraints, n_variables, n_public_inputs): (usize, usize, usize),
        mut matrices: Vec<Matrix<F>>,
    ) -> Result<Self, Error> {
        // R1CS should have exactly 3 matrices (A, B, C)
        if matrices.len() != 3 {
            return Err(Error::ConstraintExtractionFailure(format!(
                "R1CS should only have 3 matrices (A, B, C) but found {} matrices",
                matrices.len()
            )));
        }

        let C = matrices.pop().unwrap();
        let B = matrices.pop().unwrap();
        let A = matrices.pop().unwrap();

        Ok(Self {
            m: n_constraints,
            n: n_variables,
            l: n_public_inputs,
            A,
            B,
            C,
        })
    }
}

impl<F: Field> TryFrom<CCS<F>> for R1CS<F> {
    type Error = Error;

    fn try_from(ccs: CCS<F>) -> Result<Self, Error> {
        Self::new(
            (
                ccs.n_constraints(),
                ccs.n_variables(),
                ccs.n_public_inputs(),
            ),
            ccs.M,
        )
    }
}

/// Extracts R1CS from arkworks ConstraintSystem matrices
impl<F: Field> TryFrom<&ConstraintSystem<F>> for R1CS<F> {
    type Error = Error;

    fn try_from(cs: &ConstraintSystem<F>) -> Result<Self, Error> {
        // Get the R1CS predicate matrices
        let r1cs_predicate = cs.predicate_constraint_systems.get("R1CS").ok_or_else(|| {
            Error::ConstraintExtractionFailure(
                "No R1CS predicate found in constraint system".into(),
            )
        })?;
        Self::new(
            (
                cs.num_constraints(),
                cs.num_instance_variables + cs.num_witness_variables,
                cs.num_instance_variables - 1, // -1 to subtract the first '1'
            ),
            r1cs_predicate.to_matrices(cs),
        )
    }
}

/// extracts the witness and the public inputs from arkworks ConstraintSystem.
pub fn extract_w_x<F: Field>(cs: &ConstraintSystem<F>) -> (Vec<F>, Vec<F>) {
    let witness = cs
        .witness_assignment()
        .expect("witness_assignment failed")
        .to_vec();
    let instance = cs
        .instance_assignment()
        .expect("instance_assignment failed");
    (
        witness,
        // skip the first element which is '1'
        instance[1..].to_vec(),
    )
}

// TODO: add back tests