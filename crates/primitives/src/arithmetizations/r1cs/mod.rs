//! This module implements the Rank-1 Constraint System (R1CS) and its relation
//! checks against plain and relaxed witnesses and instances.

use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSystem, Matrix, R1CS_PREDICATE_LABEL};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
};
use ark_std::{cfg_into_iter, cfg_iter};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{Arith, ArithConfig, ArithRelation, Error, ccs::CCS};
use crate::circuits::Assignments;

pub mod circuits;

/// [`R1CS`] holds the three sparse matrices `A`, `B`, `C` together with the
/// configuration.
#[derive(Debug, Clone, Default, PartialEq, CanonicalSerialize)]
pub struct R1CS<F: Field> {
    m: usize, // number of constraints
    n: usize, // number of variables
    l: usize, // io len
    matrices: [Matrix<F>; 3],
}

impl<F: Field> Arith for R1CS<F> {
    #[inline]
    fn config(&self) -> ArithConfig {
        ArithConfig {
            degree: 2,
            n_constraints: self.m,
            n_variables: self.n,
            n_public_inputs: self.l,
            n_witnesses: self.n - self.l - 1,
        }
    }
}

impl<F: Field> CCS for R1CS<F> {
    type Field = F;

    fn matrices(&self) -> &[Matrix<Self::Field>] {
        &self.matrices[..]
    }
}

impl<F: Field> R1CS<F> {
    /// [`R1CS::new`] creates a new R1CS structure from the given configuration
    /// and matrices.
    pub fn new(
        n_constraints: usize,
        n_variables: usize,
        n_public_inputs: usize,
        matrices: [Matrix<F>; 3],
    ) -> Result<Self, Error> {
        let r1cs =
            Self::new_without_validity_check(n_constraints, n_variables, n_public_inputs, matrices);
        r1cs.validate()?;
        Ok(r1cs)
    }

    /// [`R1CS::validate`] checks that the structural invariant of the R1CS
    /// holds, i.w., every matrix has exactly `m` rows (one per constraint), and
    /// no column index reaches beyond the `n` variables.
    pub fn validate(&self) -> Result<(), Error> {
        for matrix in &self.matrices {
            if matrix.len() != self.m {
                return Err(Error::InvalidNumberOfConstraints(self.m, matrix.len()));
            }
            for row in matrix {
                if let Some(max) = row.iter().map(|(_, i)| *i).max()
                    && max >= self.n
                {
                    return Err(Error::InvalidNumberOfVariables(self.n, max + 1));
                }
            }
        }
        Ok(())
    }

    /// [`R1CS::new_without_validity_check`] creates a new R1CS structure from
    /// the given configuration and matrices without checking their validity.
    pub fn new_without_validity_check(
        n_constraints: usize,
        n_variables: usize,
        n_public_inputs: usize,
        matrices: [Matrix<F>; 3],
    ) -> Self {
        Self {
            m: n_constraints,
            l: n_public_inputs,
            n: n_variables,
            matrices,
        }
    }

    /// [`R1CS::evaluate_r1cs`] evaluates the R1CS relation at a given vector of
    /// assignments `z`.
    ///
    /// This method is simply a wrapper of [`CCS::evaluate_ccs`] with fixed
    /// coefficients and multisets.
    pub fn evaluate_r1cs(
        &self,
        z: Assignments<F, impl AsRef<[F]> + Sync>,
    ) -> Result<Vec<F>, Error> {
        let u = z[0];
        self.evaluate_ccs(z, [vec![0, 1], vec![2]], [F::one(), -u])
    }
}

impl<F: Field> Valid for R1CS<F> {
    fn check(&self) -> Result<(), SerializationError> {
        self.matrices.check()?;
        self.validate().map_err(|_| SerializationError::InvalidData)
    }
}

impl<F: Field> CanonicalDeserialize for R1CS<F> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let m = usize::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let n = usize::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let l = usize::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let matrices =
            <[Matrix<F>; 3]>::deserialize_with_mode(&mut reader, compress, Validate::No)?;

        let r1cs = Self::new_without_validity_check(m, n, l, matrices);
        if validate == Validate::Yes {
            r1cs.check()?;
        }
        Ok(r1cs)
    }
}

impl<F: Field> From<&ConstraintSystem<F>> for R1CS<F> {
    fn from(cs: &ConstraintSystem<F>) -> Self {
        // Get the R1CS predicate matrices
        let r1cs_predicate = &cs.predicate_constraint_systems[R1CS_PREDICATE_LABEL];
        let matrices = r1cs_predicate.to_matrices(cs);

        // matrices are extracted from a circuit, which we assume is trusted
        R1CS::new_without_validity_check(
            cs.num_constraints(),
            cs.num_instance_variables + cs.num_witness_variables,
            cs.num_instance_variables - 1, // -1 to subtract the first '1'
            matrices.try_into().unwrap(),  // safe as R1CS always has 3 matrices
        )
    }
}

impl<F: Field> From<ConstraintSystem<F>> for R1CS<F> {
    fn from(cs: ConstraintSystem<F>) -> Self {
        Self::from(&cs)
    }
}

impl<F: Field, W: AsRef<[F]>, U: AsRef<[F]>> ArithRelation<W, U> for R1CS<F> {
    type Evaluation = Vec<F>;

    fn eval_relation(&self, w: &W, x: &U) -> Result<Self::Evaluation, Error> {
        self.evaluate_r1cs((F::one(), x.as_ref(), w.as_ref()).into())
    }

    fn check_evaluation(_w: &W, _x: &U, e: Self::Evaluation) -> Result<(), Error> {
        cfg_into_iter!(e)
            .all(|i| i.is_zero())
            .then_some(())
            .ok_or(Error::UnsatisfiedAssignments(
                "Evaluation contains non-zero values".into(),
            ))
    }
}

/// [`RelaxedWitness`] defines a relaxed version of R1CS witness.
///
/// It is the basis of witnesses in many folding schemes that support R1CS.
pub struct RelaxedWitness<V> {
    /// [`RelaxedWitness::w`] is the witness vector
    pub w: V,
    /// [`RelaxedWitness::e`] is the error term
    pub e: V,
}

/// [`RelaxedInstance`] defines a relaxed version of R1CS instance.
///
/// It is the basis of instances in many folding schemes that support R1CS.
pub struct RelaxedInstance<V: IntoIterator> {
    /// [`RelaxedInstance::x`] is the public input vector
    pub x: V,
    /// [`RelaxedInstance::u`] is the constant term
    pub u: V::Item,
}

impl<F: Field> ArithRelation<RelaxedWitness<&[F]>, RelaxedInstance<&[F]>> for R1CS<F> {
    type Evaluation = Vec<F>;

    fn eval_relation(
        &self,
        w: &RelaxedWitness<&[F]>,
        u: &RelaxedInstance<&[F]>,
    ) -> Result<Self::Evaluation, Error> {
        self.evaluate_r1cs((*u.u, u.x, w.w).into())
    }

    fn check_evaluation(
        w: &RelaxedWitness<&[F]>,
        _u: &RelaxedInstance<&[F]>,
        v: Self::Evaluation,
    ) -> Result<(), Error> {
        if w.e.len() != v.len() {
            return Err(Error::MalformedAssignments(format!(
                "The number of constraints in R1CS ({}) does not match the length of the provided relaxed witness's error term ({}).",
                v.len(),
                w.e.len()
            )));
        }

        cfg_iter!(w.e)
            .zip(&v)
            .all(|(e, v)| e == v)
            .then_some(())
            .ok_or(Error::UnsatisfiedAssignments(
                "Evaluation does not match error term".into(),
            ))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_std::{error::Error, rand::thread_rng};

    use super::*;
    use crate::{
        circuits::test_utils::{constraints_for_test, satisfying_assignments_for_test},
        relations::Relation,
    };

    #[test]
    fn test_check() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let r1cs = constraints_for_test::<Fr>();

        let assignments = satisfying_assignments_for_test(Fr::rand(&mut rng));

        assert!(
            r1cs.check_relation(&assignments.private, &assignments.public)
                .is_ok()
        );
        assert!(
            r1cs.check_relation(
                &[
                    Fr::rand(&mut rng),
                    Fr::rand(&mut rng),
                    Fr::rand(&mut rng),
                    Fr::rand(&mut rng),
                ],
                &[Fr::rand(&mut rng)]
            )
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn test_deserialize_rejects_malformed() -> Result<(), Box<dyn Error>> {
        let valid = R1CS::<Fr>::new(1, 1, 0, [vec![vec![]], vec![vec![]], vec![vec![]]]).unwrap();
        let mut bytes = vec![];
        valid.serialize_compressed(&mut bytes)?;
        assert_eq!(valid, R1CS::<Fr>::deserialize_compressed(&bytes[..])?);

        let mismatched_constraints = R1CS::<Fr>::new_without_validity_check(
            2,
            1,
            0,
            [vec![vec![]], vec![vec![]], vec![vec![]]],
        );
        let mut bytes = vec![];
        mismatched_constraints
            .serialize_compressed(&mut bytes)
            .unwrap();
        assert!(R1CS::<Fr>::deserialize_compressed_unchecked(&bytes[..]).is_ok());
        assert!(R1CS::<Fr>::deserialize_compressed(&bytes[..]).is_err());

        let out_of_range_variable = R1CS::<Fr>::new_without_validity_check(
            1,
            1,
            0,
            [vec![vec![(Fr::from(1u64), 5)]], vec![vec![]], vec![vec![]]],
        );
        let mut bytes = vec![];
        out_of_range_variable.serialize_compressed(&mut bytes)?;
        assert!(R1CS::<Fr>::deserialize_compressed_unchecked(&bytes[..]).is_ok());
        assert!(R1CS::<Fr>::deserialize_compressed(&bytes[..]).is_err());

        Ok(())
    }
}
