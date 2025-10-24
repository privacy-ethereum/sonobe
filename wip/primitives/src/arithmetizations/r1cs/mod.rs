use std::ops::Index;
use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSystem, Matrix};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter};
use ark_std::iterable::Iterable;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    circuits::{Assignments, ConstraintSystemExt},
    relations::{WitnessInstanceExtractor},
    traits::Dummy,
};

use super::{ccs::CCS, Arith, ArithRelation, Error};

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
    /// Evaluates the R1CS relation at a given vector of assignments `z`
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
        matrices: [Matrix<F>; 3],
    ) -> Self {
        let mut matrices = matrices.to_vec();
        let C = matrices.pop().unwrap();
        let B = matrices.pop().unwrap();
        let A = matrices.pop().unwrap();
        Self {
            m: n_constraints,
            n: n_variables,
            l: n_public_inputs,
            A,
            B,
            C,
        }
    }
}

impl<F: Field> TryFrom<CCS<F>> for R1CS<F> {
    type Error = Error;

    fn try_from(ccs: CCS<F>) -> Result<Self, Error> {
        if ccs.t != 3 {
            return Err(Error::ConstraintExtractionFailure(format!(
                "R1CS should only have 3 matrices (A, B, C) but found {} matrices",
                ccs.t
            )));
        }
        Ok(Self::new(
            (
                ccs.n_constraints(),
                ccs.n_variables(),
                ccs.n_public_inputs(),
            ),
            ccs.M.try_into().unwrap(),
        ))
    }
}

impl<F: Field, W: AsRef<[F]>, U: AsRef<[F]>> ArithRelation<W, U> for R1CS<F> {
    type Evaluation = Vec<F>;

    fn eval_relation(&self, w: &W, x: &U) -> Result<Self::Evaluation, Error> {
        self.eval_assignments((F::one(), x.as_ref(), w.as_ref()).into())
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

impl<F: Field> WitnessInstanceExtractor<Vec<F>, Vec<F>> for R1CS<F> {
    type Source = Assignments<F, Vec<F>>;
    type Error = Error;

    fn extract(&self, z: Self::Source) -> Result<(Vec<F>, Vec<F>), Error> {
        Ok((z.private, z.public))
    }
}

pub struct RelaxedWitness<V> {
    pub w: V,
    pub e: V,
}

pub struct RelaxedInstance<V: IntoIterator> {
    pub x: V,
    pub u: V::Item,
}

impl<F: Field> ArithRelation<RelaxedWitness<&[F]>, RelaxedInstance<&[F]>> for R1CS<F> {
    type Evaluation = Vec<F>;

    fn eval_relation(
        &self,
        w: &RelaxedWitness<&[F]>,
        u: &RelaxedInstance<&[F]>,
    ) -> Result<Self::Evaluation, Error> {
        self.eval_assignments((*u.u, u.x, w.w).into())
    }

    fn check_evaluation(
        w: &RelaxedWitness<&[F]>,
        _u: &RelaxedInstance<&[F]>,
        v: Self::Evaluation,
    ) -> Result<(), Error> {
        cfg_iter!(w.e)
            .zip(&v)
            .all(|(e, v)| e == v)
            .then_some(())
            .ok_or(Error::UnsatisfiedAssignments(
                "Evaluation does not match error term".into(),
            ))
    }
}

impl<F: Field> WitnessInstanceExtractor<RelaxedWitness<Vec<F>>, RelaxedInstance<Vec<F>>>
    for R1CS<F>
{
    type Source = Assignments<F, Vec<F>>;
    type Error = Error;

    fn extract(
        &self,
        z: Self::Source,
    ) -> Result<(RelaxedWitness<Vec<F>>, RelaxedInstance<Vec<F>>), Error> {
        let (w, x) = self.extract(z)?;
        let e = vec![F::zero(); self.n_constraints()];
        Ok((RelaxedWitness { w, e }, RelaxedInstance { x, u: F::one() }))
    }
}

impl<F: Field> ConstraintSystemExt<F> for ConstraintSystem<F> {
    type Arith = R1CS<F>;
    type Error = Error;

    fn constraints(&self) -> Result<R1CS<F>, Error> {
        // Get the R1CS predicate matrices
        let r1cs_predicate = self
            .predicate_constraint_systems
            .get("R1CS")
            .ok_or_else(|| {
                Error::ConstraintExtractionFailure(
                    "No R1CS predicate found in constraint system".into(),
                )
            })?;
        let matrices = r1cs_predicate.to_matrices(self);
        if matrices.len() != 3 {
            return Err(Error::ConstraintExtractionFailure(format!(
                "R1CS should only have 3 matrices (A, B, C) but found {} matrices",
                matrices.len()
            )));
        }
        Ok(R1CS::new(
            (
                self.num_constraints(),
                self.num_instance_variables + self.num_witness_variables,
                self.num_instance_variables - 1, // -1 to subtract the first '1'
            ),
            matrices.try_into().unwrap(),
        ))
    }

    fn assignments(&self) -> Result<Assignments<F, Vec<F>>, Error> {
        let witness = self.witness_assignment()?.to_vec();
        // skip the first element which is '1'
        let instance = self.instance_assignment()?[1..].to_vec();

        Ok((F::one(), instance, witness).into())
    }
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_relations::gr1cs::ConstraintSynthesizer;
    use ark_std::{error::Error, test_rng};

    use crate::circuits::utils::{
        constraints_for_test, satisfying_assignments_for_test, CircuitForTest,
    };

    use super::*;

    #[test]
    fn test_constraint_extraction() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let circuit = CircuitForTest::<Fr> {
            x: Fr::rand(&mut rng),
        };
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied()?);
        cs.finalize();
        let cs = cs.into_inner().unwrap();

        assert_eq!(cs.constraints()?, constraints_for_test());
        Ok(())
    }

    #[test]
    fn test_witness_extraction() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let x = Fr::rand(&mut rng);
        let circuit = CircuitForTest::<Fr> { x };
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied()?);
        cs.finalize();
        let cs = cs.into_inner().unwrap();

        assert_eq!(cs.assignments()?, satisfying_assignments_for_test(x));
        Ok(())
    }
}
