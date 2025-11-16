use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSystem, Matrix, R1CS_PREDICATE_LABEL};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, iterable::Iterable};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{ccs::CCS, Arith, ArithRelation, Error};
use crate::{
    arithmetizations::{ccs::CCSVariant, ArithConfig},
    circuits::Assignments,
    relations::WitnessInstanceExtractor,
};

pub mod circuits;

#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSConfig {
    m: usize, // number of constraints
    n: usize, // number of variables
    l: usize, // io len
}

impl R1CSConfig {
    pub fn new(n_constraints: usize, n_variables: usize, n_public_inputs: usize) -> Self {
        Self {
            m: n_constraints,
            n: n_variables,
            l: n_public_inputs,
        }
    }
}

impl ArithConfig for R1CSConfig {
    #[inline]
    fn empty() -> Self {
        Self { m: 0, n: 0, l: 0 }
    }

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

    #[inline]
    fn set_n_public_inputs(&mut self, l: usize) {
        self.l = l;
    }
}

impl<F: Field> From<&ConstraintSystem<F>> for R1CSConfig {
    fn from(cs: &ConstraintSystem<F>) -> Self {
        Self::new(
            cs.num_constraints(),
            cs.num_instance_variables + cs.num_witness_variables,
            cs.num_instance_variables - 1, // -1 to subtract the first '1'
        )
    }
}

impl CCSVariant for R1CSConfig {
    fn n_matrices() -> usize {
        3
    }

    fn degree() -> usize {
        2
    }

    fn multisets_vec() -> Vec<Vec<usize>> {
        vec![vec![0, 1], vec![2]]
    }

    fn coefficients_vec<F: Field>() -> Vec<F> {
        vec![F::one(), -F::one()]
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CS<F: Field> {
    cfg: R1CSConfig,
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
    type Config = R1CSConfig;

    #[inline]
    fn empty() -> Self {
        Self {
            cfg: R1CSConfig::empty(),
            A: vec![],
            B: vec![],
            C: vec![],
        }
    }

    #[inline]
    fn config(&self) -> &Self::Config {
        &self.cfg
    }

    #[inline]
    fn config_mut(&mut self) -> &mut Self::Config {
        &mut self.cfg
    }
}

impl<F: Field> R1CS<F> {
    #[allow(non_snake_case)]
    pub fn new(cfg: R1CSConfig, [A, B, C]: [Matrix<F>; 3]) -> Self {
        Self { cfg, A, B, C }
    }
}

impl<F: Field> TryFrom<CCS<F, R1CSConfig>> for R1CS<F> {
    type Error = Error;

    fn try_from(ccs: CCS<F, R1CSConfig>) -> Result<Self, Error> {
        Ok(Self::new(
            R1CSConfig::new(
                ccs.n_constraints(),
                ccs.n_variables(),
                ccs.n_public_inputs(),
            ),
            // `unwrap` is safe here because the type parameter T = 3
            ccs.M.try_into().unwrap(),
        ))
    }
}

impl<F: Field> From<&ConstraintSystem<F>> for R1CS<F> {
    fn from(cs: &ConstraintSystem<F>) -> Self {
        // Get the R1CS predicate matrices
        let r1cs_predicate = &cs.predicate_constraint_systems[R1CS_PREDICATE_LABEL];
        let matrices = r1cs_predicate.to_matrices(cs);
        // `unwrap` is safe here because R1CS always has 3 matrices
        R1CS::new(cs.into(), matrices.try_into().unwrap())
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

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_relations::gr1cs::ConstraintSynthesizer;
    use ark_std::{error::Error, test_rng};

    use super::*;
    use crate::circuits::{
        utils::{constraints_for_test, satisfying_assignments_for_test, CircuitForTest},
        ConstraintSystemExt,
    };

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

        assert_eq!(R1CS::from(&cs), constraints_for_test());
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
