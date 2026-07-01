//! This module implements in-circuit R1CS variables and relation check gadgets.

use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, ops::Index};

use super::{R1CS, RelaxedInstance, RelaxedWitness};
use crate::{
    algebra::{
        field::TwoStageFieldVar,
        ops::{eq::EquivalenceGadget, matrix::SparseMatrixVar, vector::VectorMulGadget},
    },
    arithmetizations::{ArithGadget, ArithRelationGadget, ccs::CCSGadget},
    circuits::Assignments,
};

/// [`R1CSVar`] is the in-circuit variable of a given R1CS structure.
///
/// Only the matrices are represented, while the remaining R1CS parameters are
/// constants to the circuit.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct R1CSVar<FVar> {
    matrices: [SparseMatrixVar<FVar>; 3],
}

impl<FVar: TwoStageFieldVar> ArithGadget for R1CSVar<FVar> {
    type ConstraintField = FVar::ConstraintField;

    type Widget = R1CS<FVar::Value>;
}

impl<FVar: TwoStageFieldVar> CCSGadget for R1CSVar<FVar> {
    type FieldVar = FVar;

    fn matrices(&self) -> &[SparseMatrixVar<Self::FieldVar>] {
        &self.matrices[..]
    }
}

impl<FVar: TwoStageFieldVar> AllocVar<R1CS<FVar::Value>, FVar::ConstraintField> for R1CSVar<FVar> {
    fn new_variable<T: Borrow<R1CS<FVar::Value>>>(
        cs: impl Into<Namespace<FVar::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            let val = val.borrow();

            Ok(Self {
                matrices: [
                    AllocVar::new_variable(cs.clone(), || Ok(&val.matrices[0]), mode)?,
                    AllocVar::new_variable(cs.clone(), || Ok(&val.matrices[1]), mode)?,
                    AllocVar::new_variable(cs.clone(), || Ok(&val.matrices[2]), mode)?,
                ],
            })
        })
    }
}

impl<FVar: TwoStageFieldVar> R1CSVar<FVar> {
    pub fn evaluate_r1cs<A: Index<usize, Output = FVar>>(
        &self,
        z: A,
    ) -> Result<Vec<FVar::Intermediate>, SynthesisError>
    where
        [(FVar, usize)]: VectorMulGadget<A, Output = FVar::Intermediate>,
    {
        let neg_u = FVar::additive_identity() - &z[0];
        self.evaluate_ccs(
            z,
            [vec![0, 1], vec![2]],
            [FVar::multiplicative_identity().into(), neg_u],
        )
    }
}

impl<FVar: TwoStageFieldVar, WVar: AsRef<[FVar]>, UVar: AsRef<[FVar]>>
    ArithRelationGadget<WVar, UVar> for R1CSVar<FVar>
where
    [FVar::Intermediate]: EquivalenceGadget<[FVar]>,
    [(FVar, usize)]:
        for<'a> VectorMulGadget<Assignments<FVar, &'a [FVar]>, Output = FVar::Intermediate>,
{
    type Evaluation = Vec<FVar::Intermediate>;

    fn eval_relation(&self, w: &WVar, u: &UVar) -> Result<Self::Evaluation, SynthesisError> {
        self.evaluate_r1cs(Assignments::from((
            FVar::multiplicative_identity(),
            u.as_ref(),
            w.as_ref(),
        )))
    }

    fn check_evaluation(_w: &WVar, _u: &UVar, e: Self::Evaluation) -> Result<(), SynthesisError> {
        e.enforce_equivalent(&vec![FVar::additive_identity(); e.len()])
    }
}

impl<FVar: TwoStageFieldVar> ArithRelationGadget<RelaxedWitness<&[FVar]>, RelaxedInstance<&[FVar]>>
    for R1CSVar<FVar>
where
    [FVar::Intermediate]: EquivalenceGadget<[FVar]>,
    [(FVar, usize)]:
        for<'a> VectorMulGadget<Assignments<FVar, &'a [FVar]>, Output = FVar::Intermediate>,
{
    type Evaluation = Vec<FVar::Intermediate>;

    fn eval_relation(
        &self,
        w: &RelaxedWitness<&[FVar]>,
        u: &RelaxedInstance<&[FVar]>,
    ) -> Result<Self::Evaluation, SynthesisError> {
        self.evaluate_r1cs(Assignments::from((u.u.clone(), u.x, w.w)))
    }

    fn check_evaluation(
        w: &RelaxedWitness<&[FVar]>,
        _u: &RelaxedInstance<&[FVar]>,
        e: Self::Evaluation,
    ) -> Result<(), SynthesisError> {
        e.enforce_equivalent(&w.e)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::{error::Error, rand::thread_rng};

    use super::*;
    use crate::{
        circuits::test_utils::{constraints_for_test, satisfying_assignments_for_test},
        relations::Relation,
    };

    #[test]
    fn test_eval() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let r1cs = constraints_for_test::<Fr>();

        assert!(
            r1cs.evaluate_r1cs(satisfying_assignments_for_test(Fr::rand(&mut rng)))?
                .into_iter()
                .all(|e| e.is_zero())
        );
        assert!(
            !r1cs
                .evaluate_r1cs(Assignments::from((
                    Fr::one(),
                    vec![Fr::rand(&mut rng)],
                    vec![
                        Fr::rand(&mut rng),
                        Fr::rand(&mut rng),
                        Fr::rand(&mut rng),
                        Fr::rand(&mut rng),
                    ],
                )))?
                .into_iter()
                .all(|e| e.is_zero())
        );

        Ok(())
    }

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
}
