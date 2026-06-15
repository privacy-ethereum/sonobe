use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::{
    arithmetizations::{
        ArithGadget, ArithRelationGadget,
        r1cs::{RelaxedInstance, RelaxedWitness},
    },
    commitments::{CommitmentDefGadget, CommitmentOpsGadget},
    relations::RelationGadget,
};

use super::super::{
    instances::circuits::{IncomingInstanceVar as IUVar, RunningInstanceVar as RUVar},
    witnesses::circuits::{IncomingWitnessVar as IWVar, RunningWitnessVar as RWVar},
};
use crate::nova::keys::NovaKey;

#[derive(Clone)]
pub struct NovaKeyVar<A, CM: CommitmentDefGadget> {
    arith: A,
    ck: CM::KeyVar,
}

impl<A: ArithGadget<ConstraintField = CM::ConstraintField>, CM: CommitmentDefGadget>
    AllocVar<NovaKey<A::Widget, CM::Widget>, CM::ConstraintField> for NovaKeyVar<A, CM>
{
    fn new_variable<T: Borrow<NovaKey<A::Widget, CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let NovaKey { arith, ck } = v.borrow();
        Ok(Self {
            arith: AllocVar::new_variable(cs.clone(), || Ok(arith.borrow()), mode)?,
            ck: AllocVar::new_variable(cs.clone(), || Ok(ck.borrow()), mode)?,
        })
    }
}

impl<A, CM> RelationGadget<RWVar<CM>, RUVar<CM>> for NovaKeyVar<A, CM>
where
    A: for<'a> ArithRelationGadget<
            RelaxedWitness<&'a [CM::ScalarVar]>,
            RelaxedInstance<&'a [CM::ScalarVar]>,
        >,
    CM: CommitmentOpsGadget,
{
    fn check_relation(&self, w: &RWVar<CM>, u: &RUVar<CM>) -> Result<(), SynthesisError> {
        self.arith.check_relation(
            &RelaxedWitness { w: &w.w, e: &w.e },
            &RelaxedInstance { x: &u.x, u: &u.u },
        )?;
        CM::open(&self.ck, &w.e, &w.r_e, &u.cm_e)?;
        CM::open(&self.ck, &w.w, &w.r_w, &u.cm_w)?;
        Ok(())
    }
}

impl<A, CM> RelationGadget<IWVar<CM>, IUVar<CM>> for NovaKeyVar<A, CM>
where
    A: ArithRelationGadget<Vec<CM::ScalarVar>, Vec<CM::ScalarVar>>,
    CM: CommitmentOpsGadget,
{
    fn check_relation(&self, w: &IWVar<CM>, u: &IUVar<CM>) -> Result<(), SynthesisError> {
        self.arith.check_relation(&w.w, &u.x)?;
        CM::open(&self.ck, &w.w, &w.r_w, &u.cm_w)?;
        Ok(())
    }
}
