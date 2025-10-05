use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::{AllocatedFp, FpVar},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use noname::{backends::BackendField, imports::FnKind, witness::WitnessEnv};
use num_bigint::BigUint;
use std::marker::PhantomData;

use folding_schemes::{frontend::FCircuit, Error};

pub use noname::backends::r1cs::R1csBn254Field;

pub mod utils;
use crate::noname::utils::{compile_source_code, LC, R1CS};
use crate::utils::{VecF, VecFpVar};

// `L` indicates the length of the ExternalInputs vector of field elements.
#[derive(Debug, Clone)]
pub struct NonameFCircuit<F: PrimeField, BF: BackendField, const SL: usize, const EIL: usize> {
    pub r1cs: R1CS<BF>,
    _f: PhantomData<F>,
}

impl<F: PrimeField, BF: BackendField, const SL: usize, const EIL: usize> FCircuit<F>
    for NonameFCircuit<F, BF, SL, EIL>
{
    type Params = String;
    type ExternalInputs = VecF<F, EIL>;
    type ExternalInputsVar = VecFpVar<F, EIL>;

    fn new(code: Self::Params) -> Result<Self, Error> {
        assert_eq!(F::MODULUS.to_string(), BF::MODULUS.to_string());
        let compiled_circuit = compile_source_code::<BF>(&code).map_err(|_| {
            Error::Other("Encountered an error while compiling a noname circuit".to_owned())
        })?;

        let main_sig = match &compiled_circuit.main_info().kind {
            FnKind::BuiltIn(_, _, _) => unreachable!(),
            FnKind::Native(fn_sig) => fn_sig.sig.clone(),
        };

        for arg in &main_sig.arguments {
            assert!(arg.name.value == "ivc_inputs" || arg.name.value == "external_inputs");
        }

        Ok(NonameFCircuit {
            r1cs: compiled_circuit.circuit.backend,
            _f: PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        SL
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut env = WitnessEnv {
            var_values: [
                (
                    "external_inputs".to_string(),
                    external_inputs
                        .0
                        .iter()
                        .map(|var| BF::from(Into::<BigUint>::into(var.value().unwrap_or_default())))
                        .collect::<Vec<BF>>(),
                ),
                (
                    "ivc_inputs".to_string(),
                    z_i.iter()
                        .map(|var| BF::from(Into::<BigUint>::into(var.value().unwrap_or_default())))
                        .collect::<Vec<BF>>(),
                ),
            ]
            .into(),
            cached_values: Default::default(),
        };

        let noname_witness = self
            .r1cs
            .extract_witness(&mut env)
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        let z_i1 = noname_witness[1..1 + z_i.len()]
            .iter()
            .map(|&val| cs.new_witness_variable(|| Ok(Into::<BigUint>::into(val).into())))
            .collect::<Result<Vec<_>, _>>()?;

        let assigned_z_i1 = z_i1
            .iter()
            .map(|&var| FpVar::Var(AllocatedFp::new(cs.assigned_value(var), var, cs.clone())))
            .collect();

        // arkworks assigns by default the 1 constant
        // assumes witness is: [1, public_outputs, public_inputs, private_inputs, aux]
        // for both the  z_i, z_i1 vectors, we assume that they have been assigned in the order
        // with which it will appear in the witness
        let idx_to_var = [
            &[Variable::One][..],
            &z_i1,
            &z_i.iter()
                .chain(&external_inputs.0)
                .map(|var| match var {
                    FpVar::Var(fp) => Ok(fp.variable),
                    _ => Err(SynthesisError::Unsatisfiable),
                })
                .collect::<Result<Vec<_>, _>>()?,
            &noname_witness[1 + z_i1.len() + z_i.len() + external_inputs.0.len()..]
                .iter()
                .map(|&val| cs.new_witness_variable(|| Ok(Into::<BigUint>::into(val).into())))
                .collect::<Result<Vec<_>, _>>()?,
        ]
        .concat();

        let make_lc = |lc_data: &LC<BF>| {
            LinearCombination(
                lc_data
                    .0
                    .iter()
                    .map(|(&var, &coeff)| (F::from(Into::<BigUint>::into(coeff)), idx_to_var[var]))
                    .collect(),
            )
        };

        for (a, b, c) in &self.r1cs.constraints {
            cs.enforce_r1cs_constraint(|| make_lc(a), || make_lc(b), || make_lc(c))?;
        }

        Ok(assigned_z_i1)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use noname::backends::r1cs::R1csBn254Field;

    use folding_schemes::{frontend::FCircuit, Error};

    use super::NonameFCircuit;
    use crate::utils::VecFpVar;

    /// Native implementation of `NONAME_CIRCUIT_EXTERNAL_INPUTS`
    fn external_inputs_step_native<F: PrimeField>(z_i: Vec<F>, external_inputs: Vec<F>) -> Vec<F> {
        let xx = external_inputs[0] + z_i[0];
        let yy = external_inputs[1] * z_i[1];
        assert_eq!(yy, xx);
        vec![xx, yy]
    }

    const NONAME_CIRCUIT_EXTERNAL_INPUTS: &str =
        "fn main(pub ivc_inputs: [Field; 2], external_inputs: [Field; 2]) -> [Field; 2] {
    let xx = external_inputs[0] + ivc_inputs[0];
    let yy = external_inputs[1] * ivc_inputs[1];
    assert_eq(yy, xx);
    return [xx, yy];
}";

    const NONAME_CIRCUIT_NO_EXTERNAL_INPUTS: &str =
        "fn main(pub ivc_inputs: [Field; 2]) -> [Field; 2] {
    let out = ivc_inputs[0] * ivc_inputs[1];
    return [out, ivc_inputs[1]];
}";

    #[test]
    fn test_step_native() -> Result<(), Error> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let params = NONAME_CIRCUIT_EXTERNAL_INPUTS.to_owned();
        // state length = 2, external inputs length = 2
        let circuit = NonameFCircuit::<Fr, R1csBn254Field, 2, 2>::new(params)?;
        let inputs_public = vec![Fr::from(2), Fr::from(5)];
        let inputs_private = vec![Fr::from(8), Fr::from(2)];

        let ivc_inputs_var =
            Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs_public.clone()))?;
        let external_inputs_var =
            Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs_private.clone()))?;

        let z_i1 = circuit.generate_step_constraints(
            cs.clone(),
            0,
            ivc_inputs_var,
            VecFpVar(external_inputs_var),
        )?;
        let z_i1_native = external_inputs_step_native(inputs_public, inputs_private);

        assert_eq!(z_i1[0].value()?, z_i1_native[0]);
        assert_eq!(z_i1[1].value()?, z_i1_native[1]);
        Ok(())
    }

    #[test]
    fn test_step_constraints() -> Result<(), Error> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let params = NONAME_CIRCUIT_EXTERNAL_INPUTS.to_owned();
        // state length = 2, external inputs length = 2
        let circuit = NonameFCircuit::<Fr, R1csBn254Field, 2, 2>::new(params)?;
        let inputs_public = vec![Fr::from(2), Fr::from(5)];
        let inputs_private = vec![Fr::from(8), Fr::from(2)];

        let ivc_inputs_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs_public))?;
        let external_inputs_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs_private))?;

        let z_i1 = circuit.generate_step_constraints(
            cs.clone(),
            0,
            ivc_inputs_var,
            VecFpVar(external_inputs_var),
        )?;
        assert!(cs.is_satisfied()?);
        assert_eq!(z_i1[0].value()?, Fr::from(10_u8));
        assert_eq!(z_i1[1].value()?, Fr::from(10_u8));
        Ok(())
    }

    #[test]
    fn test_generate_constraints_no_external_inputs() -> Result<(), Error> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let params = NONAME_CIRCUIT_NO_EXTERNAL_INPUTS.to_owned();
        let inputs_public = vec![Fr::from(2), Fr::from(5)];

        let ivc_inputs_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs_public))?;

        // state length = 2, external inputs length = 0
        let f_circuit = NonameFCircuit::<Fr, R1csBn254Field, 2, 0>::new(params)?;
        f_circuit.generate_step_constraints(cs.clone(), 0, ivc_inputs_var, VecFpVar(vec![]))?;
        assert!(cs.is_satisfied()?);
        Ok(())
    }
}
