use noname::{
    backends::{Backend, BackendField, BackendVar},
    circuit_writer::{CircuitWriter, VarInfo},
    compiler::{typecheck_next_file, Sources},
    constants::Span,
    error::Result,
    imports::FnHandle,
    mast::{self, Mast},
    type_checker::TypeChecker,
    var::{Value, Var},
    witness::{CompiledCircuit, WitnessEnv},
};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LC<F: BackendField>(pub HashMap<usize, F>);

impl<F: BackendField> BackendVar for LC<F> {}

#[derive(Clone, Debug, Default)]
pub struct R1CS<F: BackendField> {
    pub constraints: Vec<(LC<F>, LC<F>, LC<F>)>,
    variables: Vec<Value<Self>>,
}

impl<F: BackendField> R1CS<F> {
    pub fn extract_witness(&self, witness_env: &mut WitnessEnv<F>) -> Result<Vec<F>> {
        self.variables
            .iter()
            .enumerate()
            .map(|(index, val)| self.compute_val(witness_env, val, index))
            .collect()
    }
}

impl<F: BackendField> Backend for R1CS<F> {
    type Field = F;
    type Var = LC<F>;
    type GeneratedWitness = Vec<F>;

    fn poseidon() -> FnHandle<Self> {
        unimplemented!()
    }

    fn init_circuit(&mut self) {
        self.new_internal_var(Value::Constant(F::one()), Span::default());
    }

    fn new_internal_var(&mut self, val: Value<Self>, _span: Span) -> LC<F> {
        let var = self.variables.len();
        self.variables.push(val);
        LC([(var, F::one())].into())
    }

    fn add_constant(&mut self, _label: Option<&'static str>, value: F, _span: Span) -> LC<F> {
        LC([(0, value)].into())
    }

    fn finalize_circuit(
        &mut self,
        public_output: Option<Var<F, LC<F>>>,
        returned_cells: Option<Vec<LC<F>>>,
        _disable_safety_check: bool,
    ) -> Result<()> {
        if let Some(public_output) = public_output {
            for (var, val) in public_output.cvars.iter().zip(returned_cells.unwrap()) {
                let &var_idx = var.cvar().unwrap().0.iter().next().unwrap().0;
                self.variables[var_idx] = Value::PublicOutput(Some(val));
            }
        }

        Ok(())
    }

    fn compute_var(&self, env: &mut WitnessEnv<F>, lc: &LC<F>) -> Result<F> {
        Ok(lc
            .0
            .iter()
            .map(|(&var, coeff)| {
                if var == 0 {
                    *coeff
                } else {
                    self.compute_val(env, &self.variables[var], var).unwrap() * coeff
                }
            })
            .sum())
    }

    fn generate_witness(
        &self,
        _witness_env: &mut WitnessEnv<F>,
        _sources: &Sources,
        _typed: &Mast<Self>,
    ) -> Result<Self::GeneratedWitness> {
        unreachable!()
    }

    fn generate_asm(&self, _sources: &Sources, _debug: bool) -> String {
        unreachable!()
    }

    fn neg(&mut self, x: &LC<F>, _span: Span) -> LC<F> {
        LC(x.0.iter().map(|(&var, &coeff)| (var, -coeff)).collect())
    }

    fn add(&mut self, lhs: &LC<F>, rhs: &LC<F>, _span: Span) -> LC<F> {
        let mut terms = lhs.0.clone();
        rhs.0.iter().for_each(|(var, c1)| {
            terms.entry(*var).and_modify(|c2| *c2 += c1).or_insert(*c1);
        });
        LC(terms)
    }

    fn add_const(&mut self, x: &LC<F>, cst: &F, _span: Span) -> LC<F> {
        let mut terms = x.0.clone();
        terms.entry(0).and_modify(|c| *c += cst).or_insert(*cst);
        LC(terms)
    }

    fn mul(&mut self, lhs: &LC<F>, rhs: &LC<F>, span: Span) -> LC<F> {
        let res = self.new_internal_var(Value::Mul(lhs.clone(), rhs.clone()), span);

        self.constraints
            .push((lhs.clone(), rhs.clone(), res.clone()));

        res
    }

    fn mul_const(&mut self, x: &LC<F>, cst: &F, _span: Span) -> LC<F> {
        LC(x.0
            .iter()
            .map(|(&var, &coeff)| (var, coeff * cst))
            .collect())
    }

    fn assert_eq_const(&mut self, x: &LC<F>, cst: F, _span: Span) {
        self.constraints
            .push((x.clone(), LC([(0, F::one())].into()), LC([(0, cst)].into())));
    }

    fn assert_eq_var(&mut self, lhs: &LC<F>, rhs: &LC<F>, _span: Span) {
        self.constraints
            .push((lhs.clone(), LC([(0, F::one())].into()), rhs.clone()));
    }

    fn add_public_input(&mut self, val: Value<Self>, span: Span) -> LC<F> {
        self.new_internal_var(val, span)
    }

    fn add_private_input(&mut self, val: Value<Self>, span: Span) -> LC<F> {
        self.new_internal_var(val, span)
    }

    fn add_public_output(&mut self, val: Value<Self>, span: Span) -> LC<F> {
        assert!(matches!(val, Value::PublicOutput(None)));
        self.new_internal_var(val, span)
    }

    fn log_var(&mut self, _var: &VarInfo<F, LC<F>>, _span: Span) {}
}

pub fn compile_source_code<BF: BackendField>(code: &str) -> Result<CompiledCircuit<R1CS<BF>>> {
    let mut sources = Sources::new();

    let mut tast = TypeChecker::<R1CS<BF>>::new();
    let node_id = 0;
    typecheck_next_file(
        &mut tast,
        None,
        &mut sources,
        "main.no".to_string(),
        code.to_string(),
        node_id,
        &mut None,
    )
    .unwrap();

    CircuitWriter::generate_circuit(mast::monomorphize(tast)?, R1CS::<BF>::default(), false)
}
