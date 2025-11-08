use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
    GR1CSVar,
};
use ark_relations::gr1cs::SynthesisError;

use super::params::GriffinParams;

impl<F: PrimeField> GriffinParams<F> {
    fn non_linear_gadget(&self, state: &[FpVar<F>]) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let cs = state.cs();
        let mut result = state.to_owned();
        // x0
        result[0] = FpVar::new_variable_with_inferred_mode(cs, || {
            Ok({
                {
                    let v = result[0].value().unwrap_or_default();
                    let mut res = F::one();
                    for &i in &self.d_inv {
                        res.square_in_place();
                        if i {
                            res *= v;
                        }
                    }
                    res
                }
            })
        })?;

        let mut sq = result[0].square()?;
        if self.d == 5 {
            sq = sq.square()?;
        }
        result[0].mul_equals(&sq, &state[0])?;

        // x1
        let mut sq = result[1].square()?;
        if self.d == 5 {
            sq = sq.square()?;
        }
        result[1] *= sq;

        let mut y01_i = result[1].clone();

        // rest of the state
        for i in 2..result.len() {
            y01_i += &result[0];
            let l = if i == 2 {
                y01_i.clone()
            } else {
                &y01_i + &state[i - 1]
            };
            let ab = &self.alpha_beta[i - 2];
            result[i] *= l.square()? + l * ab[0] + ab[1];
        }

        Ok(result)
    }

    pub fn permute_gadget(&self, state: &[FpVar<F>]) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut current_state = state.to_owned();
        current_state = self
            .mat
            .iter()
            .map(|row| current_state.iter().zip(row).map(|(a, b)| a * *b).sum())
            .collect();

        for r in 0..self.rounds {
            current_state = self.non_linear_gadget(&current_state)?;
            current_state = self
                .mat
                .iter()
                .map(|row| current_state.iter().zip(row).map(|(a, b)| a * *b).sum())
                .collect();
            if r < self.rounds - 1 {
                current_state = current_state
                    .iter()
                    .zip(&self.round_constants[r])
                    .map(|(c, rc)| c + *rc)
                    .collect();
            }
        }
        Ok(current_state)
    }

    pub fn hash_gadget(&self, message: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        let mut state = vec![FpVar::zero(); self.t];
        for chunk in message.chunks(self.rate) {
            for i in 0..chunk.len() {
                state[i] += &chunk[i];
            }
            state = self.permute_gadget(&state)?;
        }
        Ok(state[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::rand::thread_rng;

    use super::*;

    #[test]
    fn test() {
        let rng = &mut thread_rng();
        let griffin = GriffinParams::new(24, 5, 9);
        let t = griffin.t;
        let x: Vec<Fr> = (0..t).map(|_| Fr::rand(rng)).collect();

        let y = griffin.hash(&x);

        let cs = ConstraintSystem::new_ref();
        let x_var = Vec::new_witness(cs.clone(), || Ok(x.clone())).unwrap();
        let y_var = griffin.hash_gadget(&x_var).unwrap();
        assert_eq!(y, y_var.value().unwrap());
        println!("{}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }
}
