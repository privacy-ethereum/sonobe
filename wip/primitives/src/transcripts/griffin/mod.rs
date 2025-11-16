use ark_ff::{LegendreSymbol, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
    GR1CSVar,
};
use ark_relations::gr1cs::SynthesisError;
use num_bigint::BigUint;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake128Reader,
};

pub mod sponge;

pub fn field_element_from_shake<F: PrimeField>(reader: &mut impl XofReader) -> F {
    let mut buf = vec![0u8; F::MODULUS_BIT_SIZE.div_ceil(8) as usize];

    loop {
        reader.read(&mut buf);
        if let Some(el) = F::from_random_bytes(&buf) {
            return el;
        }
    }
}

pub fn field_element_from_shake_without_0<F: PrimeField>(reader: &mut impl XofReader) -> F {
    loop {
        let element = field_element_from_shake::<F>(reader);
        if !element.is_zero() {
            return element;
        }
    }
}

#[derive(Clone, Debug)]
pub struct GriffinParams<F: PrimeField> {
    pub(crate) round_constants: Vec<Vec<F>>,
    pub(crate) t: usize,
    pub(crate) d: usize,
    pub(crate) d_inv: Vec<bool>,
    pub(crate) rounds: usize,
    pub(crate) alpha_beta: Vec<[F; 2]>,
    pub(crate) mat: Vec<Vec<F>>,
    pub rate: usize,
    pub capacity: usize,
}

impl<F: PrimeField> GriffinParams<F> {
    pub const INIT_SHAKE: &'static str = "Griffin";

    pub fn new(t: usize, d: usize, rounds: usize) -> Self {
        assert!(t == 3 || t.is_multiple_of(4));
        assert!(d == 3 || d == 5);
        assert!(rounds >= 1);

        let mut shake = Self::init_shake();

        let d_inv = Self::calculate_d_inv(d as u64)
            .to_radix_be(2)
            .into_iter()
            .map(|i| i != 0)
            .skip_while(|i| !i)
            .collect();
        let round_constants = Self::instantiate_rc(t, rounds, &mut shake);
        let alpha_beta = Self::instantiate_alpha_beta(t, &mut shake);

        let mat = Self::instantiate_matrix(t);

        GriffinParams {
            round_constants,
            t,
            d,
            d_inv,
            rounds,
            alpha_beta,
            mat,
            rate: t - 1,
            capacity: 1,
        }
    }

    fn calculate_d_inv(d: u64) -> BigUint {
        let p_1 = -F::one();
        BigUint::from(d).modinv(&p_1.into()).unwrap()
    }

    fn init_shake() -> Shake128Reader {
        let mut shake = Shake128::default();
        shake.update(Self::INIT_SHAKE.as_bytes());
        for i in F::characteristic() {
            shake.update(&i.to_le_bytes());
        }
        shake.finalize_xof()
    }

    fn instantiate_rc(t: usize, rounds: usize, shake: &mut Shake128Reader) -> Vec<Vec<F>> {
        (0..rounds - 1)
            .map(|_| (0..t).map(|_| field_element_from_shake(shake)).collect())
            .collect()
    }

    fn instantiate_alpha_beta(t: usize, shake: &mut Shake128Reader) -> Vec<[F; 2]> {
        let mut alpha_beta = Vec::with_capacity(t - 2);

        // random alpha/beta
        loop {
            let alpha = field_element_from_shake_without_0::<F>(shake);
            let mut beta = field_element_from_shake_without_0::<F>(shake);
            // distinct
            while alpha == beta {
                beta = field_element_from_shake_without_0::<F>(shake);
            }
            let mut symbol = alpha;
            symbol.square_in_place();
            let mut tmp = beta;
            tmp.double_in_place();
            tmp.double_in_place();
            symbol.sub_assign(&tmp);
            if symbol.legendre() == LegendreSymbol::QuadraticNonResidue {
                alpha_beta.push([alpha, beta]);
                break;
            }
        }

        // other alphas/betas
        for i in 2..t - 1 {
            let mut alpha = alpha_beta[0][0];
            let mut beta = alpha_beta[0][1];
            alpha.mul_assign(&F::from(i as u64));
            beta.mul_assign(&F::from((i * i) as u64));
            // distinct
            while alpha == beta {
                beta = field_element_from_shake_without_0::<F>(shake);
            }

            #[cfg(debug_assertions)]
            {
                // check if really ok
                let mut symbol = alpha;
                symbol.square_in_place();
                let mut tmp = beta;
                tmp.double_in_place();
                tmp.double_in_place();
                symbol.sub_assign(&tmp);
                assert_eq!(symbol.legendre(), LegendreSymbol::QuadraticNonResidue);
            }

            alpha_beta.push([alpha, beta]);
        }

        alpha_beta
    }

    fn circ_mat(row: &[F]) -> Vec<Vec<F>> {
        let t = row.len();
        let mut mat: Vec<Vec<F>> = Vec::with_capacity(t);
        let mut rot = row.to_owned();
        mat.push(rot.clone());
        for _ in 1..t {
            rot.rotate_right(1);
            mat.push(rot.clone());
        }
        mat
    }

    fn instantiate_matrix(t: usize) -> Vec<Vec<F>> {
        if t == 3 {
            let row = vec![F::from(2), F::from(1), F::from(1)];
            Self::circ_mat(&row)
        } else {
            let row1 = vec![F::from(5), F::from(7), F::from(1), F::from(3)];
            let row2 = vec![F::from(4), F::from(6), F::from(1), F::from(1)];
            let row3 = vec![F::from(1), F::from(3), F::from(5), F::from(7)];
            let row4 = vec![F::from(1), F::from(1), F::from(4), F::from(6)];
            let c_mat = vec![row1, row2, row3, row4];
            if t == 4 {
                c_mat
            } else {
                assert_eq!(t % 4, 0);
                let mut mat: Vec<Vec<F>> = vec![vec![F::zero(); t]; t];
                for (row, matrow) in mat.iter_mut().enumerate().take(t) {
                    for (col, matitem) in matrow.iter_mut().enumerate().take(t) {
                        let row_mod = row % 4;
                        let col_mod = col % 4;
                        *matitem = c_mat[row_mod][col_mod];
                        if row / 4 == col / 4 {
                            matitem.add_assign(&c_mat[row_mod][col_mod]);
                        }
                    }
                }
                mat
            }
        }
    }
}

impl<S: PrimeField> GriffinParams<S> {
    fn affine_3(&self, input: &mut [S], round: usize) {
        // multiplication by circ(2 1 1) is equal to state + sum(state)
        let mut sum = input[0];
        input.iter().skip(1).for_each(|el| sum.add_assign(el));

        if round < self.rounds - 1 {
            for (el, rc) in input.iter_mut().zip(self.round_constants[round].iter()) {
                el.add_assign(&sum);
                el.add_assign(rc); // add round constant
            }
        } else {
            // no round constant
            for el in input.iter_mut() {
                el.add_assign(&sum);
            }
        }
    }

    fn affine_4(&self, input: &mut [S], round: usize) {
        let mut t_0 = input[0];
        t_0.add_assign(&input[1]);
        let mut t_1 = input[2];
        t_1.add_assign(&input[3]);
        let mut t_2 = input[1];
        t_2.double_in_place();
        t_2.add_assign(&t_1);
        let mut t_3 = input[3];
        t_3.double_in_place();
        t_3.add_assign(&t_0);
        let mut t_4 = t_1;
        t_4.double_in_place();
        t_4.double_in_place();
        t_4.add_assign(&t_3);
        let mut t_5 = t_0;
        t_5.double_in_place();
        t_5.double_in_place();
        t_5.add_assign(&t_2);
        let mut t_6 = t_3;
        t_6.add_assign(&t_5);
        let mut t_7 = t_2;
        t_7.add_assign(&t_4);
        input[0] = t_6;
        input[1] = t_5;
        input[2] = t_7;
        input[3] = t_4;

        if round < self.rounds - 1 {
            for (i, rc) in input.iter_mut().zip(self.round_constants[round].iter()) {
                i.add_assign(rc);
            }
        }
    }

    fn affine(&self, input: &mut [S], round: usize) {
        if self.t == 3 {
            self.affine_3(input, round);
            return;
        }
        if self.t == 4 {
            self.affine_4(input, round);
            return;
        }

        // first matrix
        let t4 = self.t / 4;
        for i in 0..t4 {
            let start_index = i * 4;
            let mut t_0 = input[start_index];
            t_0.add_assign(&input[start_index + 1]);
            let mut t_1 = input[start_index + 2];
            t_1.add_assign(&input[start_index + 3]);
            let mut t_2 = input[start_index + 1];
            t_2.double_in_place();
            t_2.add_assign(&t_1);
            let mut t_3 = input[start_index + 3];
            t_3.double_in_place();
            t_3.add_assign(&t_0);
            let mut t_4: S = t_1;
            t_4.double_in_place();
            t_4.double_in_place();
            t_4.add_assign(&t_3);
            let mut t_5 = t_0;
            t_5.double_in_place();
            t_5.double_in_place();
            t_5.add_assign(&t_2);
            input[start_index] = t_3 + t_5;
            input[start_index + 1] = t_5;
            input[start_index + 2] = t_2 + t_4;
            input[start_index + 3] = t_4;
        }

        // second matrix
        let mut stored = [S::zero(); 4];
        for l in 0..4 {
            stored[l] = input[l];
            for j in 1..t4 {
                stored[l].add_assign(&input[4 * j + l]);
            }
        }

        for i in 0..input.len() {
            input[i].add_assign(&stored[i % 4]);
            if round < self.rounds - 1 {
                input[i].add_assign(&self.round_constants[round][i]); // add round constant
            }
        }
    }

    fn non_linear(&self, input: &mut [S]) {
        // first two state words
        input[0] = {
            let mut res = S::one();
            for &i in &self.d_inv {
                res.square_in_place();
                if i {
                    res *= input[0];
                }
            }
            res
        };

        let mut state = input[1];

        input[1].square_in_place();
        match self.d {
            3 => {}
            5 => {
                input[1].square_in_place();
            }
            _ => panic!(),
        }
        input[1].mul_assign(&state);

        let mut y01_i = input[1];
        // rest of the state
        for i in 2..input.len() {
            y01_i += input[0];
            let l = if i == 2 { y01_i } else { y01_i + state };
            let ab = &self.alpha_beta[i - 2];
            state = input[i];
            input[i] *= l.square() + l * ab[0] + ab[1];
        }
    }

    pub fn permute(&self, input: &mut [S]) {
        self.affine(input, self.rounds); // no RC

        for r in 0..self.rounds {
            self.non_linear(input);
            self.affine(input, r);
        }
    }

    pub fn hash(&self, message: &[S]) -> S {
        let mut state = vec![S::zero(); self.t];
        for chunk in message.chunks(self.rate) {
            for i in 0..chunk.len() {
                state[i] += &chunk[i];
            }
            self.permute(&mut state)
        }
        state[0]
    }
}

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

#[cfg(test)]
mod griffin_tests_bn256 {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_std::rand::thread_rng;

    use super::*;

    static TESTRUNS: usize = 5;

    #[test]
    fn consistent_perm() {
        let rng = &mut thread_rng();
        let griffin = GriffinParams::new(3, 5, 12);
        let t = griffin.t;
        for _ in 0..TESTRUNS {
            let input1: Vec<_> = (0..t).map(|_| Fr::rand(rng)).collect();

            let mut input2: Vec<_>;
            loop {
                input2 = (0..t).map(|_| Fr::rand(rng)).collect();
                if input1 != input2 {
                    break;
                }
            }

            let mut perm1 = input1.clone();
            let mut perm2 = input1.clone();
            let mut perm3 = input2.clone();
            griffin.permute(&mut perm1);
            griffin.permute(&mut perm2);
            griffin.permute(&mut perm3);
            assert_eq!(perm1, perm2);
            assert_ne!(perm1, perm3);
        }
    }

    fn matmul<F: PrimeField>(input: &[F], mat: &[Vec<F>]) -> Vec<F> {
        let t = mat.len();
        debug_assert!(t == input.len());
        let mut out = vec![F::zero(); t];
        for row in 0..t {
            for (col, inp) in input.iter().enumerate() {
                let mut tmp = mat[row][col];
                tmp *= inp;
                out[row] += &tmp;
            }
        }
        out
    }

    fn affine_test<F: PrimeField>(t: usize) {
        let rng = &mut thread_rng();
        let griffin = GriffinParams::<F>::new(t, 5, 1);

        let mat = &griffin.mat;

        for _ in 0..TESTRUNS {
            let input: Vec<F> = (0..t).map(|_| F::rand(rng)).collect();

            // affine 1
            let output1 = matmul(&input, mat);
            let mut output2 = input.to_owned();
            griffin.affine(&mut output2, 1);
            assert_eq!(output1, output2);
        }
    }

    #[test]
    fn affine_3() {
        affine_test::<Fr>(3);
    }

    #[test]
    fn affine_4() {
        affine_test::<Fr>(4);
    }

    #[test]
    fn affine_8() {
        affine_test::<Fr>(8);
    }

    #[test]
    fn affine_60() {
        affine_test::<Fr>(60);
    }
}
