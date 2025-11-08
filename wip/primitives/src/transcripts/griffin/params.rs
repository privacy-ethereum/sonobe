use ark_ff::{LegendreSymbol, PrimeField};
use num_bigint::BigUint;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake128Reader,
};

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
        assert!(t == 3 || t % 4 == 0);
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

    pub fn get_t(&self) -> usize {
        self.t
    }

    pub fn get_rounds(&self) -> usize {
        self.rounds
    }
}
