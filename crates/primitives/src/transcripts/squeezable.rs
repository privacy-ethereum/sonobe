use ark_ff::{
    Field, Fp, Fp2, Fp2Config, Fp3, Fp3Config, Fp4, Fp4Config, Fp6, Fp6Config, Fp12, Fp12Config,
    FpConfig, PrimeField,
};
use ark_std::array;

pub trait Squeezable<F: PrimeField> {
    fn size() -> usize;

    fn squeeze_from(v: Vec<F>) -> Self;
}

impl<F: PrimeField, T: Squeezable<F>, const N: usize> Squeezable<F> for [T; N] {
    fn size() -> usize {
        N * T::size()
    }

    fn squeeze_from(v: Vec<F>) -> Self {
        let chunk_size = T::size();

        array::from_fn(|i| {
            let start = i * chunk_size;
            let end = start + chunk_size;

            T::squeeze_from(v[start..end].to_vec())
        })
    }
}
