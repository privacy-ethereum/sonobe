use ark_std::{
    iter::Sum,
    ops::{Add, Mul},
};

pub trait ScalarRLC<Coeff> {
    type Value;

    fn scalar_rlc(self, coeffs: &[Coeff]) -> Self::Value;
}

impl<I: Iterator + Sized, Coeff> ScalarRLC<Coeff> for I
where
    I::Item: Add<Output = I::Item> + Sum + for<'a> Mul<&'a Coeff, Output = I::Item>,
{
    type Value = I::Item;

    fn scalar_rlc(self, coeffs: &[Coeff]) -> Self::Value {
        self.zip(coeffs).map(|(v, c)| v * c).sum::<I::Item>()
    }
}

pub trait SliceRLC<Coeff> {
    type Value;

    fn slice_rlc(self, coeffs: &[Coeff]) -> Vec<Self::Value>;
}

impl<'a, T, I: Iterator<Item = &'a [T]>, Coeff> SliceRLC<Coeff> for I
where
    T: 'a + Add<Output = T> + Clone,
    for<'x> T: Mul<&'x Coeff, Output = T>,
{
    type Value = T;

    fn slice_rlc(self, coeffs: &[Coeff]) -> Vec<Self::Value> {
        let mut iter = self
            .zip(coeffs)
            .map(|(v, c)| v.iter().map(|x| x.clone() * c));
        let first = iter.next().unwrap();

        iter.fold(first.collect(), |acc, v| {
            acc.into_iter().zip(v).map(|(a, b)| a + b).collect()
        })
    }
}
