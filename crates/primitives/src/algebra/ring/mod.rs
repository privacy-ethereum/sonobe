use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{
    array,
    fmt::Debug,
    io::Read,
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

use crate::{algebra::field::SonobeField, transcripts::Absorbable};

pub trait PolynomialRingConfig:
    'static
    + Clone
    + Debug
    + Default
    + Eq
    + PartialEq
    + Send
    + Sync
    + CanonicalDeserialize
    + CanonicalSerialize
{
    const DEGREE: usize;

    const CYCLOTOMIC_POLYNOMIAL: &'static [(usize, i64)];

    fn inner_product_transform<F: Field>(v: &[F]) -> Vec<F> {
        let mut constant_terms = vec![0; Self::DEGREE * 2 - 1];
        constant_terms[0] = 1;
        for k in Self::DEGREE..Self::DEGREE * 2 - 1 {
            for (m, f) in Self::CYCLOTOMIC_POLYNOMIAL {
                if m != &Self::DEGREE {
                    constant_terms[k] -= f * constant_terms[k + m - Self::DEGREE];
                }
            }
        }
        let m = (0..Self::DEGREE)
            .map(|i| {
                (0..Self::DEGREE)
                    .map(|j| constant_terms[i + j])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        todo!()
    }

    fn rot<F: Field>(a: &[F], col: usize, row: usize) -> F;

    fn mul<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
        let mut result = vec![F::zero(); Self::DEGREE];
        for i in 0..Self::DEGREE {
            for j in 0..Self::DEGREE {
                result[j] += b[i] * Self::rot(a, i, j);
            }
        }
        result
    }

    fn mul_small<F: Field>(a: &[F], b: &[i8]) -> Vec<F> {
        let mut result = vec![F::zero(); Self::DEGREE];
        for i in 0..Self::DEGREE {
            if b[i] == 0 {
                continue;
            }
            for j in 0..Self::DEGREE {
                let rot = Self::rot(a, i, j);
                match b[i] {
                    1 => result[j] += rot,
                    -1 => result[j] -= rot,
                    v => result[j] += rot * F::from(v),
                };
            }
        }
        result
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize)]
pub struct Config1;

impl Valid for Config1 {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for Config1 {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Ok(Self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize)]
pub struct Config2;

impl Valid for Config2 {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for Config2 {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Ok(Self)
    }
}

impl PolynomialRingConfig for Config1 {
    const DEGREE: usize = 54;

    const CYCLOTOMIC_POLYNOMIAL: &'static [(usize, i64)] = &PHI_81;

    fn rot<F: Field>(a: &[F], col: usize, mut row: usize) -> F {
        let mut res = F::zero();
        let h = Self::DEGREE / 2;
        let m = row;

        if row >= col && row - col < Self::DEGREE {
            res += a[row - col];
        }
        row += h;
        if m >= h && row >= col && row - col < Self::DEGREE {
            res -= a[row - col];
        }
        row += h;
        if m < h && row >= col && row - col < Self::DEGREE {
            res -= a[row - col];
        }
        row += h;
        if row >= col && row - col < Self::DEGREE {
            res += a[row - col];
        }
        res
    }

    fn inner_product_transform<F: Field>(v: &[F]) -> Vec<F> {
        let mut res = vec![F::zero(); v.len()];
        res[0] = v[0];
        for i in 1..=Self::DEGREE / 2 {
            res[Self::DEGREE - i] = -v[i];
        }
        for i in Self::DEGREE / 2 + 1..Self::DEGREE {
            res[Self::DEGREE - i] = res[3 * Self::DEGREE / 2 - i] - v[i];
        }
        res
    }
}

impl PolynomialRingConfig for Config2 {
    const DEGREE: usize = 64;

    const CYCLOTOMIC_POLYNOMIAL: &'static [(usize, i64)] = &PHI_128;

    fn rot<F: Field>(a: &[F], col: usize, row: usize) -> F {
        if row >= col {
            a[row - col]
        } else {
            -a[row + Self::DEGREE - col]
        }
    }

    fn inner_product_transform<F: Field>(v: &[F]) -> Vec<F> {
        let mut res = vec![v[0]];
        for i in 1..Self::DEGREE {
            res.push(-v[Self::DEGREE - i]);
        }
        res
    }
}

const PHI_81: [(usize, i64); 3] = [(0, 1), (27, 1), (54, 1)];
const PHI_128: [(usize, i64); 2] = [(0, 1), (64, 1)];

#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PolynomialRingOverField<Cfg: PolynomialRingConfig, F: Field> {
    pub _t: PhantomData<Cfg>,
    pub coeffs: Vec<F>,
}

impl<Cfg: PolynomialRingConfig, F: Field> Default for PolynomialRingOverField<Cfg, F> {
    fn default() -> Self {
        Self {
            _t: PhantomData,
            coeffs: vec![F::zero(); Cfg::DEGREE],
        }
    }
}

impl<Cfg: PolynomialRingConfig, K: Field + Absorbable> Absorbable
    for PolynomialRingOverField<Cfg, K>
{
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.coeffs.absorb_into(dest)
    }
}

impl<Cfg: PolynomialRingConfig, F: Field> PolynomialRingOverField<Cfg, F> {
    pub fn element_embedding(v: Vec<F>) -> Self {
        assert_eq!(v.len(), Cfg::DEGREE);
        Self {
            _t: PhantomData,
            coeffs: v,
        }
    }

    pub fn element_unembedding(self) -> Vec<F> {
        self.coeffs
    }

    pub fn vector_embedding(v: Vec<F>) -> Vec<Self> {
        assert!(v.len().is_multiple_of(Cfg::DEGREE));

        v.chunks(Cfg::DEGREE)
            .map(|chunk| Self::element_embedding(chunk.to_vec()))
            .collect()
    }

    pub fn vector_unembedding(v: Vec<Self>) -> Vec<F> {
        v.into_iter().flat_map(|i| i.coeffs).collect()
    }

    pub fn matrix_embedding(m: Vec<Vec<F>>) -> Vec<Vec<Self>> {
        m.into_iter().map(Self::vector_embedding).collect()
    }

    pub fn matrix_unembedding(m: Vec<Vec<Self>>) -> Vec<Vec<F>> {
        m.into_iter().map(Self::vector_unembedding).collect()
    }

    pub fn element_transform(v: Vec<F>) -> Self {
        Self::element_embedding(Cfg::inner_product_transform(&v))
    }

    pub fn vector_transform(v: Vec<F>) -> Vec<Self> {
        assert!(v.len().is_multiple_of(Cfg::DEGREE));

        v.chunks(Cfg::DEGREE)
            .map(|chunk| Self::element_transform(chunk.to_vec()))
            .collect()
    }

    pub fn matrix_transform(m: Vec<Vec<F>>) -> Vec<Vec<Self>> {
        m.into_iter().map(Self::vector_transform).collect()
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            _t: PhantomData,
            coeffs: self
                .coeffs
                .iter()
                .zip(&other.coeffs)
                .map(|(a, b)| *a + b)
                .collect::<Vec<_>>(),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self {
            _t: PhantomData,
            coeffs: self
                .coeffs
                .iter()
                .zip(&other.coeffs)
                .map(|(a, b)| *a - b)
                .collect::<Vec<_>>(),
        }
    }

    pub fn scale(&self, other: F) -> Self {
        Self {
            _t: PhantomData,
            coeffs: self.coeffs.iter().map(|a| other * a).collect::<Vec<_>>(),
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        Self {
            _t: PhantomData,
            coeffs: Cfg::mul(&self.coeffs, &other.coeffs),
        }
    }

    pub fn mul_small(&self, other: &[i8]) -> Self {
        Self {
            _t: PhantomData,
            coeffs: Cfg::mul_small(&self.coeffs, &other),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use ark_pallas::Fr;
    use ark_std::rand::thread_rng;

    use super::*;

    #[test]
    fn test() {
        let mut rng = thread_rng();

        let a = (0..Config1::DEGREE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let b = (0..Config1::DEGREE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let ip = a.iter().zip(&b).map(|(a, b)| a * b).sum::<Fr>();

        let prod = PolynomialRingOverField::<Config1, _>::element_transform(a.clone()).mul(
            &PolynomialRingOverField::<Config1, _>::element_embedding(b.clone()),
        );

        assert_eq!(ip, prod.coeffs[0])
    }
}
