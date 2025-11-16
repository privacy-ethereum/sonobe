use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};

pub trait Pow: Sized {
    fn powers(&self, n: usize) -> Vec<Self>;
}

impl<F: Field> Pow for F {
    fn powers(&self, n: usize) -> Vec<Self> {
        let mut res = vec![F::one(); n];
        for i in 1..n {
            res[i] = res[i - 1] * self;
        }
        res
    }
}

pub trait PowGadget: Sized {
    fn powers(&self, n: usize) -> Vec<Self>;
}

impl<F: PrimeField> PowGadget for FpVar<F> {
    fn powers(&self, n: usize) -> Vec<Self> {
        let mut res = vec![FpVar::one(); n];
        for i in 1..n {
            res[i] = &res[i - 1] * self;
        }
        res
    }
}
