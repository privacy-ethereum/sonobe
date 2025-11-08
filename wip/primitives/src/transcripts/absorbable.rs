use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

pub trait Absorbable {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>);

    fn to_absorbable<F: PrimeField>(&self) -> Vec<F> {
        let mut result = Vec::new();
        self.absorb_into(&mut result);
        result
    }
}

impl Absorbable for usize {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self as u64));
    }
}

impl<T: Absorbable> Absorbable for &T {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self).absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for (T, T) {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest);
        self.1.absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for [T] {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        for t in self.iter() {
            t.absorb_into(dest);
        }
    }
}

impl<T: Absorbable, const N: usize> Absorbable for [T; N] {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.as_ref().absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for Vec<T> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.as_slice().absorb_into(dest);
    }
}

/// An interface for objects that can be absorbed by a `TranscriptVar` whose constraint field
/// is `F`.
///
/// Matches `AbsorbGadget` in `ark-crypto-primitives`.
pub trait AbsorbableGadget<F: PrimeField> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError>;

    fn to_absorbable(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut result = Vec::new();
        self.absorb_into(&mut result)?;
        Ok(result)
    }
}

impl<F: PrimeField, T: AbsorbableGadget<F>> AbsorbableGadget<F> for &T {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        (*self).absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableGadget<F>> AbsorbableGadget<F> for (T, T) {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)?;
        self.1.absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableGadget<F>> AbsorbableGadget<F> for [T] {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.iter().try_for_each(|t| t.absorb_into(dest))
    }
}

impl<F: PrimeField, T: AbsorbableGadget<F>, const N: usize> AbsorbableGadget<F> for [T; N] {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.as_ref().absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableGadget<F>> AbsorbableGadget<F> for Vec<T> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.as_slice().absorb_into(dest)
    }
}
