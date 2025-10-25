use ark_relations::gr1cs::SynthesisError;

pub trait Absorbable<F> {
    fn absorb_into(&self, dest: &mut Vec<F>);

    fn to_absorbable(&self) -> Vec<F> {
        let mut result = Vec::new();
        self.absorb_into(&mut result);
        result
    }
}

impl<F: From<u64>> Absorbable<F> for usize {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self as u64));
    }
}

impl<F, T: Absorbable<F>> Absorbable<F> for &T {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        <T as Absorbable<F>>::absorb_into(self, dest);
    }
}

impl<F, T: Absorbable<F>> Absorbable<F> for (T, T) {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest);
        self.1.absorb_into(dest);
    }
}

impl<F, T: Absorbable<F>> Absorbable<F> for [T] {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        for t in self.iter() {
            t.absorb_into(dest);
        }
    }
}

impl<F, T: Absorbable<F>, const N: usize> Absorbable<F> for [T; N] {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        <[T] as Absorbable<F>>::absorb_into(self, dest);
    }
}

impl<F, T: Absorbable<F>> Absorbable<F> for Vec<T> {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        <[T] as Absorbable<F>>::absorb_into(self, dest);
    }
}

/// An interface for objects that can be absorbed by a `TranscriptVar` whose constraint field
/// is `F`.
///
/// Matches `AbsorbGadget` in `ark-crypto-primitives`.
pub trait AbsorbableGadget<FV> {
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError>;

    fn to_absorbable(&self) -> Result<Vec<FV>, SynthesisError> {
        let mut result = Vec::new();
        self.absorb_into(&mut result)?;
        Ok(result)
    }
}

impl<FV, T: AbsorbableGadget<FV>> AbsorbableGadget<FV> for &T {
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        <T as AbsorbableGadget<FV>>::absorb_into(self, dest)
    }
}

impl<FV, T: AbsorbableGadget<FV>> AbsorbableGadget<FV> for (T, T) {
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)?;
        self.1.absorb_into(dest)
    }
}

impl<FV, T: AbsorbableGadget<FV>> AbsorbableGadget<FV> for [T] {
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        self.iter().try_for_each(|t| t.absorb_into(dest))
    }
}

impl<FV, T: AbsorbableGadget<FV>, const N: usize> AbsorbableGadget<FV> for [T; N] {
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        <[T] as AbsorbableGadget<FV>>::absorb_into(self, dest)
    }
}

impl<FV, T: AbsorbableGadget<FV>> AbsorbableGadget<FV> for Vec<T> {
    fn absorb_into(&self, dest: &mut Vec<FV>) -> Result<(), SynthesisError> {
        <[T] as AbsorbableGadget<FV>>::absorb_into(self, dest)
    }
}
