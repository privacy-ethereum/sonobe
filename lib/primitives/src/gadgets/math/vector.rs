use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

pub trait VectorGadget<FV> {
    fn add(&self, other: &Self) -> Result<Vec<FV>, SynthesisError>;

    fn scale(&self, scalar: &FV) -> Result<Vec<FV>, SynthesisError>;

    fn hadamard(&self, other: &Self) -> Result<Vec<FV>, SynthesisError>;
}

impl<F: PrimeField> VectorGadget<FpVar<F>> for [FpVar<F>] {
    fn add(&self, other: &Self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        if self.len() != other.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(self.iter().zip(other.iter()).map(|(a, b)| a + b).collect())
    }

    fn scale(&self, scalar: &FpVar<F>) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(self.iter().map(|a| a * scalar).collect())
    }

    fn hadamard(&self, other: &Self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        if self.len() != other.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(self.iter().zip(other.iter()).map(|(a, b)| a * b).collect())
    }
}
