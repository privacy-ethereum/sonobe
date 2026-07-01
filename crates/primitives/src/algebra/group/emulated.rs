//! This module provides implementation of in-circuit variables for emulated
//! elliptic curve points.
//!
//! This is useful when we want to express points whose coordinates lie in a
//! different field than the circuit's constraint field.
//!
//! Note that currently this module only provides the representation of such
//! points, without any arithmetic operations.

use ark_ec::{AffineRepr, short_weierstrass::SWFlags};
use ark_ff::Zero;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeWithFlags};
use ark_std::borrow::Borrow;

use crate::{
    algebra::{
        field::{SonobeField, emulated::EmulatedFieldVar},
        group::SonobeCurve,
    },
    transcripts::AbsorbableVar,
};

/// [`EmulatedAffineVar`] defines an in-circuit elliptic curve point with its
/// affine representation, where the coordinates are in the curve's base field
/// `Target::BaseField` and are emulated over the constraint field `Base` in the
/// circuit.
#[derive(Debug, Clone)]
pub struct EmulatedAffineVar<Base: SonobeField, Target: SonobeCurve> {
    /// [`EmulatedAffineVar::x`] is the x-coordinate of the point's affine
    /// representation.
    pub x: EmulatedFieldVar<Base, Target::BaseField>,
    /// [`EmulatedAffineVar::y`] is the y-coordinate of the point's affine
    /// representation.
    pub y: EmulatedFieldVar<Base, Target::BaseField>,
}

impl<Base: SonobeField, Target: SonobeCurve> AllocVar<Target, Base>
    for EmulatedAffineVar<Base, Target>
{
    fn new_variable<T: Borrow<Target>>(
        cs: impl Into<Namespace<Base>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            let affine = val.borrow().into_affine();
            let (x, y) = affine.xy().unwrap_or_default();

            let x = EmulatedFieldVar::new_variable(cs.clone(), || Ok(x), mode)?;
            let y = EmulatedFieldVar::new_variable(cs.clone(), || Ok(y), mode)?;

            Ok(Self { x, y })
        })
    }
}

impl<Base: SonobeField, Target: SonobeCurve> GR1CSVar<Base> for EmulatedAffineVar<Base, Target> {
    type Value = Target;

    fn cs(&self) -> ConstraintSystemRef<Base> {
        self.x.cs().or(self.y.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let x = self.x.value()?;
        let y = self.y.value()?;
        // Below is a workaround to convert the `x` and `y` coordinates to a
        // point. This is because the `SonobeCurve` trait does not provide a
        // method to construct a point from `BaseField` elements.
        let mut bytes = vec![];
        // `unwrap` below is safe because serialization of a `PrimeField` value
        // only fails if the serialization flag has more than 8 bits, but here
        // we call `serialize_uncompressed` which uses an empty flag.
        x.serialize_uncompressed(&mut bytes).unwrap();
        // `unwrap` below is also safe, because the bit size of `SWFlags` is 2.
        y.serialize_with_flags(
            &mut bytes,
            if x.is_zero() && y.is_zero() {
                SWFlags::PointAtInfinity
            } else if y <= -y {
                SWFlags::YIsPositive
            } else {
                SWFlags::YIsNegative
            },
        )
        .unwrap();
        // `unwrap` below is safe because `bytes` is constructed from the `x`
        // and `y` coordinates of a valid point, and these coordinates are
        // serialized in the same way as the `SonobeCurve` implementation.
        Ok(Target::deserialize_uncompressed_unchecked(&bytes[..]).unwrap())
    }
}

impl<Base: SonobeField, Target: SonobeCurve> EqGadget<Base> for EmulatedAffineVar<Base, Target> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<Base>, SynthesisError> {
        Ok(self.x.is_eq(&other.x)? & self.y.is_eq(&other.y)?)
    }

    fn enforce_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        self.x.enforce_equal(&other.x)?;
        self.y.enforce_equal(&other.y)?;
        Ok(())
    }
}

impl<Base: SonobeField, Target: SonobeCurve> EmulatedAffineVar<Base, Target> {
    /// [`EmulatedAffineVar::zero`] allocates the zero point (point at infinity)
    /// of the curve as a constant.
    pub fn zero() -> Self {
        // `unwrap` below is safe because we are allocating a constant value,
        // which is guaranteed to succeed.
        Self::new_constant(ConstraintSystemRef::None, Target::zero()).unwrap()
    }
}

impl<Base: SonobeField, Target: SonobeCurve> AbsorbableVar<Base>
    for EmulatedAffineVar<Base, Target>
{
    fn absorb_into(&self, dest: &mut Vec<FpVar<Base>>) -> Result<(), SynthesisError> {
        (&self.x, &self.y).absorb_into(dest)
    }
}

impl<Base: SonobeField, Target: SonobeCurve> CondSelectGadget<Base>
    for EmulatedAffineVar<Base, Target>
{
    fn conditionally_select(
        cond: &Boolean<Base>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            x: cond.select(&true_value.x, &false_value.x)?,
            y: cond.select(&true_value.y, &false_value.y)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ark_pallas::{Fq, Fr, PallasConfig, Projective};
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{UniformRand, error::Error, rand::thread_rng};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{circuits::inputize::Inputize, transcripts::Absorbable};

    #[test]
    fn test_alloc_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // dealing with the 'zero' point should not panic when doing the unwrap
        let p = Projective::zero();
        assert!(EmulatedAffineVar::<Fr, Projective>::new_witness(cs.clone(), || Ok(p)).is_ok());
    }

    #[test]
    fn test_to_hash_preimage() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut rng = thread_rng();
        let p = Projective::rand(&mut rng);
        let p_var = EmulatedAffineVar::<Fr, Projective>::new_witness(cs.clone(), || Ok(p))?;

        let mut v = vec![];
        let mut v_var = vec![];
        p.absorb_into(&mut v);
        p_var.absorb_into(&mut v_var)?;

        assert_eq!(v_var.value()?, v);
        Ok(())
    }

    #[test]
    fn test_inputize() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let p = Projective::rand(&mut rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let p_var = EmulatedAffineVar::<Fr, Projective>::new_witness(cs.clone(), || Ok(p))?;
        assert_eq!(
            [p_var.x.limbs.value()?, p_var.y.limbs.value()?].concat(),
            EmulatedAffineVar::inputize(&p)
        );

        let cs = ConstraintSystem::<Fq>::new_ref();
        let p_var = ProjectiveVar::<PallasConfig, FpVar<Fq>>::new_witness(cs.clone(), || Ok(p))?;
        assert_eq!(
            vec![p_var.x.value()?, p_var.y.value()?, p_var.z.value()?],
            ProjectiveVar::inputize(&p)
        );
        Ok(())
    }
}
