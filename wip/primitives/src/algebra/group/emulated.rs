use ark_ec::{short_weierstrass::SWFlags, AffineRepr};
use ark_ff::Zero;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeWithFlags};
use ark_std::borrow::Borrow;

use crate::{
    algebra::{field::emulated::EmulatedFieldVar, group::SonobeCurve},
    traits::SonobeField,
    transcripts::AbsorbableGadget,
};

/// NonNativeAffineVar represents an elliptic curve point in Affine representation in the non-native
/// field, over the constraint field. It is not intended to perform operations, but just to contain
/// the affine coordinates in order to perform hash operations of the point.
#[derive(Debug, Clone)]
pub struct EmulatedAffineVar<Base: SonobeField, Target: SonobeCurve> {
    pub x: EmulatedFieldVar<Base, Target::BaseField, true>,
    pub y: EmulatedFieldVar<Base, Target::BaseField, true>,
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
    pub fn zero() -> Self {
        // `unwrap` below is safe because we are allocating a constant value,
        // which is guaranteed to succeed.
        Self::new_constant(ConstraintSystemRef::None, Target::zero()).unwrap()
    }
}

impl<Base: SonobeField, Target: SonobeCurve> AbsorbableGadget<Base>
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
    use ark_std::{error::Error, UniformRand};

    use super::*;
    use crate::{
        traits::{Inputize, InputizeEmulated},
        transcripts::Absorbable,
    };

    #[test]
    fn test_alloc_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // dealing with the 'zero' point should not panic when doing the unwrap
        let p = Projective::zero();
        assert!(EmulatedAffineVar::<Fr, Projective>::new_witness(cs.clone(), || Ok(p)).is_ok());
    }

    #[test]
    fn test_improved_to_hash_preimage() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // check that point_to_nonnative_limbs returns the expected values
        let mut rng = ark_std::test_rng();
        let p = Projective::rand(&mut rng);
        let p_var = EmulatedAffineVar::<Fr, Projective>::new_witness(cs.clone(), || Ok(p))?;
        assert_eq!(p_var.to_absorbable()?.value()?, p.to_absorbable());
        Ok(())
    }

    #[test]
    fn test_inputize() -> Result<(), Box<dyn Error>> {
        // check that point_to_nonnative_limbs returns the expected values
        let mut rng = ark_std::test_rng();
        let p = Projective::rand(&mut rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let p_var = EmulatedAffineVar::<Fr, Projective>::new_witness(cs.clone(), || Ok(p))?;
        assert_eq!(
            [p_var.x.limbs.value()?, p_var.y.limbs.value()?].concat(),
            p.inputize_emulated()
        );

        let cs = ConstraintSystem::<Fq>::new_ref();
        let p_var = ProjectiveVar::<PallasConfig, FpVar<Fq>>::new_witness(cs.clone(), || Ok(p))?;
        assert_eq!(
            vec![p_var.x.value()?, p_var.y.value()?, p_var.z.value()?],
            p.inputize()
        );
        Ok(())
    }
}
