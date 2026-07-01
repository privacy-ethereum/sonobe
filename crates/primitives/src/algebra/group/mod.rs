//! This module defines extension traits for elliptic curve points and their
//! in-circuit counterparts, along with some common implementations.

use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::{
    convert::ToConstraintFieldGadget,
    fields::fp::FpVar,
    groups::{CurveVar, curves::short_weierstrass::ProjectiveVar},
};
use ark_relations::gr1cs::SynthesisError;

#[cfg(feature = "evm")]
use crate::utils::evm::serialize::EVMSerialize;
use crate::{
    algebra::{
        Val,
        field::{SonobeField, emulated::EmulatedFieldVar},
        group::emulated::EmulatedAffineVar,
    },
    circuits::{WitnessToPublic, inputize::Inputize},
    transcripts::{Absorbable, AbsorbableVar},
    utils::dummy::Dummy,
};

pub mod emulated;

/// [`CF1`] is a type alias for the scalar field of a curve `C`.
pub type CF1<C> = <C as PrimeGroup>::ScalarField;
/// [`CF2`] is a type alias for the base field of a curve `C`.
pub type CF2<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// [`SonobeCurve`] trait is a wrapper around [`CurveGroup`] that also includes
/// necessary bounds for the curve to be used conveniently in folding schemes.
pub trait SonobeCurve:
    CurveGroup<ScalarField: SonobeField, BaseField: SonobeField, Config: SWCurveConfig>
    + Absorbable
    + Val<
        Var: CurveVar<Self, Self::BaseField>
                 + AbsorbableVar<Self::BaseField>
                 + WitnessToPublic
                 + Inputize<Self::BaseField>,
        EmulatedVar<Self::ScalarField> = EmulatedAffineVar<Self::ScalarField, Self>,
    >
{
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> SonobeCurve
    for Projective<P>
{
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> Val for Projective<P> {
    type PreferredConstraintField = P::BaseField;
    type Var = ProjectiveVar<P, FpVar<P::BaseField>>;

    type EmulatedVar<F: SonobeField> = EmulatedAffineVar<F, Self>;
}

impl<T, C: SonobeCurve> Dummy<T> for C {
    fn dummy(_: T) -> Self {
        Default::default()
    }
}

impl<P: SWCurveConfig<BaseField: Absorbable>> Absorbable for Projective<P> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();
        [x, y].absorb_into(dest);
    }
}

impl<P: SWCurveConfig<BaseField: PrimeField>> AbsorbableVar<P::BaseField>
    for ProjectiveVar<P, FpVar<P::BaseField>>
{
    fn absorb_into(&self, dest: &mut Vec<FpVar<P::BaseField>>) -> Result<(), SynthesisError> {
        let mut vec = self.to_constraint_field()?;
        // The last element in the vector tells whether the point is infinity,
        // but we can in fact avoid absorbing it without loss of soundness.
        // This is because the `to_constraint_field` method internally invokes
        // [`ProjectiveVar::to_afine`](https://github.com/arkworks-rs/r1cs-std/blob/4020fbc22625621baa8125ede87abaeac3c1ca26/src/groups/curves/short_weierstrass/mod.rs#L160-L195),
        // which guarantees that an infinity point is represented as `(0, 0)`,
        // but the y-coordinate of a non-infinity point is never 0 (for why, see
        // https://crypto.stackexchange.com/a/108242 ).
        vec.pop();
        dest.extend(vec);
        Ok(())
    }
}

impl<P: SWCurveConfig<BaseField: PrimeField>> Inputize<P::BaseField>
    for ProjectiveVar<P, FpVar<P::BaseField>>
{
    fn inputize(value: &Self::Value) -> Vec<P::BaseField> {
        let affine = value.into_affine();
        match affine.xy() {
            Some((x, y)) => vec![x, y, One::one()],
            None => vec![Zero::zero(), One::one(), Zero::zero()],
        }
    }
}

impl<Base: SonobeField, Target: SonobeCurve> Inputize<Base> for EmulatedAffineVar<Base, Target> {
    fn inputize(value: &Self::Value) -> Vec<Base> {
        let affine = value.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();
        <[EmulatedFieldVar<Base, Target::BaseField>]>::inputize(&vec![x, y])
    }
}

impl<P: SWCurveConfig<BaseField: PrimeField>> WitnessToPublic
    for ProjectiveVar<P, FpVar<P::BaseField>>
{
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        // We only need the x and y coordinates of the point, but the `infinity`
        // flag is not necessary.
        self.to_constraint_field()?[..2].mark_as_public()
    }
}

impl<Base: SonobeField, Target: SonobeCurve> WitnessToPublic for EmulatedAffineVar<Base, Target> {
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        self.x.mark_as_public()?;
        self.y.mark_as_public()?;
        Ok(())
    }
}

#[cfg(feature = "evm")]
impl<P: SWCurveConfig<BaseField: EVMSerialize>> EVMSerialize for Affine<P> {
    fn to_calldata(&self) -> Vec<u8> {
        // the encoding of the additive identity is [0, 0] on the EVM
        let (x, y) = self.xy().unwrap_or_default();

        [x.to_calldata(), y.to_calldata()].concat()
    }
}

#[cfg(feature = "evm")]
impl<P: SWCurveConfig<BaseField: EVMSerialize>> EVMSerialize for Projective<P> {
    fn to_calldata(&self) -> Vec<u8> {
        self.into_affine().to_calldata()
    }
}
