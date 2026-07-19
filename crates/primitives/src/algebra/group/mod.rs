//! This module defines extension traits for elliptic curve points and their
//! in-circuit counterparts, along with some common implementations.

use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup,
    short_weierstrass::{Projective, SWCurveConfig},
};
use ark_ff::{One, PrimeField, Zero};
use ark_r1cs_std::{
    convert::ToConstraintFieldGadget,
    fields::fp::FpVar,
    groups::{CurveVar, curves::short_weierstrass::ProjectiveVar},
};
use ark_relations::gr1cs::SynthesisError;

use crate::{
    algebra::{field::SonobeField, group::emulated::EmulatedAffineVar},
    circuits::{
        WitnessToPublic,
        linkage::{Canonical, Emulated, HasConstraintField, HasValue, HasVar},
    },
    traits::{Dummy, Inputize, InputizeEmulated},
    transcripts::{Absorbable, AbsorbableVar},
};

pub mod emulated;

/// [`SonobeCurve`] trait is a wrapper around [`CurveGroup`] that also includes
/// necessary bounds for the curve to be used conveniently in folding schemes.
pub trait SonobeCurve:
    CurveGroup<ScalarField: SonobeField, BaseField: SonobeField, Config: SWCurveConfig>
    + Absorbable
    + Inputize<Self::BaseField>
    + InputizeEmulated<Self::ScalarField>
    + HasGroup<Group = Self>
    + HasVar<
        Canonical,
        Var: CurveVar<Self, Self::BaseField> + AbsorbableVar<Self::BaseField> + WitnessToPublic,
    > + HasVar<Emulated<Self::ScalarField>, Var = EmulatedAffineVar<Self::ScalarField, Self>>
{
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> SonobeCurve
    for Projective<P>
{
}

impl<P: SWCurveConfig<BaseField: PrimeField>> HasConstraintField
    for ProjectiveVar<P, FpVar<P::BaseField>>
{
    type ConstraintField = P::BaseField;
}

impl<P: SWCurveConfig<BaseField: PrimeField>> HasValue for ProjectiveVar<P, FpVar<P::BaseField>> {
    type Value = Projective<P>;
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> HasVar<Canonical>
    for Projective<P>
{
    type Var = ProjectiveVar<P, FpVar<P::BaseField>>;
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>, F: SonobeField>
    HasVar<Emulated<F>> for Projective<P>
{
    type Var = EmulatedAffineVar<F, Self>;
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

impl<P: SWCurveConfig<BaseField: SonobeField>> Inputize<P::BaseField> for Projective<P> {
    fn inputize(&self) -> Vec<P::BaseField> {
        let affine = self.into_affine();
        match affine.xy() {
            Some((x, y)) => vec![x, y, One::one()],
            None => vec![Zero::zero(), One::one(), Zero::zero()],
        }
    }
}

impl<P: SWCurveConfig<BaseField: SonobeField, ScalarField: SonobeField>>
    InputizeEmulated<P::ScalarField> for Projective<P>
{
    fn inputize_emulated(&self) -> Vec<P::ScalarField> {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();

        [x, y].inputize_emulated()
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

pub trait HasGroup {
    type Group: SonobeCurve;
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> HasGroup
    for Projective<P>
{
    type Group = Self;
}

pub type BF<T> = <<T as HasGroup>::Group as CurveGroup>::BaseField;
pub type SF<T> = <<T as HasGroup>::Group as PrimeGroup>::ScalarField;
