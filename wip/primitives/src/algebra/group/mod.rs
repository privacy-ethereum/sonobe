use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToConstraintFieldGadget,
    fields::fp::FpVar,
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    prelude::Boolean,
    GR1CSVar,
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::mem::swap;
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;

use crate::algebra::field::nonnative2::IntVarInner;
use crate::{
    algebra::field::{
        nonnative::{Bound, NonNativeUintVar},
        SonobeField,
    },
    traits::{Inputize, InputizeNonNative},
    transcripts::{Absorbable, AbsorbableGadget},
};

pub mod nonnative;

pub type CF1<C> = <C as PrimeGroup>::ScalarField;
pub type CF2<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
pub type CI1<C> = <<C as PrimeGroup>::ScalarField as PrimeField>::BigInt;
pub type CI2<C> = <<<C as CurveGroup>::BaseField as Field>::BasePrimeField as PrimeField>::BigInt;

/// `Curve` trait is a wrapper around `CurveGroup` that also includes the
/// necessary bounds for the curve to be used conveniently in folding schemes.
pub trait SonobeCurve:
    CurveGroup<ScalarField: SonobeField, BaseField: SonobeField>
    + Absorbable<Self::BaseField>
    + Inputize<Self::BaseField>
    + InputizeNonNative<Self::ScalarField>
{
    /// The in-circuit variable type for this curve.
    type Var: CurveVar<Self, Self::BaseField>;
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> SonobeCurve
    for Projective<P>
{
    type Var = ProjectiveVar<P, FpVar<P::BaseField>>;
}

impl<F: PrimeField, P: SWCurveConfig<BaseField: Absorbable<F>>> Absorbable<F> for Projective<P> {
    fn absorb_into(&self, dest: &mut Vec<F>) {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();
        [x, y].absorb_into(dest);
    }
}

impl<P: SWCurveConfig<BaseField: PrimeField>> AbsorbableGadget<FpVar<P::BaseField>>
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
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `ProjectiveVar::new_input`.
    fn inputize(&self) -> Vec<P::BaseField> {
        let affine = self.into_affine();
        match affine.xy() {
            Some((x, y)) => vec![x, y, One::one()],
            None => vec![Zero::zero(), One::one(), Zero::zero()],
        }
    }
}

impl<P: SWCurveConfig<BaseField: SonobeField, ScalarField: SonobeField>>
    InputizeNonNative<P::ScalarField> for Projective<P>
{
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `NonNativeAffineVar::new_input`.
    fn inputize_nonnative(&self) -> Vec<P::ScalarField> {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();

        [x, y].inputize_nonnative()
    }
}

fn lattice_reduction_2x2(
    mut b1: (BigInt, BigInt),
    mut b2: (BigInt, BigInt),
) -> ((BigInt, BigInt), (BigInt, BigInt)) {
    loop {
        let mut b1_norm_sq = &b1.0 * &b1.0 + &b1.1 * &b1.1;
        let mut b2_norm_sq = &b2.0 * &b2.0 + &b2.1 * &b2.1;

        if b1_norm_sq > b2_norm_sq {
            swap(&mut b1, &mut b2);
            swap(&mut b1_norm_sq, &mut b2_norm_sq);
        }

        let (mut m, r) = (&b1.0 * &b2.0 + &b1.1 * &b2.1).div_rem(&b1_norm_sq);
        if &r + &r >= b1_norm_sq {
            m += BigInt::one();
        }

        if m.is_zero() {
            break;
        }

        b2.0 -= &m * &b1.0;
        b2.1 -= &m * &b1.1;
    }

    (b1, b2)
}

pub trait PointScalarMulGadget<F: PrimeField>: Sized {
    fn mul_scalar(&self, scalar: &impl ToBitsGadget<F>) -> Result<Self, SynthesisError>;
}

impl<C: SonobeCurve> PointScalarMulGadget<CF2<C>> for C {
    fn mul_scalar(&self, scalar: &impl ToBitsGadget<CF2<C>>) -> Result<Self, SynthesisError> {
        let scalar = scalar.to_bits_le()?;

        let cs = scalar.cs();

        let m = BigInt::from_biguint(Sign::Plus, CF1::<C>::MODULUS.into());
        let m_sqrt = m.sqrt();

        let (a, b) = lattice_reduction_2x2(
            (m, Zero::zero()),
            (
                CI2::<C>::from_bits_le(&scalar.value().unwrap_or_default())
                    .into()
                    .into(),
                One::one(),
            ),
        )
        .0;
        let (a_sign, a_abs) = a.into_parts();
        let (b_sign, b_abs) = b.into_parts();
        let a_is_negative =
            Boolean::new_variable_with_inferred_mode(cs.clone(), || Ok(a_sign == Sign::Minus))?;
        let b_is_negative =
            Boolean::new_variable_with_inferred_mode(cs.clone(), || Ok(b_sign == Sign::Minus))?;

        let a = NonNativeUintVar::new_variable_with_inferred_mode(cs.clone(), || {
            Ok((a_abs.into(), Bound::new_ub(m_sqrt.clone())))
        })?;
        let b = NonNativeUintVar::new_variable_with_inferred_mode(cs, || {
            Ok((b_abs.into(), Bound::new_ub(m_sqrt)))
        })?;

        todo!()
    }
}
