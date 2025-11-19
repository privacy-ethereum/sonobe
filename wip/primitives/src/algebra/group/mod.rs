use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::{
    convert::ToConstraintFieldGadget,
    fields::fp::FpVar,
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::mem::swap;
use num_bigint::BigInt;
use num_integer::Integer;

use crate::{
    algebra::{field::SonobeField, group::emulated::EmulatedAffineVar, Val},
    traits::{Dummy, Inputize, InputizeEmulated},
    transcripts::{Absorbable, AbsorbableGadget},
};

pub mod emulated;

pub type CF1<C> = <C as PrimeGroup>::ScalarField;
pub type CF2<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
pub type CI1<C> = <<C as PrimeGroup>::ScalarField as PrimeField>::BigInt;
pub type CI2<C> = <<<C as CurveGroup>::BaseField as Field>::BasePrimeField as PrimeField>::BigInt;

/// `Curve` trait is a wrapper around `CurveGroup` that also includes the
/// necessary bounds for the curve to be used conveniently in folding schemes.
pub trait SonobeCurve:
    CurveGroup<ScalarField: SonobeField, BaseField: SonobeField, Config: SWCurveConfig>
    + Absorbable
    + Inputize<Self::BaseField>
    + InputizeEmulated<Self::ScalarField>
    + Val<
        Var: CurveVar<Self, Self::BaseField> + AbsorbableGadget<Self::BaseField>,
        EmulatedVar<Self::ScalarField> = EmulatedAffineVar<Self::ScalarField, Self>
    >
{
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> SonobeCurve
    for Projective<P>
{
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> Val for Projective<P> {
    type ConstraintField = P::BaseField;
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

impl<P: SWCurveConfig<BaseField: PrimeField>> AbsorbableGadget<P::BaseField>
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
    InputizeEmulated<P::ScalarField> for Projective<P>
{
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `NonNativeAffineVar::new_input`.
    fn inputize_emulated(&self) -> Vec<P::ScalarField> {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();

        [x, y].inputize_emulated()
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

// impl<C: SonobeCurve> PointScalarMulGadget<CF2<C>> for C {
//     fn mul_scalar(&self, scalar: &impl ToBitsGadget<CF2<C>>) -> Result<Self, SynthesisError> {
//         let scalar = scalar.to_bits_le()?;

//         let cs = scalar.cs();

//         let m = BigInt::from_biguint(Sign::Plus, CF1::<C>::MODULUS.into());
//         let m_sqrt = m.sqrt();

//         let (a, b) = lattice_reduction_2x2(
//             (m, Zero::zero()),
//             (
//                 CI2::<C>::from_bits_le(&scalar.value().unwrap_or_default())
//                     .into()
//                     .into(),
//                 One::one(),
//             ),
//         )
//         .0;
//         let (a_sign, a_abs) = a.into_parts();
//         let (b_sign, b_abs) = b.into_parts();
//         let a_is_negative =
//             Boolean::new_variable_with_inferred_mode(cs.clone(), || Ok(a_sign == Sign::Minus))?;
//         let b_is_negative =
//             Boolean::new_variable_with_inferred_mode(cs.clone(), || Ok(b_sign == Sign::Minus))?;

//         // let a = NonNativeUintVar::new_variable_with_inferred_mode(cs.clone(), || {
//         //     Ok((a_abs.into(), Bound::new_ub(m_sqrt.clone())))
//         // })?;
//         // let b = NonNativeUintVar::new_variable_with_inferred_mode(cs, || {
//         //     Ok((b_abs.into(), Bound::new_ub(m_sqrt)))
//         // })?;

//         todo!()
//     }
// }
