//! This module defines extension traits for elliptic curve points and their
//! in-circuit counterparts, along with some common implementations.

use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup,
    short_weierstrass::{Projective, SWCurveConfig},
};
use ark_ff::{AdditiveGroup, Field, One, PrimeField, Zero};
use ark_r1cs_std::{
    GR1CSVar,
    boolean::Boolean,
    convert::ToConstraintFieldGadget,
    fields::{FieldVar, fp::FpVar},
    groups::{
        CurveVar,
        curves::short_weierstrass::{ProjectiveVar, non_zero_affine::NonZeroAffineVar},
    },
};
use ark_relations::gr1cs::SynthesisError;

use crate::{
    algebra::{
        Val,
        field::{SonobePrimeField, emulated::EmulatedFieldVar},
        group::emulated::EmulatedAffineVar,
    },
    circuits::WitnessToPublic,
    traits::{Dummy, Inputize},
    transcripts::{Absorbable, AbsorbableVar},
};

pub mod emulated;

/// [`CF1`] is a type alias for the scalar field of a curve `C`.
pub type CF1<C> = <C as PrimeGroup>::ScalarField;
/// [`CF2`] is a type alias for the base field of a curve `C`.
pub type CF2<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// [`SonobeCurve`] trait is a wrapper around [`CurveGroup`] that also includes
/// necessary bounds for the curve to be used conveniently in folding schemes.
pub trait SonobeCurve:
    CurveGroup<ScalarField: SonobePrimeField, BaseField: SonobePrimeField, Config: SWCurveConfig>
    + Absorbable
    + Val<
        Var: CurveVar<Self, Self::BaseField>
                 + AbsorbableVar<Self::BaseField>
                 + WitnessToPublic
                 + JointScalarMul<Self::BaseField>
                 + Inputize<Self::BaseField>,
        EmulatedVar<Self::ScalarField> = EmulatedAffineVar<Self::ScalarField, Self>,
    >
{
}

impl<P: SWCurveConfig<ScalarField: SonobePrimeField, BaseField: SonobePrimeField>> SonobeCurve
    for Projective<P>
{
}

impl<P: SWCurveConfig<ScalarField: SonobePrimeField, BaseField: SonobePrimeField>> Val for Projective<P> {
    type PreferredConstraintField = P::BaseField;
    type Var = ProjectiveVar<P, FpVar<P::BaseField>>;

    type EmulatedVar<F: SonobePrimeField> = EmulatedAffineVar<F, Self>;
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

impl<Base: SonobePrimeField, Target: SonobeCurve> Inputize<Base> for EmulatedAffineVar<Base, Target> {
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

impl<Base: SonobePrimeField, Target: SonobeCurve> WitnessToPublic for EmulatedAffineVar<Base, Target> {
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        self.x.mark_as_public()?;
        self.y.mark_as_public()?;
        Ok(())
    }
}

/// [`JointScalarMul`] extends arkworks' [`CurveVar`] for more efficient MSM
/// operations in-circuit, without relying on a fork.
pub trait JointScalarMul<F: Field>: Sized {
    /// [`JointScalarMul::joint_scalar_mul_be`] computes `s1 * self + s2 * p`,
    /// where `s1` and `s2` are the scalars represented in big-endian `Boolean`.
    ///
    /// `self` and `p` are non-zero and `self` ≠ `-p`.
    fn joint_scalar_mul_be<'a>(
        &self,
        p: &Self,
        s1: impl Iterator<Item = &'a Boolean<F>>,
        s2: impl Iterator<Item = &'a Boolean<F>>,
    ) -> Result<Self, SynthesisError>;
}

impl<P: SWCurveConfig<BaseField: PrimeField>> JointScalarMul<P::BaseField>
    for ProjectiveVar<P, FpVar<P::BaseField>>
{
    fn joint_scalar_mul_be<'a>(
        &self,
        p: &Self,
        bits1: impl Iterator<Item = &'a Boolean<<P::BaseField as Field>::BasePrimeField>>,
        bits2: impl Iterator<Item = &'a Boolean<<P::BaseField as Field>::BasePrimeField>>,
    ) -> Result<Self, SynthesisError> {
        // prepare bits decomposition
        let mut bits1 = bits1.collect::<Vec<_>>();
        if bits1.is_empty() {
            return Ok(Self::zero());
        }
        // Remove unnecessary constant zeros in the most-significant positions.
        bits1 = bits1
            .into_iter()
            // We iterate from the MSB down.
            .rev()
            // Skip leading zeros, if they are constants.
            .skip_while(|b| b.is_constant() && !b.value().unwrap())
            .collect();

        let mut bits2 = bits2.collect::<Vec<_>>();
        if bits2.is_empty() {
            return Ok(Self::zero());
        }
        // Remove unnecessary constant zeros in the most-significant positions.
        bits2 = bits2
            .into_iter()
            // We iterate from the MSB down.
            .rev()
            // Skip leading zeros, if they are constants.
            .skip_while(|b| b.is_constant() && !b.value().unwrap())
            .collect();

        // precompute points
        let aff1 = self.to_affine()?;
        let nz_aff1 = NonZeroAffineVar::<P, _>::new(aff1.x, aff1.y);

        let aff2 = p.to_affine()?;
        let nz_aff2 = NonZeroAffineVar::new(aff2.x, aff2.y);

        let mut aff1_neg = NonZeroAffineVar::new(nz_aff1.x.clone(), nz_aff1.y.negate()?);
        let mut aff2_neg = NonZeroAffineVar::new(nz_aff2.x.clone(), nz_aff2.y.negate()?);
        let acc = nz_aff1.double()?;

        let sum = nz_aff1.add_unchecked(&nz_aff2)?;
        let diff = nz_aff1.add_unchecked(&aff2_neg)?;
        let NonZeroAffineVar { mut x, mut y, .. } = acc;

        // double-and-add loop
        for (bit1, bit2) in (bits1.iter().rev().skip(1).rev()).zip(bits2.iter().rev().skip(1).rev())
        {
            let xor = *bit1 ^ *bit2;
            let xx = xor.select(&diff.x, &sum.x)?;
            let yy = xor.select(&diff.y, &sum.y)?;
            let yy = bit1.select(&yy, &yy.negate()?)?;

            if [&x, &y].is_constant() || ([&xx, &yy].is_constant()) {
                let p = NonZeroAffineVar::<P, _>::new(x.clone(), y.clone())
                    .double()?
                    .add_unchecked(&NonZeroAffineVar::new(xx, yy))?;
                x = p.x;
                y = p.y;
            } else {
                let lambda_1 = (&yy - &y).mul_by_inverse_unchecked(&(&xx - &x))?;
                let lambda_1_square = lambda_1.square()?;

                let lambda_2 = y
                    .mul_by_inverse_unchecked(&(&x.double()? + &xx - &lambda_1_square))?
                    .double()?
                    - lambda_1;

                let x4 = lambda_2.square()? - lambda_1_square + &xx;
                let y4 = lambda_2 * &(&x - &x4) - &y;
                x = x4;
                y = y4;
            };
        }

        let mut acc = NonZeroAffineVar::new(x, y);
        // last bit
        aff1_neg = aff1_neg.add_unchecked(&acc)?;
        acc = bits1[bits1.len() - 1].select(&acc, &aff1_neg)?;
        aff2_neg = aff2_neg.add_unchecked(&acc)?;
        acc = bits2[bits1.len() - 1].select(&acc, &aff2_neg)?;

        let acc = acc.into_projective();
        let mut p = diff;
        for _ in 0..bits1.len() - 1 {
            p = p.double()?;
        }

        // [`ProjectiveVar::add_mixed`]
        let (x1, y1, z1) = (&acc.x, &acc.y, &acc.z);
        let (x2, y2) = (&p.x, &p.y.negate()?);
        let three_b = P::COEFF_B.double() + P::COEFF_B;

        let xx = x1 * x2; // 1
        let yy = y1 * y2; // 2
        let xy_pairs = (x1 + y1) * (x2 + y2) - (&xx + &yy); // 4, 5, 6, 7, 8
        let xz_pairs = x2 * z1 + x1; // 8, 9
        let yz_pairs = y2 * z1 + y1; // 10, 11

        let bz3_part = &xz_pairs * P::COEFF_A + z1 * three_b; // 12, 13, 14

        let yy_m_bz3 = &yy - &bz3_part; // 15
        let yy_p_bz3 = &yy + &bz3_part; // 16

        let azz = z1 * P::COEFF_A; // 20
        let xx3_p_azz = xx.double()? + &xx + &azz; // 18, 19, 22

        let b3_xz_pairs = (&xx - &azz) * P::COEFF_A + &xz_pairs * three_b; // 21, 23, 24, 25

        Ok(ProjectiveVar::new(
            &yy_m_bz3 * &xy_pairs - &yz_pairs * &b3_xz_pairs, // 28, 29, 30
            &yy_p_bz3 * &yy_m_bz3 + &xx3_p_azz * b3_xz_pairs, // 17, 26, 27
            &yy_p_bz3 * &yz_pairs + xy_pairs * xx3_p_azz,     // 31, 32, 33
        ))
    }
}
