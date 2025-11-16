use std::fmt::Debug;

use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::EqGadget,
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow,
    cmp::{max, min},
    marker::PhantomData,
    ops::Index,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::Signed;

use crate::{
    algebra::{
        field::SonobeField,
        ops::{
            bits::{FromBitsGadget, ToBitsGadgetExt},
            matrix::{MatrixGadget, SparseMatrixVar},
            vector::VectorGadget,
        },
    },
    transcripts::AbsorbableGadget,
};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Bound(pub BigInt, pub BigInt);

impl Bound {
    pub fn zero() -> Self {
        Self::default()
    }
}

impl Bound {
    pub fn add(&self, other: &Self) -> Self {
        Self(&self.0 + &other.0, &self.1 + &other.1)
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self(&self.0 - &other.1, &self.1 - &other.0)
    }

    pub fn add_many(limbs: &[Self]) -> Self {
        Self(
            limbs.iter().map(|l| &l.0).sum(),
            limbs.iter().map(|l| &l.1).sum(),
        )
    }

    pub fn mul(&self, other: &Self) -> Self {
        let ll = &self.0 * &other.0;
        let lu = &self.0 * &other.1;
        let ul = &self.1 * &other.0;
        let uu = &self.1 * &other.1;

        Self(
            min(min(&ll, &lu), min(&ul, &uu)).clone(),
            max(max(&ll, &lu), max(&ul, &uu)).clone(),
        )
    }

    pub fn shl(&self, shift: usize) -> Self {
        Self(&self.0 << shift, &self.1 << shift)
    }

    pub fn filter_safe<F: PrimeField>(self) -> Option<Self> {
        let limit = BigInt::from_biguint(Sign::Plus, F::MODULUS_MINUS_ONE_DIV_TWO.into());
        (self.0 >= -&limit && self.1 <= limit).then_some(self)
    }
}

fn compose<F: SonobeField, V: Borrow<[F]>>(limbs: V) -> BigInt {
    let mut r = BigInt::zero();

    for &limb in limbs.borrow().iter().rev() {
        r <<= F::BITS_PER_LIMB;
        r += if limb.into_bigint() > F::MODULUS_MINUS_ONE_DIV_TWO {
            BigInt::from_biguint(Sign::Minus, (-limb).into())
        } else {
            BigInt::from_biguint(Sign::Plus, limb.into())
        };
    }
    r
}

#[derive(Debug, Clone)]
pub struct IntVarInner<F: PrimeField, Cfg, const ALIGNED: bool> {
    _cfg: PhantomData<Cfg>,
    pub limbs: Vec<FpVar<F>>,
    pub bounds: Vec<Bound>,
}

pub type BigIntVar<F, const ALIGNED: bool> = IntVarInner<F, (), ALIGNED>;
pub type EmulatedFieldVar<Base, Target, const ALIGNED: bool> = IntVarInner<Base, Target, ALIGNED>;

impl<F: SonobeField, const ALIGNED: bool> GR1CSVar<F> for IntVarInner<F, (), ALIGNED> {
    type Value = BigInt;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.limbs.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.limbs.value().map(compose)
    }
}

impl<Base: SonobeField, Target: SonobeField, const ALIGNED: bool> GR1CSVar<Base>
    for IntVarInner<Base, Target, ALIGNED>
{
    type Value = Target;

    fn cs(&self) -> ConstraintSystemRef<Base> {
        self.limbs.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.limbs.value().map(compose).map(|v| {
            let (sign, abs) = v.into_parts();
            assert!(abs < Target::MODULUS.into());
            match sign {
                Sign::Plus | Sign::NoSign => Target::from(abs),
                Sign::Minus => Target::zero() - Target::from(abs),
            }
        })
    }
}

impl<F: SonobeField, Cfg, const ALIGNED: bool> IntVarInner<F, Cfg, ALIGNED> {
    pub fn new(limbs: Vec<FpVar<F>>, bounds: Vec<Bound>) -> Self {
        Self {
            _cfg: PhantomData,
            limbs,
            bounds,
        }
    }

    fn ubound(&self) -> BigInt {
        let mut r = BigInt::zero();

        for i in self.bounds.iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += &i.1;
        }

        r
    }

    fn lbound(&self) -> BigInt {
        let mut r = BigInt::zero();

        for i in self.bounds.iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += &i.0;
        }

        r
    }
}

impl<F: SonobeField, Cfg> IntVarInner<F, Cfg, true> {
    /// Enforce `self` to be less than `other`, where `self` and `other` should
    /// be aligned.
    /// Adapted from https://github.com/akosba/jsnark/blob/0955389d0aae986ceb25affc72edf37a59109250/JsnarkCircuitBuilder/src/circuit/auxiliary/LongElement.java#L801-L872
    pub fn enforce_lt(&self, other: &Self) -> Result<(), SynthesisError> {
        let len = max(self.limbs.len(), other.limbs.len());
        let zero = FpVar::zero();

        // Compute the difference between limbs of `other` and `self`.
        // Denote a positive limb by `+`, a negative limb by `-`, a zero limb by
        // `0`, and an unknown limb by `?`.
        // Then, for `self < other`, `delta` should look like:
        // ? ? ... ? ? + 0 0 ... 0 0
        let delta = (0..len)
            .map(|i| {
                let x = self.limbs.get(i).unwrap_or(&zero);
                let y = other.limbs.get(i).unwrap_or(&zero);
                y - x
            })
            .collect::<Vec<_>>();

        // `helper` is a vector of booleans that indicates if the corresponding
        // limb of `delta` is the first (searching from MSB) positive limb.
        // For example, if `delta` is:
        // - + ... + - + 0 0 ... 0 0
        // <---- search in this direction --------
        // Then `helper` should be:
        // F F ... F F T F F ... F F
        let helper = {
            let cs = self.limbs.cs().or(other.limbs.cs());
            let mut helper = vec![false; len];
            for i in (0..len).rev() {
                let delta = delta[i].value().unwrap_or_default().into_bigint();
                if !delta.is_zero() && delta < F::MODULUS_MINUS_ONE_DIV_TWO {
                    helper[i] = true;
                    break;
                }
            }
            Vec::<Boolean<F>>::new_variable_with_inferred_mode(cs, || Ok(helper))?
        };

        // `p` is the first positive limb in `delta`.
        let mut p = FpVar::<F>::zero();
        // `r` is the sum of all bits in `helper`, which should be 1 when `self`
        // is less than `other`, as there should be more than one positive limb
        // in `delta`, and thus exactly one true bit in `helper`.
        let mut r = FpVar::zero();
        for (b, d) in helper.into_iter().zip(delta) {
            // Choose the limb `d` only if `b` is true.
            p += b.select(&d, &FpVar::zero())?;
            // Either `r` or `d` should be zero.
            // Consider the same example as above:
            // - + ... + - + 0 0 ... 0 0
            // F F ... F F T F F ... F F
            // |-----------|
            // `r = 0` in this range (before/when we meet the first positive limb)
            //               |---------|
            //               `d = 0` in this range (after we meet the first positive limb)
            // This guarantees that for every bit after the true bit in `helper`,
            // the corresponding limb in `delta` is zero.
            (&r * &d).enforce_equal(&FpVar::zero())?;
            // Add the current bit to `r`.
            r += FpVar::from(b);
        }

        // Ensure that `r` is exactly 1. This guarantees that there is exactly
        // one true value in `helper`.
        r.enforce_equal(&FpVar::one())?;
        // Ensure that `p` is positive, i.e.,
        // `0 <= p - 1 < 2^bits_per_limb < F::MODULUS_MINUS_ONE_DIV_TWO`.
        // This guarantees that the true value in `helper` corresponds to a
        // positive limb in `delta`.
        (p - FpVar::one()).enforce_bit_length(F::BITS_PER_LIMB)?;

        Ok(())
    }
}

impl<F: SonobeField, Cfg> From<IntVarInner<F, Cfg, true>> for IntVarInner<F, Cfg, false> {
    fn from(v: IntVarInner<F, Cfg, true>) -> Self {
        Self::new(v.limbs, v.bounds)
    }
}

impl<F: SonobeField, Cfg, const LHS_ALIGNED: bool> IntVarInner<F, Cfg, LHS_ALIGNED> {
    /// Compute `self + other`, without aligning the limbs.
    pub fn add_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &IntVarInner<F, Cfg, RHS_ALIGNED>,
    ) -> Result<IntVarInner<F, Cfg, false>, SynthesisError> {
        let mut limbs = vec![FpVar::zero(); max(self.limbs.len(), other.limbs.len())];
        let mut bounds = vec![Bound::zero(); limbs.len()];
        for (i, v) in self.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&self.bounds[i])
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            limbs[i] += v;
        }
        for (i, v) in other.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&other.bounds[i])
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            limbs[i] += v;
        }
        Ok(IntVarInner::new(limbs, bounds))
    }

    pub fn sub_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &IntVarInner<F, Cfg, RHS_ALIGNED>,
    ) -> Result<IntVarInner<F, Cfg, false>, SynthesisError> {
        let mut limbs = vec![FpVar::zero(); max(self.limbs.len(), other.limbs.len())];
        let mut bounds = vec![Bound::zero(); limbs.len()];
        for (i, v) in self.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&self.bounds[i])
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            limbs[i] += v;
        }
        for (i, v) in other.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .sub(&other.bounds[i])
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            limbs[i] -= v;
        }
        Ok(IntVarInner::new(limbs, bounds))
    }

    /// Compute `self * other`, without aligning the limbs.
    /// Implements the O(n) approach described in xJsnark, Section IV.B.1)
    pub fn mul_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &IntVarInner<F, Cfg, RHS_ALIGNED>,
    ) -> Result<IntVarInner<F, Cfg, false>, SynthesisError> {
        let len = self.limbs.len() + other.limbs.len() - 1;
        if self.limbs.is_constant() || other.limbs.is_constant() {
            // Use the naive approach for constant operands, which costs no
            // constraints.
            let bounds = (0..len)
                .map(|i| {
                    let start = max(i + 1, other.bounds.len()) - other.bounds.len();
                    let end = min(i + 1, self.bounds.len());
                    Bound::add_many(
                        &(start..end)
                            .map(|j| self.bounds[j].mul(&other.bounds[i - j]))
                            .collect::<Vec<_>>(),
                    )
                    .filter_safe::<F>()
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(SynthesisError::Unsatisfiable)?;

            let limbs = (0..len)
                .map(|i| {
                    let start = max(i + 1, other.limbs.len()) - other.limbs.len();
                    let end = min(i + 1, self.limbs.len());
                    (start..end)
                        .map(|j| &self.limbs[j] * &other.limbs[i - j])
                        .sum()
                })
                .collect();
            return Ok(IntVarInner::new(limbs, bounds));
        }
        // Compute the product `limbs` outside the circuit and provide it as
        // hints.
        let (limbs, bounds) = {
            let cs = self.limbs.cs().or(other.limbs.cs());
            let mut limbs = vec![F::zero(); len];
            let mut bounds = vec![Bound::zero(); len];
            for i in 0..self.limbs.len() {
                for j in 0..other.limbs.len() {
                    limbs[i + j] += self.limbs[i].value().unwrap_or_default()
                        * other.limbs[j].value().unwrap_or_default();
                    bounds[i + j] = bounds[i + j].add(&self.bounds[i].mul(&other.bounds[j]))
                }
            }
            (
                Vec::new_variable_with_inferred_mode(cs, || Ok(limbs))?,
                bounds
                    .into_iter()
                    .map(|b| b.filter_safe::<F>())
                    .collect::<Option<_>>()
                    .ok_or(SynthesisError::Unsatisfiable)?,
            )
        };
        for c in 1..=len {
            let c = F::from(c as u64);
            let mut t = F::one();
            let mut c_powers = vec![];
            for _ in 0..len {
                c_powers.push(t);
                t *= c;
            }
            // `l = Σ self[i] c^i`
            let l = self
                .limbs
                .iter()
                .zip(&c_powers)
                .map(|(v, t)| v * *t)
                .sum::<FpVar<_>>();
            // `r = Σ other[i] c^i`
            let r = other
                .limbs
                .iter()
                .zip(&c_powers)
                .map(|(v, t)| v * *t)
                .sum::<FpVar<_>>();
            // `o = Σ z[i] c^i`
            let o = limbs
                .iter()
                .zip(&c_powers)
                .map(|(v, t)| v * *t)
                .sum::<FpVar<_>>();
            // Enforce `o = l * r`
            l.mul_equals(&r, &o)?;
        }

        Ok(IntVarInner::new(limbs, bounds))
    }

    /// Enforce `self` to be equal to `other`, where `self` and `other` are not
    /// necessarily aligned.
    ///
    /// Adapted from https://github.com/akosba/jsnark/blob/0955389d0aae986ceb25affc72edf37a59109250/JsnarkCircuitBuilder/src/circuit/auxiliary/LongElement.java#L562-L798
    /// Similar implementations can also be found in https://github.com/alex-ozdemir/bellman-bignat/blob/0585b9d90154603a244cba0ac80b9aafe1d57470/src/mp/bignat.rs#L566-L661
    /// and https://github.com/arkworks-rs/r1cs-std/blob/4020fbc22625621baa8125ede87abaeac3c1ca26/src/fields/emulated_fp/reduce.rs#L201-L323
    pub fn enforce_equal_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &IntVarInner<F, Cfg, RHS_ALIGNED>,
    ) -> Result<(), SynthesisError> {
        let len = min(self.limbs.len(), other.limbs.len());

        // Group the limbs of `self` and `other` so that each group nearly
        // reaches the capacity `F::MODULUS_MINUS_ONE_DIV_TWO`.
        // By saying group, we mean the operation `Σ x_i 2^{i * W}`, where `W`
        // is the initial number of bits in a limb, just as what we do in grade
        // school arithmetic, e.g.,
        //         5   9
        // x       7   3
        // -------------
        //        15  27
        //    35  63
        // -------------  <- When grouping 35, 15 + 63, and 27, we are computing
        // 4   3   0   7     35 * 100 + (15 + 63) * 10 + 27 = 4307
        // Note that this is different from the concatenation `x_0 || x_1 ...`,
        // since the bit-length of each limb is not necessarily the initial size
        // `W`.

        let mut i = 0;
        let mut diff = FpVar::zero();
        let mut x_bound = Bound::zero();
        let mut y_bound = Bound::zero();
        let mut step = 0;
        let inv = F::from(BigUint::one() << F::BITS_PER_LIMB)
            .inverse()
            .unwrap();

        while i < len {
            if let (Some(new_x_bound), Some(new_y_bound)) = (
                self.bounds[i].shl(step).add(&x_bound).filter_safe::<F>(),
                other.bounds[i].shl(step).add(&y_bound).filter_safe::<F>(),
            ) {
                diff = (diff + &self.limbs[i] - &other.limbs[i]) * inv;
                x_bound = new_x_bound;
                y_bound = new_y_bound;

                i += 1;
                step += F::BITS_PER_LIMB;
                continue;
            }
            // For each group, check the last `step_i` bits of `x_i` and `y_i` are
            // equal.
            // The intuition is to check `diff = x_i - y_i = 0 (mod 2^step_i)`.
            // However, this is only true for `i = 0`, and we need to consider carry
            // values `diff >> step_i` for `i > 0`.
            // Therefore, we actually check `diff = x_i - y_i + c = 0 (mod 2^step_i)`
            // and derive the next `c` by computing `diff >> step_i`.
            // To enforce `diff = 0 (mod 2^step_i)`, we compute `diff / 2^step_i`
            // and enforce it to be small (soundness holds because for `a` that does
            // not divide `b`, `b / a` in the field will be very large).
            let bits = (max(
                min(&x_bound.0, &y_bound.0).bits(),
                max(&x_bound.1, &y_bound.1).bits(),
            ) as usize)
                .checked_sub(step)
                .unwrap_or_default();

            (&diff + F::from(BigUint::one() << bits)).enforce_bit_length(bits + 1)?;

            x_bound = Bound::zero();
            y_bound = Bound::zero();
            step = 0;
        }

        let remaining_limbs = if i < self.limbs.len() {
            &self.limbs[i..]
        } else {
            &other.limbs[i..]
        };
        let remaining_bounds = if i < self.bounds.len() {
            &self.bounds[i..]
        } else {
            &other.bounds[i..]
        };
        if remaining_limbs.is_empty() {
            diff.enforce_equal(&FpVar::zero())?;
        } else {
            // If there is any remaining limb, the first one should be the
            // final carry (which will be checked later), and the following
            // ones should be zero.

            // Enforce the remaining limbs to be zero.
            // Instead of doing that one by one, we check if their sum is
            // zero using a single constraint.
            // This is sound, as the upper bounds of the limbs and their sum
            // are guaranteed to be less than `F::MODULUS_MINUS_ONE_DIV_TWO`
            // (i.e., all of them are "non-negative"), implying that all
            // limbs should be zero to make the sum zero.
            remaining_limbs[1..]
                .iter()
                .sum::<FpVar<F>>()
                .enforce_equal(&FpVar::zero())?;
            Bound::add_many(remaining_bounds)
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            // For the final carry, we need to ensure that it equals the
            // remaining limb `rest`.
            diff.enforce_equal(&remaining_limbs[0])?;
        }

        Ok(())
    }
}

impl<Base: SonobeField, Target: SonobeField, const LHS_ALIGNED: bool>
    IntVarInner<Base, Target, LHS_ALIGNED>
{
    /// Convert `Self` to an element in `M`, i.e., compute `Self % M::MODULUS`.
    pub fn modulo(&self) -> Result<IntVarInner<Base, Target, true>, SynthesisError> {
        let cs = self.cs();
        let m = BigInt::from_biguint(Sign::Plus, Target::MODULUS.into());
        // Provide the quotient and remainder as hints
        let q = IntVarInner::new_variable_with_inferred_mode(cs.clone(), || {
            let (lb, ub) = (self.lbound().div_floor(&m), self.ubound().div_floor(&m));
            Ok((
                compose(self.limbs.value().unwrap_or_default()).div_floor(&m),
                Bound(lb, ub),
            ))
        })?;
        let r = IntVarInner::new_variable_with_inferred_mode(cs.clone(), || {
            Ok((
                compose(self.limbs.value().unwrap_or_default()).abs() % &m,
                Bound(Zero::zero(), m.clone()),
            ))
        })?;

        let m = IntVarInner::constant(m);

        // Enforce `self = q * m + r`
        q.mul_unaligned(&m)?
            .add_unaligned(&r)?
            .enforce_equal_unaligned(self)?;
        // Enforce `r < m` (and `r >= 0` already holds)
        r.enforce_lt(&m)?;

        Ok(r)
    }

    /// Enforce that `self` is congruent to `other` modulo `M::MODULUS`.
    pub fn enforce_congruent<const RHS_ALIGNED: bool>(
        &self,
        other: &IntVarInner<Base, Target, RHS_ALIGNED>,
    ) -> Result<(), SynthesisError> {
        let cs = self.cs();
        let m = BigInt::from_biguint(Sign::Plus, Target::MODULUS.into());
        // Provide the quotient as hint
        let q = IntVarInner::new_variable_with_inferred_mode(cs.clone(), || {
            let (lb, ub) = (self.lbound().div_floor(&m), self.ubound().div_floor(&m));
            Ok((
                compose(self.limbs.value().unwrap_or_default()).div_floor(&m),
                Bound(lb, ub),
            ))
        })?;

        let m = IntVarInner::constant(m);

        // Enforce `self - other = q * m`
        self.sub_unaligned(other)?
            .enforce_equal_unaligned(&q.mul_unaligned(&m)?)
    }
}

impl<Base: SonobeField, Target: SonobeField> TryFrom<IntVarInner<Base, Target, false>>
    for IntVarInner<Base, Target, true>
{
    type Error = SynthesisError;

    fn try_from(v: IntVarInner<Base, Target, false>) -> Result<Self, Self::Error> {
        v.modulo()
    }
}

impl<F: SonobeField, Cfg> EqGadget<F> for IntVarInner<F, Cfg, true> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        let mut result = Boolean::TRUE;
        if self.limbs.len() != other.limbs.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if self.bounds.len() != other.bounds.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..self.limbs.len() {
            if self.bounds[i] != other.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            result &= self.limbs[i].is_eq(&other.limbs[i])?;
        }
        Ok(result)
    }

    fn enforce_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        if self.limbs.len() != other.limbs.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if self.bounds.len() != other.bounds.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..self.limbs.len() {
            if self.bounds[i] != other.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            self.limbs[i].enforce_equal(&other.limbs[i])?;
        }
        Ok(())
    }

    fn enforce_not_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        if self.limbs.len() != other.limbs.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if self.bounds.len() != other.bounds.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..self.limbs.len() {
            if self.bounds[i] != other.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            self.limbs[i].enforce_not_equal(&other.limbs[i])?;
        }
        Ok(())
    }

    fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        if should_enforce.is_constant() {
            if should_enforce.value()? {
                return self.enforce_equal(other);
            } else {
                return self.enforce_not_equal(other);
            }
        }
        self.is_eq(&other)?
            .conditional_enforce_equal(&Boolean::TRUE, should_enforce)
    }
}

impl<F: SonobeField, Cfg> FromBitsGadget<F> for IntVarInner<F, Cfg, true> {
    fn from_bits_le(bits: &[Boolean<F>], bound: Bound) -> Result<Self, SynthesisError> {
        Ok(Self::new(
            bits.chunks(F::BITS_PER_LIMB)
                .map(Boolean::le_bits_to_fp)
                .collect::<Result<_, _>>()?,
            compute_bounds(&bound.0, &bound.1, F::BITS_PER_LIMB),
        ))
    }
}

impl<F: PrimeField, Cfg: Clone> CondSelectGadget<F> for IntVarInner<F, Cfg, true> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.limbs.len() != false_value.limbs.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if true_value.bounds.len() != false_value.bounds.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut limbs = vec![];
        let mut bounds = vec![];
        for i in 0..true_value.limbs.len() {
            if true_value.bounds[i] != false_value.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            limbs.push(cond.select(&true_value.limbs[i], &false_value.limbs[i])?);
            bounds.push(true_value.bounds[i].clone());
        }
        Ok(Self {
            _cfg: PhantomData,
            limbs,
            bounds,
        })
    }
}

impl<F: PrimeField, Cfg> ToBitsGadget<F> for IntVarInner<F, Cfg, true> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        for bound in &self.bounds {
            assert!(bound.0 >= BigInt::zero());
        }
        Ok(self
            .limbs
            .iter()
            .zip(&self.bounds)
            .map(|(limb, bound)| limb.to_n_bits_le(bound.1.bits() as usize))
            .collect::<Result<Vec<_>, _>>()?
            .concat())
    }
}

impl<F: PrimeField, Cfg> AbsorbableGadget<F> for IntVarInner<F, Cfg, true> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        let bits_per_limb = F::MODULUS_BIT_SIZE as usize - 1;

        self.to_bits_le()?
            .chunks(bits_per_limb)
            .try_for_each(|i| Boolean::le_bits_to_fp(i).map(|v| dest.push(v)))
    }
}

impl<F: SonobeField, Cfg> VectorGadget<IntVarInner<F, Cfg, false>>
    for [IntVarInner<F, Cfg, false>]
{
    fn add(&self, other: &Self) -> Result<Vec<IntVarInner<F, Cfg, false>>, SynthesisError> {
        self.iter()
            .zip(other.iter())
            .map(|(x, y)| x.add_unaligned(y))
            .collect()
    }

    fn hadamard(&self, other: &Self) -> Result<Vec<IntVarInner<F, Cfg, false>>, SynthesisError> {
        self.iter()
            .zip(other.iter())
            .map(|(x, y)| x.mul_unaligned(y))
            .collect()
    }

    fn scale(
        &self,
        other: &IntVarInner<F, Cfg, false>,
    ) -> Result<Vec<IntVarInner<F, Cfg, false>>, SynthesisError> {
        self.iter().map(|x| x.mul_unaligned(other)).collect()
    }
}

impl<CF: SonobeField, Cfg> MatrixGadget<IntVarInner<CF, Cfg, false>>
    for SparseMatrixVar<IntVarInner<CF, Cfg, false>>
{
    fn mul_vector(
        &self,
        v: &impl Index<usize, Output = IntVarInner<CF, Cfg, false>>,
    ) -> Result<Vec<IntVarInner<CF, Cfg, false>>, SynthesisError> {
        self.0
            .iter()
            .map(|row| {
                let len = row
                    .iter()
                    .map(|(value, col_i)| value.limbs.len() + v[*col_i].limbs.len() - 1)
                    .max()
                    .unwrap_or(0);
                // This is a combination of `mul_no_align` and `add_no_align`
                // that results in more flattened `LinearCombination`s.
                // Consequently, `ConstraintSystem::inline_all_lcs` costs less
                // time, thus making trusted setup and proof generation faster.
                let bounds = (0..len)
                    .map(|i| {
                        Bound::add_many(
                            &row.iter()
                                .flat_map(|(value, col_i)| {
                                    let start =
                                        max(i + 1, v[*col_i].bounds.len()) - v[*col_i].bounds.len();
                                    let end = min(i + 1, value.bounds.len());
                                    (start..end)
                                        .map(|j| value.bounds[j].mul(&v[*col_i].bounds[i - j]))
                                })
                                .collect::<Vec<_>>(),
                        )
                        .filter_safe::<CF>()
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or(SynthesisError::Unsatisfiable)?;
                let limbs = (0..len)
                    .map(|i| {
                        row.iter()
                            .flat_map(|(value, col_i)| {
                                let start =
                                    max(i + 1, v[*col_i].limbs.len()) - v[*col_i].limbs.len();
                                let end = min(i + 1, value.limbs.len());
                                (start..end).map(|j| &value.limbs[j] * &v[*col_i].limbs[i - j])
                            })
                            .sum()
                    })
                    .collect();
                Ok(IntVarInner::new(limbs, bounds))
            })
            .collect()
    }
}

pub fn compute_bounds(lb: &BigInt, ub: &BigInt, bits_per_limb: usize) -> Vec<Bound> {
    let len = max(lb.bits(), ub.bits()) as usize;
    let (n_full_limbs, n_remaining_bits) = len.div_rem(&bits_per_limb);

    let mut bounds = vec![
        Bound(
            if lb.is_negative() {
                BigInt::one() - (BigInt::one() << bits_per_limb)
            } else {
                BigInt::zero()
            },
            if ub.is_positive() {
                (BigInt::one() << bits_per_limb) - BigInt::one()
            } else {
                BigInt::zero()
            },
        );
        n_full_limbs
    ];

    if !n_remaining_bits.is_zero() {
        let d = BigInt::one() << (len - n_remaining_bits);
        bounds.push(Bound(lb.div_floor(&d), ub.div_ceil(&d)));
    }

    bounds
}

impl<F: SonobeField, Cfg> AllocVar<(BigInt, Bound), F> for IntVarInner<F, Cfg, true> {
    fn new_variable<T: Borrow<(BigInt, Bound)>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let (x, Bound(lb, ub)) = v.borrow();

        if x < lb || x > ub {
            return Err(SynthesisError::Unsatisfiable);
        }

        let len = max(lb.bits(), ub.bits()) as usize;

        let x_is_neg = x.is_negative();
        let mut x_bits = x
            .magnitude()
            .to_radix_le(2)
            .into_iter()
            .map(|i| i == 1)
            .collect::<Vec<_>>();
        x_bits.resize(len, false);

        let x_is_neg = if !lb.is_negative() {
            Boolean::FALSE
        } else if !ub.is_positive() {
            Boolean::TRUE
        } else {
            Boolean::new_variable(cs.clone(), || Ok(x_is_neg), mode)?
        };
        let x_bits = Vec::new_variable(cs, || Ok(x_bits), mode)?;

        let limbs = x_bits
            .chunks(F::BITS_PER_LIMB)
            .map(|chunk| {
                let limb_abs = Boolean::le_bits_to_fp(chunk)?;
                x_is_neg.select(&limb_abs.negate()?, &limb_abs)
            })
            .collect::<Result<_, _>>()?;

        let bounds = compute_bounds(&lb, &ub, F::BITS_PER_LIMB);

        let var = Self::new(limbs, bounds);

        // At this point, we are confident that:
        // * If `lb >= 0`, then `0 <= var <= 2^len - 1`.
        // * If `ub <= 0`, then `-2^len + 1 <= var <= 0`.
        // * Otherwise, `-2^len + 1 <= var <= 2^len - 1`.
        //
        // However, for soundness, we need to enforce `lb <= var <= ub`, which
        // is already guaranteed only if:
        // * `lb = 0` and `ub = 2^len - 1`
        // * `lb = -2^len + 1` and `ub = 0`
        // * `lb = -2^len + 1` and `ub = 2^len - 1`
        //
        // For other cases, we additionally check:
        // * `var <= ub`
        // * `var >= lb`
        if lb.is_zero() && ub + BigInt::one() == BigInt::one() << len {
        } else if BigInt::one() - lb == BigInt::one() << len && ub.is_zero() {
        } else if BigInt::one() - lb == BigInt::one() << len
            && ub + BigInt::one() == BigInt::one() << len
        {
        } else {
            var.enforce_lt(&Self::constant(ub + BigInt::one()))?;
            Self::constant(lb - BigInt::one()).enforce_lt(&var)?;
        }

        Ok(var)
    }

    fn new_constant(
        _cs: impl Into<Namespace<F>>,
        t: impl Borrow<(BigInt, Bound)>,
    ) -> Result<Self, SynthesisError> {
        let (x, Bound(lb, ub)) = t.borrow();

        if x < lb || x > ub {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Ignore `lb` and `ub` from now on, as a constant `x` will be bounded
        // by itself.
        let bits = x
            .magnitude()
            .to_radix_le(2)
            .into_iter()
            .map(|i| i == 1)
            .collect::<Vec<_>>();

        let (limbs, bounds) = bits
            .chunks(F::BITS_PER_LIMB)
            .map(F::BigInt::from_bits_le)
            .map(|v| {
                let v_field = if x.is_negative() {
                    -F::from(v)
                } else {
                    F::from(v)
                };
                let v_bigint = BigInt::from_biguint(x.sign(), v.into());
                (FpVar::constant(v_field), Bound(v_bigint.clone(), v_bigint))
            })
            .unzip::<_, _, Vec<_>, Vec<_>>();

        Ok(Self::new(limbs, bounds))
    }
}

impl<F: SonobeField, G: SonobeField, Cfg> AllocVar<G, F> for IntVarInner<F, Cfg, true> {
    fn new_variable<T: Borrow<G>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Self::new_variable(
            cs,
            || {
                f().map(|v| {
                    (
                        BigInt::from_biguint(Sign::Plus, (*v.borrow()).into()),
                        Bound(Zero::zero(), G::MODULUS.into().into()),
                    )
                })
            },
            mode,
        )
    }
}

impl<F: SonobeField, Cfg> IntVarInner<F, Cfg, true> {
    pub fn constant(x: BigInt) -> Self {
        Self::new_constant(ConstraintSystemRef::None, (x.clone(), Bound(x.clone(), x))).unwrap()
    }
}

macro_rules! impl_binary_op {
    (
        $trait: ident,
        $fn: ident,
        |$lhs_i:tt : &$lhs:ty, $rhs_i:tt : &$rhs:ty| -> $out:ty $body:block,
        ($($params:tt)+),
    ) => {
        impl<$($params)+> core::ops::$trait<&$rhs> for &$lhs
        {
            type Output = $out;

            fn $fn(self, other: &$rhs) -> Self::Output {
                let $lhs_i = self;
                let $rhs_i = other;
                $body
            }
        }

        impl<$($params)+> core::ops::$trait<$rhs> for &$lhs
        {
            type Output = $out;

            fn $fn(self, other: $rhs) -> Self::Output {
                core::ops::$trait::$fn(self, &other)
            }
        }

        impl<$($params)+> core::ops::$trait<&$rhs> for $lhs
        {
            type Output = $out;

            fn $fn(self, other: &$rhs) -> Self::Output {
                core::ops::$trait::$fn(&self, other)
            }
        }

        impl<$($params)+> core::ops::$trait<$rhs> for $lhs
        {
            type Output = $out;

            fn $fn(self, other: $rhs) -> Self::Output {
                core::ops::$trait::$fn(&self, &other)
            }
        }
    }
}

macro_rules! impl_assignment_op {
    (
        $assign_trait: ident,
        $assign_fn: ident,
        |$lhs_i:tt : &mut $lhs:ty, $rhs_i:tt : &$rhs:ty| $body:block,
        ($($params:tt)+),
    ) => {
        impl<$($params)+> core::ops::$assign_trait<$rhs> for $lhs
        {
            fn $assign_fn(&mut self, other: $rhs) {
                core::ops::$assign_trait::$assign_fn(self, &other)
            }
        }

        impl<$($params)+> core::ops::$assign_trait<&$rhs> for $lhs
        {
            fn $assign_fn(&mut self, other: &$rhs) {
                let $lhs_i = self;
                let $rhs_i = other;
                $body
            }
        }
    }
}

impl_binary_op!(
    Add,
    add,
    |a: &IntVarInner<F, Cfg, LHS_ALIGNED>, b: &IntVarInner<F, Cfg, RHS_ALIGNED>| -> IntVarInner<F, Cfg, false> {
        a.add_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const LHS_ALIGNED: bool, const RHS_ALIGNED: bool),
);

impl_assignment_op!(
    AddAssign,
    add_assign,
    |a: &mut IntVarInner<F, Cfg, false>, b: &IntVarInner<F, Cfg, ALIGNED>| {
        *a = a.add_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const ALIGNED: bool),
);

impl_binary_op!(
    Sub,
    sub,
    |a: &IntVarInner<F, Cfg, SELF_ALIGNED>, b: &IntVarInner<F, Cfg, OTHER_ALIGNED>| -> IntVarInner<F, Cfg, false> {
        a.sub_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const SELF_ALIGNED: bool, const OTHER_ALIGNED: bool),
);

impl_assignment_op!(
    SubAssign,
    sub_assign,
    |a: &mut IntVarInner<F, Cfg, false>, b: &IntVarInner<F, Cfg, OTHER_ALIGNED>| {
        *a = a.sub_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const OTHER_ALIGNED: bool),
);

impl_binary_op!(
    Mul,
    mul,
    |a: &IntVarInner<F, Cfg, SELF_ALIGNED>, b: &IntVarInner<F, Cfg, OTHER_ALIGNED>| -> IntVarInner<F, Cfg, false> {
        a.mul_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const SELF_ALIGNED: bool, const OTHER_ALIGNED: bool),
);

impl_assignment_op!(
    MulAssign,
    mul_assign,
    |a: &mut IntVarInner<F, Cfg, false>, b: &IntVarInner<F, Cfg, OTHER_ALIGNED>| {
        *a = a.mul_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const OTHER_ALIGNED: bool),
);

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use ark_pallas::{Fq, Fr};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, test_rng, UniformRand};
    use num_bigint::RandBigInt;

    use super::*;

    #[test]
    fn test_alloc() -> Result<(), Box<dyn Error>> {
        let rng = &mut test_rng();

        let size = 1024;
        let mut lbs = vec![BigInt::zero()];
        let mut ubs: Vec<BigInt> = vec![(BigInt::one() << size) - BigInt::one()];
        lbs.push(-ubs[0].clone());
        ubs.push(BigInt::zero());
        lbs.push(-ubs[0].clone());
        ubs.push(ubs[0].clone());
        lbs.push(rng.gen_bigint_range(&-&ubs[0], &BigInt::zero()));
        ubs.push(BigInt::zero());
        lbs.push(BigInt::zero());
        ubs.push(rng.gen_bigint_range(&BigInt::zero(), &ubs[0]));
        lbs.push(rng.gen_bigint_range(&-&ubs[0], &BigInt::zero()));
        ubs.push(rng.gen_bigint_range(&BigInt::zero(), &ubs[0]));
        lbs.push(rng.gen_bigint_range(&-&ubs[0], &BigInt::zero()));
        ubs.push(rng.gen_bigint_range(lbs.last().unwrap(), &BigInt::zero()));
        lbs.push(rng.gen_bigint_range(&BigInt::zero(), &ubs[0]));
        ubs.push(rng.gen_bigint_range(lbs.last().unwrap(), &ubs[0]));

        for (lb, ub) in lbs.into_iter().zip(ubs.into_iter()) {
            let mut v = vec![
                lb.clone(),
                ub.clone(),
                &lb + BigInt::one(),
                &ub - BigInt::one(),
            ];
            if BigInt::zero() >= lb && BigInt::zero() <= ub {
                v.push(BigInt::zero());
            }
            for _ in 0..10 {
                v.push(rng.gen_bigint_range(&lb, &ub));
            }
            for a in v {
                let cs = ConstraintSystem::<Fr>::new_ref();

                let a_var = BigIntVar::new_witness(cs.clone(), || {
                    Ok((a.clone(), Bound(lb.clone(), ub.clone())))
                })?;

                let a_const = BigIntVar::<Fr, _>::constant(a.clone());

                assert_eq!(a, a_var.value()?);
                assert_eq!(a, a_const.value()?);
                assert!(cs.is_satisfied()?);
            }
        }

        Ok(())
    }

    #[test]
    fn test_mul_bigint() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let size = 2048;

        let rng = &mut test_rng();
        let a = rng.gen_bigint(size as u64);
        let b = rng.gen_bigint(size as u64);
        let ab = &a * &b;
        let aab = &a * &ab;
        let abb = &ab * &b;

        let a_var = BigIntVar::new_witness(cs.clone(), || {
            Ok((
                a,
                Bound(
                    BigInt::one() - (BigInt::one() << size),
                    (BigInt::one() << size) - BigInt::one(),
                ),
            ))
        })?;
        let b_var = BigIntVar::new_witness(cs.clone(), || {
            Ok((
                b,
                Bound(
                    BigInt::one() - (BigInt::one() << size),
                    (BigInt::one() << size) - BigInt::one(),
                ),
            ))
        })?;
        let ab_var = BigIntVar::new_witness(cs.clone(), || {
            Ok((
                ab,
                Bound(
                    BigInt::one() - (BigInt::one() << (size * 2)),
                    (BigInt::one() << (size * 2)) - BigInt::one(),
                ),
            ))
        })?;
        let aab_var = BigIntVar::new_witness(cs.clone(), || {
            Ok((
                aab,
                Bound(
                    BigInt::one() - (BigInt::one() << (size * 3)),
                    (BigInt::one() << (size * 3)) - BigInt::one(),
                ),
            ))
        })?;
        let abb_var = BigIntVar::new_witness(cs.clone(), || {
            Ok((
                abb,
                Bound(
                    BigInt::one() - (BigInt::one() << (size * 3)),
                    (BigInt::one() << (size * 3)) - BigInt::one(),
                ),
            ))
        })?;

        a_var
            .mul_unaligned(&b_var)?
            .enforce_equal_unaligned(&ab_var)?;
        a_var
            .mul_unaligned(&ab_var)?
            .enforce_equal_unaligned(&aab_var)?;
        ab_var
            .mul_unaligned(&b_var)?
            .enforce_equal_unaligned(&abb_var)?;

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_mul_fq() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let rng = &mut test_rng();
        let a = Fq::rand(rng);
        let b = Fq::rand(rng);
        let ab = a * b;
        let aab = a * ab;
        let abb = ab * b;

        let a_var = EmulatedFieldVar::<Fr, Fq, _>::new_witness(cs.clone(), || Ok(a))?;
        let b_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(b))?;
        let ab_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(ab))?;
        let aab_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(aab))?;
        let abb_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(abb))?;

        a_var.mul_unaligned(&b_var)?.enforce_congruent(&ab_var)?;
        a_var.mul_unaligned(&ab_var)?.enforce_congruent(&aab_var)?;
        ab_var.mul_unaligned(&b_var)?.enforce_congruent(&abb_var)?;

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_pow() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let rng = &mut test_rng();

        let a = Fq::rand(rng);

        let a_var = EmulatedFieldVar::<Fr, Fq, _>::new_witness(cs.clone(), || Ok(a))?;

        let mut r_var = a_var.clone();
        for _ in 0..16 {
            r_var = r_var.mul_unaligned(&r_var)?.modulo()?;
        }
        r_var = r_var.mul_unaligned(&a_var)?.modulo()?;
        assert_eq!(a.pow([65537u64]), r_var.value()?);
        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_vec_vec_mul() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let len = 1000;

        let rng = &mut test_rng();
        let a = (0..len).map(|_| Fq::rand(rng)).collect::<Vec<Fq>>();
        let b = (0..len).map(|_| Fq::rand(rng)).collect::<Vec<Fq>>();
        let c = a.iter().zip(b.iter()).map(|(a, b)| a * b).sum::<Fq>();

        let a_var = Vec::<EmulatedFieldVar<Fr, Fq, _>>::new_witness(cs.clone(), || Ok(a))?;
        let b_var = Vec::<EmulatedFieldVar<Fr, Fq, _>>::new_witness(cs.clone(), || Ok(b))?;
        let c_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(c))?;

        let mut r_var: EmulatedFieldVar<Fr, Fq, false> =
            EmulatedFieldVar::constant(BigUint::zero().into()).into();
        for (a, b) in a_var.into_iter().zip(b_var.into_iter()) {
            r_var = r_var.add_unaligned(&a.mul_unaligned(&b)?)?;
        }
        r_var.enforce_congruent(&c_var)?;

        assert!(cs.is_satisfied()?);
        Ok(())
    }
}
