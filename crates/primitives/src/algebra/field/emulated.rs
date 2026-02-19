//! This module provides implementation of in-circuit variables for emulated
//! integers or field elements.
//!
//! This is useful when we want to express or perform operations over a ring or
//! field in a circuit defined over a different field.
//!
//! Note that the implementation here is dedicated to Sonobe's use cases and the
//! priorities are efficiency instead of generality or usability, e.g., the user
//! needs to manually ensure the variables do not overflow the field capacity.
//! Therefore, be cautious if you want to use it in other contexts.

use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::EqGadget,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow,
    cmp::{max, min},
    fmt::Debug,
    marker::PhantomData,
    ops::Index,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::Signed;

use crate::{
    algebra::{
        field::{SonobeField, TwoStageFieldVar},
        ops::{
            bits::{FromBitsGadget, ToBitsGadgetExt},
            eq::EquivalenceGadget,
            matrix::{MatrixGadget, SparseMatrixVar},
        },
    },
    transcripts::AbsorbableVar,
};

/// [`Bounds`] records the lower and upper bounds (inclusive) of an integer.
///
/// When allocating an emulated field element, we need to decompose it into
/// several limbs, each represented as a variable in the constraint field.
/// Operations over the emulated field element are translated into operations
/// over its limbs.
/// After several operations, the limbs may grow larger than the capacity of the
/// constraint field, and to prevent that, we track the bounds of each limb
/// using this struct, so that we can take action before the limbs overflow.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Bounds(pub BigInt, pub BigInt);

impl Bounds {
    /// [`Bounds::zero`] returns the bounds `[0, 0]`.
    pub fn zero() -> Self {
        Self::default()
    }
}

impl Bounds {
    /// [`Bounds::add`] computes the sum of two pairs of bounds.
    pub fn add(&self, other: &Self) -> Self {
        // Consider two values `x` and `y`.
        // For `z = x + y`, its lower bound is the sum of the lower bounds of
        // `x` and `y`, and its upper bound is the sum of the upper bounds of
        // `x` and `y`.
        Self(&self.0 + &other.0, &self.1 + &other.1)
    }

    /// [`Bounds::sub`] computes the difference of two pairs of bounds.
    pub fn sub(&self, other: &Self) -> Self {
        // Consider two values `x` and `y`.
        // For `z = x - y`, its lower bound is the difference of the lower bound
        // of `x` and the upper bound of `y`, and its upper bound is the
        // difference of the upper bound of `x` and the lower bound of `y`.
        Self(&self.0 - &other.1, &self.1 - &other.0)
    }

    /// [`Bounds::add_many`] computes the sum of multiple pairs of bounds.
    pub fn add_many(limbs: &[Self]) -> Self {
        Self(
            limbs.iter().map(|l| &l.0).sum(),
            limbs.iter().map(|l| &l.1).sum(),
        )
    }

    /// [`Bounds::mul`] computes the product of two pairs of bounds.
    pub fn mul(&self, other: &Self) -> Self {
        // Consider two values `x` and `y`.
        // To compute the bounds of `z = x * y`, we need to take into account
        // the signs of `x` and `y`.
        //
        // Therefore, we first compute the following 4 products formed by the
        // possible combinations of the bounds of `x` and `y`:
        let ll = &self.0 * &other.0;
        let lu = &self.0 * &other.1;
        let ul = &self.1 * &other.0;
        let uu = &self.1 * &other.1;

        // `z`'s lower bound is the minimum of these products, and its upper
        // bound is the maximum of these products.
        Self(
            min(min(&ll, &lu), min(&ul, &uu)).clone(),
            max(max(&ll, &lu), max(&ul, &uu)).clone(),
        )
    }

    /// [`Bounds::shl`] shifts the bounds left by `shift` bits, i.e., multiplies
    /// the bounds by `2^shift`.
    pub fn shl(&self, shift: usize) -> Self {
        // Given `x`, the bounds of `x << shift` can simply be computed by
        // shifting the bounds of `x`.
        Self(&self.0 << shift, &self.1 << shift)
    }

    /// [`Bounds::shr_narrower`] shifts the bounds right by `shift` bits, i.e.,
    /// divides the bounds by `2^shift` and rounds the lower bound up and the
    /// upper bound down, which gives a narrower range.
    pub fn shr_narrower(&self, shift: usize) -> Self {
        let d = BigInt::from(1u64) << shift;
        Self(self.0.div_ceil(&d), self.1.div_floor(&d))
    }

    /// [`Bounds::shr_wider`] shifts the bounds right by `shift` bits, i.e.,
    /// divides the bounds by `2^shift` and rounds the lower bound down and the
    /// upper bound up, which gives a wider range.
    pub fn shr_wider(&self, shift: usize) -> Self {
        let d = BigInt::from(1u64) << shift;
        Self(self.0.div_floor(&d), self.1.div_ceil(&d))
    }

    /// [`Bounds::filter_safe`] checks if the bounds fit within the capacity of
    /// a prime field `F`, and returns `Some(self)` if so, or `None` otherwise.
    pub fn filter_safe<F: PrimeField>(self) -> Option<Self> {
        // We restrict variables to be within a window of size `(|F| + 1) / 2`,
        // and the window to be within `[-(|F| - 1) / 2, (|F| - 1) / 2]`.
        let limit = BigInt::from_biguint(Sign::Plus, F::MODULUS_MINUS_ONE_DIV_TWO.into());
        (self.0 >= -&limit && self.1 <= limit && &self.1 - &self.0 <= limit).then_some(self)
    }
}

fn compose<F: SonobeField>(limbs: impl Borrow<[F]>) -> BigInt {
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

/// [`LimbedVar`] represents an in-circuit variable for an emulated integer or
/// field element, whose value is decomposed into several limbs, each being
/// created as a [`FpVar`] in the constraint field and tracked with its bounds.
///
/// The generic parameter `Cfg` can be used to customize the behavior of ops on
/// `LimbedVar`, for instance, by specifying the modulus when emulating a field
/// element.
///
/// The const generic parameter `ALIGNED` indicates if the limbs are "aligned".
/// When allocating a [`LimbedVar`], each limb has a predefined bit-length, but
/// after several operations, the actual bit-length of each limb may grow beyond
/// that.
/// It is usually fine to have larger limbs, but if they becomes larger than the
/// field capacity, we can no longer do operations on them.
/// Therefore, we sometimes need to "align" the limbs, i.e., reduce each limb
/// back to the predefined bit-length.
/// We say the limbs are "aligned" if the actual bit-length of each limb equals
/// the predefined bit-length, and "unaligned" otherwise.
#[derive(Debug, Clone)]
pub struct LimbedVar<F: PrimeField, Cfg, const ALIGNED: bool> {
    _cfg: PhantomData<Cfg>,
    pub(crate) limbs: Vec<FpVar<F>>,
    bounds: Vec<Bounds>,
}

/// [`EmulatedIntVar`] is a type alias for emulated integer variables.
///
/// We only expose aligned variables because unaligned integer variables only
/// appear as intermediate results during computations.
pub type EmulatedIntVar<F> = LimbedVar<F, (), true>;
/// [`EmulatedFieldVar`] is a type alias for emulated field element variables.
///
/// We only expose aligned variables because unaligned integer variables only
/// appear as intermediate results during computations.
pub type EmulatedFieldVar<Base, Target> = LimbedVar<Base, Target, true>;

impl<F: SonobeField, const ALIGNED: bool> GR1CSVar<F> for LimbedVar<F, (), ALIGNED> {
    type Value = BigInt; // For integers, their values are `BigInt`.

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.limbs.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.limbs.value().map(compose)
    }
}

impl<Base: SonobeField, Target: SonobeField, const ALIGNED: bool> GR1CSVar<Base>
    for LimbedVar<Base, Target, ALIGNED>
{
    type Value = Target; // For field elements, their values are in `Target`.

    fn cs(&self) -> ConstraintSystemRef<Base> {
        self.limbs.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let v = compose(self.limbs.value()?);
        bigint_to_field_element(v).ok_or(SynthesisError::Unsatisfiable)
    }
}

fn bigint_to_field_element<F: PrimeField>(v: BigInt) -> Option<F> {
    let (sign, abs) = v.into_parts();
    if abs >= F::MODULUS.into() {
        return None;
    }
    match sign {
        Sign::Plus | Sign::NoSign => Some(F::from(abs)),
        Sign::Minus => Some(-F::from(abs)),
    }
}

impl<F: SonobeField, Cfg, const ALIGNED: bool> LimbedVar<F, Cfg, ALIGNED> {
    /// [`LimbedVar::new`] creates a new [`LimbedVar`] from the pre-allocated
    /// limbs and their bounds.
    pub fn new(limbs: Vec<FpVar<F>>, bounds: Vec<Bounds>) -> Self {
        Self {
            _cfg: PhantomData,
            limbs,
            bounds,
        }
    }

    /// [`LimbedVar::ubound`] computes the upper bound of the represented value
    /// from the upper bounds of its limbs.
    fn ubound(&self) -> BigInt {
        let mut r = BigInt::zero();

        for i in self.bounds.iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += &i.1;
        }

        r
    }

    /// [`LimbedVar::lbound`] computes the lower bound of the represented value
    /// from the lower bounds of its limbs.
    fn lbound(&self) -> BigInt {
        let mut r = BigInt::zero();

        for i in self.bounds.iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += &i.0;
        }

        r
    }
}

impl<F: SonobeField, Cfg> LimbedVar<F, Cfg, true> {
    /// [`LimbedVar::enforce_lt`] enforces `self` to be less than `other`, where
    /// both should be aligned (as indicated by the const generic).
    /// Adapted from the xJsnark [paper] and its [implementation].
    ///
    /// [paper]: https://www.cs.yale.edu/homes/cpap/published/xjsnark.pdf
    /// [implementation]: https://github.com/akosba/jsnark/blob/0955389d0aae986ceb25affc72edf37a59109250/JsnarkCircuitBuilder/src/circuit/auxiliary/LongElement.java#L801-L872
    pub fn enforce_lt(&self, other: &Self) -> Result<(), SynthesisError> {
        // Compute the difference between limbs of `other` and `self`.
        // Denote a positive limb by `+`, a negative limb by `-`, a zero limb by
        // `0`, and an unknown limb by `?`.
        // Then, for `self < other`, `delta` should look like:
        // ? ? ... ? ? + 0 0 ... 0 0
        let delta = other.sub_unaligned(self)?;
        let len = delta.limbs.len();

        // If `delta` has no limb, the difference between `self` and `other` is
        // zero, and thus `self < other` does not hold.
        if len == 0 {
            return Err(SynthesisError::Unsatisfiable);
        }

        // `helper` is a vector of booleans that indicates if the corresponding
        // limb of `delta` is the first (searching from MSB) positive limb.
        // For example, if `delta` is:
        // - + ... + - + 0 0 ... 0 0
        // <---- search in this direction --------
        // Then `helper` should be:
        // F F ... F F T F F ... F F
        let helper = {
            let cs = delta.limbs.cs();
            let mut helper = vec![false; len];
            for i in (0..len).rev() {
                let limb = delta.limbs[i].value().unwrap_or_default().into_bigint();
                if !limb.is_zero() && limb <= F::MODULUS_MINUS_ONE_DIV_TWO {
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
        for (b, d) in helper.into_iter().zip(delta.limbs) {
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
            r.mul_equals(&d, &FpVar::zero())?;
            // Add the current bit to `r`.
            r += FpVar::from(b);
        }

        // Ensure that `r` is exactly 1. This guarantees that there is exactly
        // one true value in `helper`.
        r.enforce_equal(&FpVar::one())?;

        // Ensure that `p` is positive, i.e., `1 <= p <= (|F| - 1) / 2`.
        // This guarantees that the true value in `helper` corresponds to a
        // positive limb in `delta`.
        // To this end, we check `0 <= p - 1 <= 2^x - 1`, where `2^x` should
        // satisfy `max_ub <= 2^x <= (|F| - 1) / 2`.
        // Hence, we compute `x` as the ceiling of `log2(max_ub)`, so the left
        // inequality holds, and the right inequality also holds because:
        // - `max_ub` is the upper bound of a limb in `delta`
        // - `delta` is the difference between two aligned `LimbedVar`s, whose
        //   limbs have at most `F::BITS_PER_LIMB` bits, which is much smaller
        //   than the field capacity
        // Thus, `log2(max_ub)` is at most `F::BITS_PER_LIMB + 1`, from which we
        // can conclude `2^x << (|F| - 1) / 2`.

        // `unwrap` is safe here because `None` can only happen when `delta` has
        // no limbs, which is already handled at the beginning of the function.
        let max_ub = delta.bounds.iter().map(|b| &b.1).max().unwrap();
        if !max_ub.is_positive() {
            // If the maximum upper bound of `delta`'s limbs is non-positive,
            // then all limbs in `delta` are non-positive, violating the
            // requirement of `self < other`.
            return Err(SynthesisError::Unsatisfiable);
        }
        (p - FpVar::one()).enforce_bit_length(max_ub.bits() as usize)?;

        Ok(())
    }
}

impl<F: SonobeField, Cfg> From<LimbedVar<F, Cfg, true>> for LimbedVar<F, Cfg, false> {
    fn from(v: LimbedVar<F, Cfg, true>) -> Self {
        Self::new(v.limbs, v.bounds)
    }
}

impl<F: SonobeField, Cfg, const LHS_ALIGNED: bool> LimbedVar<F, Cfg, LHS_ALIGNED> {
    /// [`LimbedVar::add_unaligned`] computes `self + other`, without aligning
    /// the limbs.
    pub fn add_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
    ) -> Result<LimbedVar<F, Cfg, false>, SynthesisError> {
        let mut limbs = vec![FpVar::zero(); max(self.limbs.len(), other.limbs.len())];
        let mut bounds = vec![Bounds::zero(); limbs.len()];
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
        Ok(LimbedVar::new(limbs, bounds))
    }

    /// [`LimbedVar::sub_unaligned`] computes `self - other`, without aligning
    /// the limbs.
    pub fn sub_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
    ) -> Result<LimbedVar<F, Cfg, false>, SynthesisError> {
        let mut limbs = vec![FpVar::zero(); max(self.limbs.len(), other.limbs.len())];
        let mut bounds = vec![Bounds::zero(); limbs.len()];
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
        Ok(LimbedVar::new(limbs, bounds))
    }

    /// [`LimbedVar::mul_unaligned`] computes `self * other`, without aligning
    /// the limbs.
    ///
    /// Here we implement the `O(n)` approach described in Section IV.B.1 of
    /// xJsnark's [paper] for non-constant operands.
    pub fn mul_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
    ) -> Result<LimbedVar<F, Cfg, false>, SynthesisError> {
        let len = self.limbs.len() + other.limbs.len() - 1;
        if self.limbs.is_constant() || other.limbs.is_constant() {
            // Use the naive approach for constant operands, which costs no
            // constraints.
            let bounds = (0..len)
                .map(|i| {
                    let start = max(i + 1, other.bounds.len()) - other.bounds.len();
                    let end = min(i + 1, self.bounds.len());
                    Bounds::add_many(
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
            return Ok(LimbedVar::new(limbs, bounds));
        }
        // Compute the product `limbs` outside the circuit and provide it as
        // hints.
        let (limbs, bounds) = {
            let cs = self.limbs.cs().or(other.limbs.cs());
            let mut limbs = vec![F::zero(); len];
            let mut bounds = vec![Bounds::zero(); len];
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

        Ok(LimbedVar::new(limbs, bounds))
    }

    /// [`LimbedVar::enforce_equal_unaligned`] enforces the equality between
    /// `self` and `other` that are not necessarily aligned.
    ///
    /// Adapted from https://github.com/akosba/jsnark/blob/0955389d0aae986ceb25affc72edf37a59109250/JsnarkCircuitBuilder/src/circuit/auxiliary/LongElement.java#L562-L798
    /// Similar implementations can also be found in https://github.com/alex-ozdemir/bellman-bignat/blob/0585b9d90154603a244cba0ac80b9aafe1d57470/src/mp/bignat.rs#L566-L661
    /// and https://github.com/arkworks-rs/r1cs-std/blob/4020fbc22625621baa8125ede87abaeac3c1ca26/src/fields/emulated_fp/reduce.rs#L201-L323
    pub fn enforce_equal_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
    ) -> Result<(), SynthesisError> {
        // Equality between `self` and `other` can be reduced to the equality
        // between `diff = self - other` and 0.
        let diff = self.sub_unaligned(other)?;

        let mut carry = FpVar::zero();
        let mut carry_bounds = Bounds::zero();
        let mut group_bounds = Bounds::zero();
        let mut offset = 0;
        // `unwrap` is safe as long as `F` is a prime field with `|F| > 2`.
        let inv = F::from(BigUint::one() << F::BITS_PER_LIMB)
            .inverse()
            .unwrap();

        // For each limb in `diff`, we first try to group its _bounds_ into
        // `group_bounds`.
        // If the new bounds do not overflow / underflow, we can safely group
        // the _limb_.
        //
        // By saying group, we mean the operation `Σ x_i 2^{i * W}`, where `W`
        // is `F::BITS_PER_LIMB`, the initial number of bits in a limb.
        // This is just as what we do in grade school arithmetic, e.g.,
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
        //
        // Assume a grouped limb `v` consists of `k` original limbs.
        // Then the lower `k * W` bits of `v` must be zero for equality to hold,
        // which is checked by enforcing that `2^{k * W}` divides `v`.
        // To this end, we compute the quotient `q = v / 2^{k * W}` and enforce
        // `q` is small that doesn't cause the multiplication `q * 2^{k * W}` to
        // overflow / underflow.
        //
        // Moreover, we need to take into account the carry from the previous
        // grouped limb, i.e., we actually enforce `carry + v` is a multiple of
        // `2^{k * W}`, and derive the next carry by computing the quotient `q`.
        //
        // We can further avoid storing `v` by updating the carry on the fly for
        // each limb, i.e., `carry = (carry + limb) / 2^W`, until the virtual
        // grouped limb `v` is finalized.
        for (limb, bounds) in diff.limbs.iter().zip(&diff.bounds) {
            if let Some(new_group_bounds) = group_bounds.add(&bounds.shl(offset)).filter_safe::<F>()
            {
                carry = (carry + limb) * inv;
                carry_bounds = carry_bounds.add(bounds).shr_narrower(F::BITS_PER_LIMB);
                group_bounds = new_group_bounds;
                offset += F::BITS_PER_LIMB;
            } else {
                // New bounds overflow / underflow, i.e., the current group is
                // finalized.

                debug_assert!(carry_bounds.shl(offset).0 >= group_bounds.0);
                debug_assert!(carry_bounds.shl(offset).1 <= group_bounds.1);

                // We ensure `carry` is small, i.e., `lb <= carry <= ub`, or
                // equivalently, `0 <= carry - lb <= ub - lb`, which can be done
                // by ensuring `carry - lb` is a `log2(ub - lb + 1)`-bit number.
                (&carry
                    - bigint_to_field_element::<F>(carry_bounds.0.clone())
                        .ok_or(SynthesisError::Unsatisfiable)?)
                .enforce_bit_length(
                    (&carry_bounds.1 - &carry_bounds.0 + BigInt::one()).bits() as usize
                )?;

                carry = (carry + limb) * inv;
                carry_bounds = carry_bounds.add(bounds).shr_narrower(F::BITS_PER_LIMB);
                group_bounds = carry_bounds.clone();
                offset = 0;
            }
        }

        carry.enforce_equal(&FpVar::zero())?;

        Ok(())
    }
}

impl<Base: SonobeField, Target: SonobeField, const LHS_ALIGNED: bool>
    LimbedVar<Base, Target, LHS_ALIGNED>
{
    /// [`LimbedVar::modulo`] computes `self % Target::MODULUS` and returns the
    /// result as an aligned [`LimbedVar`].
    ///
    /// Note that we allow emulated field elements to be larger than the modulus
    /// temporarily during computations, but the final result must be reduced
    /// modulo `Target::MODULUS`, and for efficiency, this needs to be done by
    /// the caller explicitly.
    pub fn modulo(&self) -> Result<LimbedVar<Base, Target, true>, SynthesisError> {
        let cs = self.cs();
        let m = BigInt::from_biguint(Sign::Plus, Target::MODULUS.into());
        // Provide the quotient and remainder as hints
        let (q, r) = {
            let v = compose(self.limbs.value().unwrap_or_default());
            let q = v.div_floor(&m);
            let r = v - &q * &m;

            (
                LimbedVar::new_variable_with_inferred_mode(cs.clone(), || {
                    Ok((
                        q,
                        Bounds(self.lbound().div_floor(&m), self.ubound().div_floor(&m)),
                    ))
                })?,
                LimbedVar::new_variable_with_inferred_mode(cs.clone(), || {
                    Ok((r, Bounds(Zero::zero(), m.clone())))
                })?,
            )
        };

        let m = LimbedVar::constant(m);

        // Enforce `self = q * m + r`
        q.mul_unaligned(&m)?
            .add_unaligned(&r)?
            .enforce_equal_unaligned(self)?;
        // Enforce `r < m` (and `r >= 0` already holds)
        r.enforce_lt(&m)?;

        Ok(r)
    }

    /// [`LimbedVar::enforce_congruent`] enforce that `self` is congruent to
    /// `other` modulo `Target::MODULUS`.
    pub fn enforce_congruent<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<Base, Target, RHS_ALIGNED>,
    ) -> Result<(), SynthesisError> {
        let cs = self.cs();
        let m = BigInt::from_biguint(Sign::Plus, Target::MODULUS.into());
        // Provide the quotient as hint
        let q = LimbedVar::new_variable_with_inferred_mode(cs.clone(), || {
            let x = compose(self.limbs.value().unwrap_or_default());
            let y = compose(other.limbs.value().unwrap_or_default());
            Ok((
                (x - y).div_floor(&m),
                Bounds(self.lbound().div_floor(&m), self.ubound().div_floor(&m)),
            ))
        })?;

        let m = LimbedVar::constant(m);

        // Enforce `self - other = q * m`
        self.sub_unaligned(other)?
            .enforce_equal_unaligned(&q.mul_unaligned(&m)?)
    }
}

// The following lines are quite repetitive, but we have to implement them all
// to make the compiler happy.
impl<Base: SonobeField, Target: SonobeField> EquivalenceGadget<LimbedVar<Base, Target, true>>
    for LimbedVar<Base, Target, true>
{
    fn enforce_equivalent(&self, other: &Self) -> Result<(), SynthesisError> {
        self.enforce_equal(other)
    }
}

impl<Base: SonobeField, Target: SonobeField> EquivalenceGadget<LimbedVar<Base, Target, true>>
    for LimbedVar<Base, Target, false>
{
    fn enforce_equivalent(
        &self,
        other: &LimbedVar<Base, Target, true>,
    ) -> Result<(), SynthesisError> {
        self.enforce_congruent(other)
    }
}

impl<Base: SonobeField, Target: SonobeField> EquivalenceGadget<LimbedVar<Base, Target, false>>
    for LimbedVar<Base, Target, true>
{
    fn enforce_equivalent(
        &self,
        other: &LimbedVar<Base, Target, false>,
    ) -> Result<(), SynthesisError> {
        self.enforce_congruent(other)
    }
}

impl<Base: SonobeField, Target: SonobeField> EquivalenceGadget<LimbedVar<Base, Target, false>>
    for LimbedVar<Base, Target, false>
{
    fn enforce_equivalent(
        &self,
        other: &LimbedVar<Base, Target, false>,
    ) -> Result<(), SynthesisError> {
        self.enforce_congruent(other)
    }
}

impl<F: SonobeField> EquivalenceGadget<LimbedVar<F, (), true>> for LimbedVar<F, (), true> {
    fn enforce_equivalent(&self, other: &LimbedVar<F, (), true>) -> Result<(), SynthesisError> {
        self.enforce_equal(other)
    }
}

impl<F: SonobeField> EquivalenceGadget<LimbedVar<F, (), true>> for LimbedVar<F, (), false> {
    fn enforce_equivalent(&self, other: &LimbedVar<F, (), true>) -> Result<(), SynthesisError> {
        self.enforce_equal_unaligned(other)
    }
}

impl<F: SonobeField> EquivalenceGadget<LimbedVar<F, (), false>> for LimbedVar<F, (), true> {
    fn enforce_equivalent(&self, other: &LimbedVar<F, (), false>) -> Result<(), SynthesisError> {
        self.enforce_equal_unaligned(other)
    }
}

impl<F: SonobeField> EquivalenceGadget<LimbedVar<F, (), false>> for LimbedVar<F, (), false> {
    fn enforce_equivalent(&self, other: &LimbedVar<F, (), false>) -> Result<(), SynthesisError> {
        self.enforce_equal_unaligned(other)
    }
}

impl<Base: SonobeField, Target: SonobeField> TryFrom<LimbedVar<Base, Target, false>>
    for LimbedVar<Base, Target, true>
{
    type Error = SynthesisError;

    fn try_from(v: LimbedVar<Base, Target, false>) -> Result<Self, Self::Error> {
        v.modulo()
    }
}

impl<Base: SonobeField, Target: SonobeField> TwoStageFieldVar for LimbedVar<Base, Target, true> {
    type Intermediate = LimbedVar<Base, Target, false>;
}

// Only implement `EqGadget` for aligned variables.
impl<F: SonobeField, Cfg> EqGadget<F> for LimbedVar<F, Cfg, true> {
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
        self.is_eq(other)?
            .conditional_enforce_equal(&Boolean::TRUE, should_enforce)
    }
}

impl<F: SonobeField, Cfg> FromBitsGadget<F> for LimbedVar<F, Cfg, true> {
    fn from_bits_le(bits: &[Boolean<F>]) -> Result<Self, SynthesisError> {
        Self::from_bounded_bits_le(
            bits,
            Bounds(
                BigInt::zero(),
                (BigInt::one() << bits.len()) - BigInt::one(),
            ),
        )
    }

    fn from_bounded_bits_le(bits: &[Boolean<F>], bounds: Bounds) -> Result<Self, SynthesisError> {
        Ok(Self::new(
            bits.chunks(F::BITS_PER_LIMB)
                .map(Boolean::le_bits_to_fp)
                .collect::<Result<_, _>>()?,
            compute_bounds(&bounds.0, &bounds.1, F::BITS_PER_LIMB),
        ))
    }
}

impl<F: PrimeField, Cfg: Clone> CondSelectGadget<F> for LimbedVar<F, Cfg, true> {
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

impl<F: PrimeField, Cfg> ToBitsGadget<F> for LimbedVar<F, Cfg, true> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        for bound in &self.bounds {
            if bound.0 < BigInt::zero() {
                return Err(SynthesisError::Unsatisfiable);
            }
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

impl<F: PrimeField, Cfg> AbsorbableVar<F> for LimbedVar<F, Cfg, true> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        let bits_per_limb = F::MODULUS_BIT_SIZE as usize - 1;

        self.to_bits_le()?
            .chunks(bits_per_limb)
            .try_for_each(|i| Boolean::le_bits_to_fp(i).map(|v| dest.push(v)))
    }
}

impl<CF: SonobeField, Cfg> MatrixGadget<LimbedVar<CF, Cfg, false>>
    for SparseMatrixVar<LimbedVar<CF, Cfg, false>>
{
    fn mul_vector(
        &self,
        v: &impl Index<usize, Output = LimbedVar<CF, Cfg, false>>,
    ) -> Result<Vec<LimbedVar<CF, Cfg, false>>, SynthesisError> {
        self.0
            .iter()
            .map(|row| {
                let len = row
                    .iter()
                    .map(|(value, col_i)| value.limbs.len() + v[*col_i].limbs.len() - 1)
                    .max()
                    .unwrap_or(0);
                // This is a combination of `mul_unaligned` and `add_unaligned`
                // that results in more flattened `LinearCombination`s.
                // Consequently, `ConstraintSystem::inline_all_lcs` costs less
                // time, thus making trusted setup and proof generation faster.
                let bounds = (0..len)
                    .map(|i| {
                        Bounds::add_many(
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
                Ok(LimbedVar::new(limbs, bounds))
            })
            .collect()
    }
}

fn compute_bounds(lb: &BigInt, ub: &BigInt, bits_per_limb: usize) -> Vec<Bounds> {
    let len = max(lb.bits(), ub.bits()) as usize;
    let (n_full_limbs, n_remaining_bits) = len.div_rem(&bits_per_limb);

    let mut bounds = vec![
        Bounds(
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
        bounds.push(Bounds(lb.div_floor(&d), ub.div_ceil(&d)));
    }

    bounds
}

impl<F: SonobeField, Cfg> AllocVar<(BigInt, Bounds), F> for LimbedVar<F, Cfg, true> {
    fn new_variable<T: Borrow<(BigInt, Bounds)>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let (x, Bounds(lb, ub)) = v.borrow();

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

        let bounds = compute_bounds(lb, ub, F::BITS_PER_LIMB);

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
        #[allow(clippy::if_same_then_else)]
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
        t: impl Borrow<(BigInt, Bounds)>,
    ) -> Result<Self, SynthesisError> {
        let (x, Bounds(lb, ub)) = t.borrow();

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
                (FpVar::constant(v_field), Bounds(v_bigint.clone(), v_bigint))
            })
            .unzip::<_, _, Vec<_>, Vec<_>>();

        Ok(Self::new(limbs, bounds))
    }
}

impl<F: SonobeField, G: SonobeField, Cfg> AllocVar<G, F> for LimbedVar<F, Cfg, true> {
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
                        Bounds(Zero::zero(), G::MODULUS.into().into()),
                    )
                })
            },
            mode,
        )
    }
}

impl<F: SonobeField, Cfg> LimbedVar<F, Cfg, true> {
    /// [`LimbedVar::constant`] allocates a constant [`LimbedVar`] with value
    /// `x`.
    pub fn constant(x: BigInt) -> Self {
        // `unwrap` below is safe because we are allocating a constant value,
        // which is guaranteed to succeed.
        Self::new_constant(ConstraintSystemRef::None, (x.clone(), Bounds(x.clone(), x))).unwrap()
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
    |a: &LimbedVar<F, Cfg, LHS_ALIGNED>, b: &LimbedVar<F, Cfg, RHS_ALIGNED>| -> LimbedVar<F, Cfg, false> {
        a.add_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const LHS_ALIGNED: bool, const RHS_ALIGNED: bool),
);

impl_assignment_op!(
    AddAssign,
    add_assign,
    |a: &mut LimbedVar<F, Cfg, false>, b: &LimbedVar<F, Cfg, ALIGNED>| {
        *a = a.add_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const ALIGNED: bool),
);

impl_binary_op!(
    Sub,
    sub,
    |a: &LimbedVar<F, Cfg, SELF_ALIGNED>, b: &LimbedVar<F, Cfg, OTHER_ALIGNED>| -> LimbedVar<F, Cfg, false> {
        a.sub_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const SELF_ALIGNED: bool, const OTHER_ALIGNED: bool),
);

impl_assignment_op!(
    SubAssign,
    sub_assign,
    |a: &mut LimbedVar<F, Cfg, false>, b: &LimbedVar<F, Cfg, OTHER_ALIGNED>| {
        *a = a.sub_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const OTHER_ALIGNED: bool),
);

impl_binary_op!(
    Mul,
    mul,
    |a: &LimbedVar<F, Cfg, SELF_ALIGNED>, b: &LimbedVar<F, Cfg, OTHER_ALIGNED>| -> LimbedVar<F, Cfg, false> {
        a.mul_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const SELF_ALIGNED: bool, const OTHER_ALIGNED: bool),
);

impl_assignment_op!(
    MulAssign,
    mul_assign,
    |a: &mut LimbedVar<F, Cfg, false>, b: &LimbedVar<F, Cfg, OTHER_ALIGNED>| {
        *a = a.mul_unaligned(b).unwrap()
    },
    (F: SonobeField, Cfg, const OTHER_ALIGNED: bool),
);

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use ark_pallas::{Fq, Fr};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{
        UniformRand,
        error::Error,
        rand::{Rng, thread_rng},
    };
    use num_bigint::RandBigInt;
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn test_eq() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let zero = LimbedVar::<Fr, (), true>::new(vec![], vec![]);
        let zero2 = LimbedVar::<Fr, (), true>::new(
            vec![
                FpVar::new_witness(cs.clone(), || {
                    Ok(Fr::from(BigUint::one() << Fr::BITS_PER_LIMB))
                })?,
                FpVar::new_witness(cs.clone(), || Ok(-Fr::one()))?,
            ],
            vec![
                Bounds(
                    -(BigInt::one() << (Fr::BITS_PER_LIMB * 2)),
                    BigInt::one() << (Fr::BITS_PER_LIMB * 2),
                ),
                Bounds(
                    -(BigInt::one() << (Fr::BITS_PER_LIMB * 2)),
                    BigInt::one() << (Fr::BITS_PER_LIMB * 2),
                ),
            ],
        );
        let zero3 = LimbedVar::<Fr, (), true>::new(
            vec![
                FpVar::new_witness(cs.clone(), || {
                    Ok(Fr::from(BigUint::one() << Fr::BITS_PER_LIMB))
                })?,
                FpVar::new_witness(cs.clone(), || Ok(-Fr::one()))?,
            ],
            vec![
                Bounds(
                    BigInt::zero(),
                    BigInt::from_biguint(Sign::Plus, Fr::MODULUS_MINUS_ONE_DIV_TWO.into()),
                ),
                Bounds(
                    -BigInt::from_biguint(Sign::Plus, Fr::MODULUS_MINUS_ONE_DIV_TWO.into()),
                    BigInt::zero(),
                ),
            ],
        );

        zero.enforce_equal_unaligned(&zero2)?;
        zero.enforce_equal_unaligned(&zero3)?;

        let rng = &mut thread_rng();

        let n_limbs = 100;

        let coeffs = (0..n_limbs)
            .map(|_| if rng.gen_bool(0.5) {
                -Fr::one()
            } else {
                Fr::one()
            } * Fr::from(rng.gen_biguint(Fr::BITS_PER_LIMB as u64 * 2 - 1)))
            .collect::<Vec<_>>();
        let unaligned = LimbedVar::<Fr, (), true>::new(
            Vec::new_witness(cs.clone(), || Ok(&coeffs[..]))?,
            vec![
                Bounds(
                    -(BigInt::one() << (Fr::BITS_PER_LIMB * 2)),
                    BigInt::one() << (Fr::BITS_PER_LIMB * 2),
                );
                n_limbs
            ],
        );

        let aligned = EmulatedIntVar::new_witness(cs.clone(), || {
            let v = compose(&coeffs[..]);
            Ok((
                v,
                Bounds(
                    BigInt::one() - (BigInt::one() << (Fr::BITS_PER_LIMB * 2 * n_limbs)),
                    (BigInt::one() << (Fr::BITS_PER_LIMB * 2 * n_limbs)) - BigInt::one(),
                ),
            ))
        })?;
        aligned.enforce_equal_unaligned(&unaligned)?;

        assert!(cs.is_satisfied()?);

        let mut unaligned_incorrect = unaligned.clone();
        unaligned_incorrect.limbs[0] = if coeffs[0].is_zero() {
            FpVar::new_witness(cs.clone(), || Ok(Fr::one()))?
        } else {
            FpVar::new_witness(cs.clone(), || Ok(-coeffs[0]))?
        };
        aligned.enforce_equal_unaligned(&unaligned_incorrect)?;

        assert!(!cs.is_satisfied()?);

        Ok(())
    }

    #[test]
    fn test_alloc() -> Result<(), Box<dyn Error>> {
        let rng = &mut thread_rng();

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

                let a_var = EmulatedIntVar::new_witness(cs.clone(), || {
                    Ok((a.clone(), Bounds(lb.clone(), ub.clone())))
                })?;

                let a_const = EmulatedIntVar::<Fr>::constant(a.clone());

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

        let rng = &mut thread_rng();
        let a = rng.gen_bigint(size as u64);
        let b = rng.gen_bigint(size as u64);
        let ab = &a * &b;
        let aab = &a * &ab;
        let abb = &ab * &b;

        let a_var = EmulatedIntVar::new_witness(cs.clone(), || {
            Ok((
                a,
                Bounds(
                    BigInt::one() - (BigInt::one() << size),
                    (BigInt::one() << size) - BigInt::one(),
                ),
            ))
        })?;
        let b_var = EmulatedIntVar::new_witness(cs.clone(), || {
            Ok((
                b,
                Bounds(
                    BigInt::one() - (BigInt::one() << size),
                    (BigInt::one() << size) - BigInt::one(),
                ),
            ))
        })?;
        let ab_var = EmulatedIntVar::new_witness(cs.clone(), || {
            Ok((
                ab,
                Bounds(
                    BigInt::one() - (BigInt::one() << (size * 2)),
                    (BigInt::one() << (size * 2)) - BigInt::one(),
                ),
            ))
        })?;
        let aab_var = EmulatedIntVar::new_witness(cs.clone(), || {
            Ok((
                aab,
                Bounds(
                    BigInt::one() - (BigInt::one() << (size * 3)),
                    (BigInt::one() << (size * 3)) - BigInt::one(),
                ),
            ))
        })?;
        let abb_var = EmulatedIntVar::new_witness(cs.clone(), || {
            Ok((
                abb,
                Bounds(
                    BigInt::one() - (BigInt::one() << (size * 3)),
                    (BigInt::one() << (size * 3)) - BigInt::one(),
                ),
            ))
        })?;

        let neg_a_var = EmulatedFieldVar::constant(BigInt::zero()) - &a_var;
        let neg_b_var = EmulatedFieldVar::constant(BigInt::zero()) - &b_var;
        let neg_ab_var = EmulatedFieldVar::constant(BigInt::zero()) - &ab_var;
        let neg_aab_var = EmulatedFieldVar::constant(BigInt::zero()) - &aab_var;
        let neg_abb_var = EmulatedFieldVar::constant(BigInt::zero()) - &abb_var;

        a_var
            .mul_unaligned(&b_var)?
            .enforce_equal_unaligned(&ab_var)?;
        neg_a_var
            .mul_unaligned(&neg_b_var)?
            .enforce_equal_unaligned(&ab_var)?;
        a_var
            .mul_unaligned(&neg_b_var)?
            .enforce_equal_unaligned(&neg_ab_var)?;
        neg_a_var
            .mul_unaligned(&b_var)?
            .enforce_equal_unaligned(&neg_ab_var)?;

        a_var
            .mul_unaligned(&ab_var)?
            .enforce_equal_unaligned(&aab_var)?;
        neg_a_var
            .mul_unaligned(&neg_ab_var)?
            .enforce_equal_unaligned(&aab_var)?;
        a_var
            .mul_unaligned(&neg_ab_var)?
            .enforce_equal_unaligned(&neg_aab_var)?;
        neg_a_var
            .mul_unaligned(&ab_var)?
            .enforce_equal_unaligned(&neg_aab_var)?;

        ab_var
            .mul_unaligned(&b_var)?
            .enforce_equal_unaligned(&abb_var)?;
        neg_ab_var
            .mul_unaligned(&neg_b_var)?
            .enforce_equal_unaligned(&abb_var)?;
        ab_var
            .mul_unaligned(&neg_b_var)?
            .enforce_equal_unaligned(&neg_abb_var)?;
        neg_ab_var
            .mul_unaligned(&b_var)?
            .enforce_equal_unaligned(&neg_abb_var)?;

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_mul_fq() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let rng = &mut thread_rng();
        let a = Fq::rand(rng);
        let b = Fq::rand(rng);
        let ab = a * b;
        let aab = a * ab;
        let abb = ab * b;

        let a_var = EmulatedFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(a))?;
        let b_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(b))?;
        let ab_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(ab))?;
        let aab_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(aab))?;
        let abb_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(abb))?;

        let neg_a_var = EmulatedFieldVar::constant(BigInt::zero()) - &a_var;
        let neg_b_var = EmulatedFieldVar::constant(BigInt::zero()) - &b_var;
        let neg_ab_var = EmulatedFieldVar::constant(BigInt::zero()) - &ab_var;
        let neg_aab_var = EmulatedFieldVar::constant(BigInt::zero()) - &aab_var;
        let neg_abb_var = EmulatedFieldVar::constant(BigInt::zero()) - &abb_var;

        a_var.mul_unaligned(&b_var)?.enforce_congruent(&ab_var)?;
        neg_a_var
            .mul_unaligned(&neg_b_var)?
            .enforce_congruent(&ab_var)?;
        a_var
            .mul_unaligned(&neg_b_var)?
            .enforce_congruent(&neg_ab_var)?;
        neg_a_var
            .mul_unaligned(&b_var)?
            .enforce_congruent(&neg_ab_var)?;

        a_var.mul_unaligned(&ab_var)?.enforce_congruent(&aab_var)?;
        neg_a_var
            .mul_unaligned(&neg_ab_var)?
            .enforce_congruent(&aab_var)?;
        a_var
            .mul_unaligned(&neg_ab_var)?
            .enforce_congruent(&neg_aab_var)?;
        neg_a_var
            .mul_unaligned(&ab_var)?
            .enforce_congruent(&neg_aab_var)?;

        ab_var.mul_unaligned(&b_var)?.enforce_congruent(&abb_var)?;
        neg_ab_var
            .mul_unaligned(&neg_b_var)?
            .enforce_congruent(&abb_var)?;
        ab_var
            .mul_unaligned(&neg_b_var)?
            .enforce_congruent(&neg_abb_var)?;
        neg_ab_var
            .mul_unaligned(&b_var)?
            .enforce_congruent(&neg_abb_var)?;

        assert_eq!(a_var.mul_unaligned(&b_var)?.modulo()?.value()?, ab);
        assert_eq!(neg_a_var.mul_unaligned(&neg_b_var)?.modulo()?.value()?, ab);
        assert_eq!(a_var.mul_unaligned(&neg_b_var)?.modulo()?.value()?, -ab);
        assert_eq!(neg_a_var.mul_unaligned(&b_var)?.modulo()?.value()?, -ab);

        assert_eq!(a_var.mul_unaligned(&ab_var)?.modulo()?.value()?, aab);
        assert_eq!(
            neg_a_var.mul_unaligned(&neg_ab_var)?.modulo()?.value()?,
            aab
        );
        assert_eq!(a_var.mul_unaligned(&neg_ab_var)?.modulo()?.value()?, -aab);
        assert_eq!(neg_a_var.mul_unaligned(&ab_var)?.modulo()?.value()?, -aab);

        assert_eq!(ab_var.mul_unaligned(&b_var)?.modulo()?.value()?, abb);
        assert_eq!(
            neg_ab_var.mul_unaligned(&neg_b_var)?.modulo()?.value()?,
            abb
        );
        assert_eq!(ab_var.mul_unaligned(&neg_b_var)?.modulo()?.value()?, -abb);
        assert_eq!(neg_ab_var.mul_unaligned(&b_var)?.modulo()?.value()?, -abb);

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_pow() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let rng = &mut thread_rng();

        let a = Fq::rand(rng);

        let a_var = EmulatedFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(a))?;

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

        let rng = &mut thread_rng();
        let a = (0..len).map(|_| Fq::rand(rng)).collect::<Vec<Fq>>();
        let b = (0..len).map(|_| Fq::rand(rng)).collect::<Vec<Fq>>();
        let c = a.iter().zip(b.iter()).map(|(a, b)| a * b).sum::<Fq>();

        let a_var = Vec::<EmulatedFieldVar<Fr, Fq>>::new_witness(cs.clone(), || Ok(a))?;
        let b_var = Vec::<EmulatedFieldVar<Fr, Fq>>::new_witness(cs.clone(), || Ok(b))?;
        let c_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(c))?;

        let mut r_var: LimbedVar<Fr, Fq, false> =
            EmulatedFieldVar::constant(BigUint::zero().into()).into();
        for (a, b) in a_var.into_iter().zip(b_var.into_iter()) {
            r_var = r_var.add_unaligned(&a.mul_unaligned(&b)?)?;
        }
        r_var.enforce_congruent(&c_var)?;

        assert!(cs.is_satisfied()?);
        Ok(())
    }
}
