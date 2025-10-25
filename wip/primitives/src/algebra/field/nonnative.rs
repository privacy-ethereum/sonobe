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
    ops::Index,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::Signed;

use crate::algebra::ops::bits::{FromBitsGadget, ToBitsGadgetExt};
use crate::{
    algebra::{
        field::SonobeField,
        ops::{
            eq::EquivalenceGadget,
            matrix::{MatrixGadget, SparseMatrixVar},
            vector::VectorGadget,
        },
    },
    transcripts::AbsorbableGadget,
};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Bound {
    pub lb: BigInt,
    pub ub: BigInt,
}

impl Bound {
    pub fn zero() -> Self {
        Self::default()
    }

    pub fn new_ub(ub: BigInt) -> Self {
        Self {
            lb: BigInt::zero(),
            ub,
        }
    }

    pub fn new_n_bits(n: usize) -> Self {
        Self {
            lb: BigInt::zero(),
            ub: (BigInt::one() << n) - BigInt::one(),
        }
    }

    pub fn new(lb: BigInt, ub: BigInt) -> Self {
        Self { lb, ub }
    }
}

impl Bound {
    pub fn add(&self, other: &Self) -> Self {
        Self {
            lb: &self.lb + &other.lb,
            ub: &self.ub + &other.ub,
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self {
            lb: &self.lb - &other.ub,
            ub: &self.ub - &other.lb,
        }
    }

    pub fn add_many(limbs: &[Self]) -> Self {
        Self {
            lb: limbs.iter().map(|l| &l.lb).sum(),
            ub: limbs.iter().map(|l| &l.ub).sum(),
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let ll = &self.lb * &other.lb;
        let lu = &self.lb * &other.ub;
        let ul = &self.ub * &other.lb;
        let uu = &self.ub * &other.ub;

        Self {
            lb: min(min(&ll, &lu), min(&ul, &uu)).clone(),
            ub: max(max(&ll, &lu), max(&ul, &uu)).clone(),
        }
    }

    pub fn shl(&self, shift: usize) -> Self {
        Self {
            lb: &self.lb << shift,
            ub: &self.ub << shift,
        }
    }

    pub fn filter_safe<F: PrimeField>(self) -> Option<Self> {
        let limit = BigInt::from_biguint(Sign::Plus, F::MODULUS_MINUS_ONE_DIV_TWO.into());
        (self.ub <= limit && self.lb >= -limit).then_some(self)
    }
}

// /// `LimbVar` represents a single limb of a non-native unsigned integer in the
// /// circuit.
// /// The limb value `v` should be small enough to fit into `FpVar`, and we also
// /// store an upper bound `ub` for the limb value, which is treated as a constant
// /// in the circuit and is used for efficient equality checks and some arithmetic
// /// operations.
// #[derive(Debug, Clone)]
// pub struct LimbVar<F: PrimeField> {
//     pub v: FpVar<F>,
//     pub lb: BigInt,
//     pub ub: BigInt,
// }

// impl<F: PrimeField, B: AsRef<[Boolean<F>]>> From<B> for LimbVar<F> {
//     fn from(bits: B) -> Self {
//         Self {
//             // `Boolean::le_bits_to_fp` will return an error if the internal
//             // invocation of `Boolean::enforce_in_field_le` fails.
//             // However, this method is only called when the length of `bits` is
//             // greater than `F::MODULUS_BIT_SIZE`, which should not happen in
//             // our case where `bits` is guaranteed to be short.
//             v: Boolean::le_bits_to_fp(bits.as_ref()).unwrap(),
//             lb: BigInt::zero(),
//             ub: (BigInt::one() << bits.as_ref().len()) - BigInt::one(),
//         }
//     }
// }

// impl<F: PrimeField> Default for LimbVar<F> {
//     fn default() -> Self {
//         Self {
//             v: FpVar::zero(),
//             lb: BigInt::zero(),
//             ub: BigInt::zero(),
//         }
//     }
// }

// impl<F: PrimeField> GR1CSVar<F> for LimbVar<F> {
//     type Value = F;

//     fn cs(&self) -> ConstraintSystemRef<F> {
//         self.v.cs()
//     }

//     fn value(&self) -> Result<Self::Value, SynthesisError> {
//         self.v.value()
//     }
// }

// impl<F: PrimeField> CondSelectGadget<F> for LimbVar<F> {
//     fn conditionally_select(
//         cond: &Boolean<F>,
//         true_value: &Self,
//         false_value: &Self,
//     ) -> Result<Self, SynthesisError> {
//         // We only allow selecting between two values with the same upper bound
//         assert_eq!(true_value.lb, false_value.lb);
//         assert_eq!(true_value.ub, false_value.ub);
//         Ok(Self {
//             v: cond.select(&true_value.v, &false_value.v)?,
//             lb: true_value.lb.clone(),
//             ub: true_value.ub.clone(),
//         })
//     }
// }

// impl<F: PrimeField> LimbVar<F> {
//     /// Add two `LimbVar`s.
//     /// Returns `None` if the upper bound of the sum is too large, i.e.,
//     /// greater than `F::MODULUS_MINUS_ONE_DIV_TWO`.
//     /// Otherwise, returns the sum as a `LimbVar`.
//     pub fn add(&self, other: &Self) -> Option<Self> {
//         let lbound = &self.lb + &other.lb;
//         let ubound = &self.ub + &other.ub;
//         let limit = Into::<BigUint>::into(F::MODULUS_MINUS_ONE_DIV_TWO).into();
//         if ubound > limit || lbound < -limit {
//             None
//         } else {
//             Some(Self {
//                 v: &self.v + &other.v,
//                 lb: lbound,
//                 ub: ubound,
//             })
//         }
//     }

//     /// Add multiple `LimbVar`s.
//     /// Returns `None` if the upper bound of the sum is too large, i.e.,
//     /// greater than `F::MODULUS_MINUS_ONE_DIV_TWO`.
//     /// Otherwise, returns the sum as a `LimbVar`.
//     pub fn add_many(limbs: &[Self]) -> Option<Self> {
//         let lbound = limbs.iter().map(|l| &l.lb).sum::<BigInt>();
//         let ubound = limbs.iter().map(|l| &l.ub).sum::<BigInt>();
//         let limit = Into::<BigUint>::into(F::MODULUS_MINUS_ONE_DIV_TWO).into();
//         if ubound > limit || lbound < -limit {
//             None
//         } else {
//             Some(Self {
//                 v: if limbs.is_constant() {
//                     FpVar::constant(limbs.value().unwrap_or_default().into_iter().sum())
//                 } else {
//                     limbs.iter().map(|l| &l.v).sum()
//                 },
//                 lb: lbound,
//                 ub: ubound,
//             })
//         }
//     }

//     /// Multiply two `LimbVar`s.
//     /// Returns `None` if the upper bound of the product is too large, i.e.,
//     /// greater than `F::MODULUS_MINUS_ONE_DIV_TWO`.
//     /// Otherwise, returns the product as a `LimbVar`.
//     pub fn mul(&self, other: &Self) -> Option<Self> {
//         let ll = &self.lb * &other.lb;
//         let lu = &self.lb * &other.ub;
//         let ul = &self.ub * &other.lb;
//         let uu = &self.ub * &other.ub;

//         let lbound = min(min(&ll, &lu), min(&ul, &uu)).clone();
//         let ubound = max(max(&ll, &lu), max(&ul, &uu)).clone();
//         let limit = Into::<BigUint>::into(F::MODULUS_MINUS_ONE_DIV_TWO).into();
//         if ubound > limit || lbound < -limit {
//             None
//         } else {
//             Some(Self {
//                 v: &self.v * &other.v,
//                 lb: lbound,
//                 ub: ubound,
//             })
//         }
//     }

//     pub fn zero() -> Self {
//         Self::default()
//     }

//     pub fn constant(v: BigInt) -> Self {
//         let (v_sign, v_abs) = v.clone().into_parts();
//         let limit = Into::<BigUint>::into(F::MODULUS_MINUS_ONE_DIV_TWO).into();
//         assert!(v_abs <= limit);
//         Self {
//             v: if v_sign == Sign::Minus {
//                 FpVar::constant(-F::from(v_abs))
//             } else {
//                 FpVar::constant(F::from(v_abs))
//             },
//             lb: v.clone(),
//             ub: v,
//         }
//     }
// }

// impl<F: PrimeField> ToBitsGadget<F> for LimbVar<F> {
//     fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
//         let cs = self.cs();

//         assert_eq!(self.lb, BigInt::zero());

//         let bits = &self
//             .v
//             .value()
//             .unwrap_or_default()
//             .into_bigint()
//             .to_bits_le()[..self.ub.bits() as usize];
//         let bits = if cs.is_none() {
//             Vec::new_constant(cs, bits)?
//         } else {
//             Vec::new_witness(cs, || Ok(bits))?
//         };

//         Boolean::le_bits_to_fp(&bits)?.enforce_equal(&self.v)?;

//         Ok(bits)
//     }
// }

/// `NonNativeUintVar` represents a non-native unsigned integer (BigUint) in the
/// circuit.
/// We apply [xJsnark](https://akosba.github.io/papers/xjsnark.pdf)'s techniques
/// for efficient operations on `NonNativeUintVar`.
/// Note that `NonNativeUintVar` is different from arkworks' `NonNativeFieldVar`
/// in that the latter runs the expensive `reduce` (`align` + `modulo` in our
/// terminology) after each arithmetic operation, while the former only reduces
/// the integer when explicitly called.
#[derive(Debug, Clone)]
pub struct NonNativeUintVar<F: PrimeField> {
    pub(crate) limbs: Vec<FpVar<F>>,
    bounds: Vec<Bound>,
}

impl<F: SonobeField> AllocVar<(BigInt, Bound), F> for NonNativeUintVar<F> {
    fn new_variable<T: Borrow<(BigInt, Bound)>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        todo!();
        let cs = cs.into().cs();
        let v = f()?;
        let (x, b) = v.borrow();

        if x > &b.ub || x < &b.lb {
            return Err(SynthesisError::DivisionByZero);
        }

        let (x_sign, mut x_abs) = x.clone().into_parts();

        let mut limbs = vec![];
        let mut bounds = vec![];

        let l = max(b.lb.bits(), b.ub.bits());

        if l == 0 {
            return Ok(Self { limbs, bounds });
        }

        let (num_full_chunks, final_chunk_size) = (l as usize).div_rem(&F::BITS_PER_LIMB);

        let mask = (BigUint::one() << F::BITS_PER_LIMB) - BigUint::one();

        loop {
            let limb = FpVar::new_variable(cs.clone(), || Ok(F::from(&x_abs & &mask)), mode)?;
            Self::enforce_bit_length(&limb, F::BITS_PER_LIMB)?;
            limbs.push(limb);
            bounds.push(Bound::new_n_bits(F::BITS_PER_LIMB));
            x_abs >>= F::BITS_PER_LIMB;
            if x_abs.is_zero() {
                let is_neg = Boolean::new_variable(cs.clone(), || Ok(x_sign == Sign::Minus), {
                    if b.lb >= BigInt::zero() || b.ub <= BigInt::zero() {
                        AllocationMode::Constant
                    } else {
                        mode
                    }
                })?;
                *limbs.last_mut().unwrap() *=
                    is_neg.select(&FpVar::one().negate()?, &FpVar::one())?;
                break;
            }
        }

        if final_chunk_size > 0 {
            let limb = FpVar::new_variable(cs.clone(), || Ok(F::from(x_abs)), mode)?;
            Self::enforce_bit_length(&limb, F::BITS_PER_LIMB)?;
        }

        for chunk in (0..l)
            .map(|i| x.bit(i))
            .collect::<Vec<_>>()
            .chunks(F::BITS_PER_LIMB)
        {
            let limb = F::from(F::BigInt::from_bits_le(chunk));
            let limb = FpVar::new_variable(cs.clone(), || Ok(limb), mode)?;
            Self::enforce_bit_length(&limb, chunk.len())?;
            limbs.push(limb);
            bounds.push(Bound::new_n_bits(chunk.len()));
        }
        let s = Boolean::new_variable(cs.clone(), || Ok(x.sign() == Sign::Minus), {
            if b.lb >= BigInt::zero() || b.ub <= BigInt::zero() {
                AllocationMode::Constant
            } else {
                mode
            }
        })?;
        limbs[num_full_chunks] =
            s.select(&limbs[num_full_chunks].negate()?, &limbs[num_full_chunks])?;

        let t = BigInt::one() << ((bounds.len() - 1) * F::BITS_PER_LIMB);
        bounds[num_full_chunks] = Bound::new(b.lb.div_floor(&t), b.ub.div_ceil(&t));

        Ok(Self { limbs, bounds })
    }
}

impl<F: SonobeField, G: SonobeField> AllocVar<G, F> for NonNativeUintVar<F> {
    fn new_variable<T: Borrow<G>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;

        let v = BigInt::from_biguint(Sign::Plus, v.borrow().clone().into());
        let m = BigInt::from_biguint(Sign::Plus, G::MODULUS.into());

        match mode {
            AllocationMode::Constant => Self::constant(v),
            _ => Self::new_variable(cs, || Ok((v, Bound::new(BigInt::zero(), m))), mode),
        }
    }
}

impl<F: SonobeField> EqGadget<F> for NonNativeUintVar<F> {
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
}

impl<F: SonobeField> GR1CSVar<F> for NonNativeUintVar<F> {
    type Value = BigInt;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.limbs.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut r = BigInt::zero();

        for limb in self.limbs.value()?.into_iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += if limb.into_bigint() > F::MODULUS_MINUS_ONE_DIV_TWO {
                BigInt::from_biguint(Sign::Minus, (-limb).into())
            } else {
                BigInt::from_biguint(Sign::Plus, limb.into())
            };
        }

        Ok(r)
    }
}

impl<F: PrimeField> CondSelectGadget<F> for NonNativeUintVar<F> {
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
        let mut v = vec![];
        let mut bounds = vec![];
        for i in 0..true_value.limbs.len() {
            if true_value.bounds[i] != false_value.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            v.push(cond.select(&true_value.limbs[i], &false_value.limbs[i])?);
            bounds.push(true_value.bounds[i].clone());
        }
        Ok(Self {
            limbs: v,
            bounds: bounds,
        })
    }
}

impl<F: SonobeField> NonNativeUintVar<F> {
    fn constant(v: BigInt) -> Result<Self, SynthesisError> {
        Self::new_constant(
            ConstraintSystemRef::None,
            (v.clone(), Bound::new(v.clone(), v)),
        )
    }

    fn ubound(&self) -> BigInt {
        let mut r = BigInt::zero();

        for i in self.bounds.iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += &i.ub;
        }

        r
    }

    fn lbound(&self) -> BigInt {
        let mut r = BigInt::zero();

        for i in self.bounds.iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += &i.lb;
        }

        r
    }
}

impl<F: SonobeField> NonNativeUintVar<F> {
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
            let cs = self.cs().or(other.cs());
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
        Self::enforce_bit_length(&(p - FpVar::one()), F::BITS_PER_LIMB)?;

        Ok(())
    }

    /// Enforce `self` to be equal to `other`, where `self` and `other` are not
    /// necessarily aligned.
    ///
    /// Adapted from https://github.com/akosba/jsnark/blob/0955389d0aae986ceb25affc72edf37a59109250/JsnarkCircuitBuilder/src/circuit/auxiliary/LongElement.java#L562-L798
    /// Similar implementations can also be found in https://github.com/alex-ozdemir/bellman-bignat/blob/0585b9d90154603a244cba0ac80b9aafe1d57470/src/mp/bignat.rs#L566-L661
    /// and https://github.com/arkworks-rs/r1cs-std/blob/4020fbc22625621baa8125ede87abaeac3c1ca26/src/fields/emulated_fp/reduce.rs#L201-L323
    pub fn enforce_equal_unaligned(&self, other: &Self) -> Result<(), SynthesisError> {
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
        // `c` stores the current carry of `x_i - y_i`
        let mut c = FpVar::<F>::zero();
        while i < len {
            let mut j = i;
            // The current grouped limbs of `self` and `other`.
            let mut p_limb = FpVar::zero();
            let mut q_limb = FpVar::zero();
            let mut p_bound = Bound::zero();
            let mut q_bound = Bound::zero();
            let mut step = 0;
            let mut weight = F::one();
            while j < len {
                match (
                    self.bounds[j].shl(step).add(&p_bound).filter_safe::<F>(),
                    other.bounds[j].shl(step).add(&q_bound).filter_safe::<F>(),
                ) {
                    (Some(new_p_bound), Some(new_q_bound)) => {
                        p_limb += &self.limbs[j] * weight;
                        q_limb += &other.limbs[j] * weight;
                        p_bound = new_p_bound;
                        q_bound = new_q_bound;
                    }
                    _ => break,
                }

                j += 1;
                step += F::BITS_PER_LIMB;
                weight *= F::from(BigUint::one() << F::BITS_PER_LIMB);
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
            c = (&p_limb - &q_limb + &c) * weight.inverse().unwrap();
            if j < len {
                // Unlike the code mentioned above which add some offset to the
                // diff `x_i - y_i + c` to make it always positive, we directly
                // check if the absolute value of the diff is small.
                Self::enforce_abs_bit_length(
                    &c,
                    (max(
                        min(&p_bound.lb, &q_bound.lb).bits(),
                        max(&p_bound.ub, &q_bound.ub).bits(),
                    ) as usize)
                        .checked_sub(step)
                        .unwrap_or_default(),
                )?;
            } else {
                let remaining_limbs = &(if j < self.limbs.len() { self } else { other }).limbs[j..];
                let remaining_bounds =
                    &(if j < self.bounds.len() { self } else { other }).bounds[j..];
                if remaining_limbs.is_empty() {
                    c.enforce_equal(&FpVar::zero())?;
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
                    c.enforce_equal(&remaining_limbs[0])?;
                };
            }
            // Start the next group
            i = j;
        }

        Ok(())
    }
}

impl<F: SonobeField> NonNativeUintVar<F> {
    fn enforce_bit_length(x: &FpVar<F>, length: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let cs = x.cs();

        let bits = &x.value().unwrap_or_default().into_bigint().to_bits_le()[..length];
        let bits = if cs.is_none() {
            Vec::new_constant(cs, bits)?
        } else {
            Vec::new_witness(cs, || Ok(bits))?
        };

        Boolean::le_bits_to_fp(&bits)?.enforce_equal(x)?;

        Ok(bits)
    }

    fn enforce_abs_bit_length(
        x: &FpVar<F>,
        length: usize,
    ) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let cs = x.cs();
        let mode = if cs.is_none() {
            AllocationMode::Constant
        } else {
            AllocationMode::Witness
        };

        let is_neg = Boolean::new_variable(
            cs.clone(),
            || Ok(x.value().unwrap_or_default().into_bigint() > F::MODULUS_MINUS_ONE_DIV_TWO),
            mode,
        )?;
        let bits = Vec::new_variable(
            cs.clone(),
            || {
                Ok({
                    let x = x.value().unwrap_or_default();
                    let mut bits = if is_neg.value().unwrap_or_default() {
                        -x
                    } else {
                        x
                    }
                    .into_bigint()
                    .to_bits_le();
                    bits.resize(length, false);
                    bits
                })
            },
            mode,
        )?;

        // Below is equivalent to but more efficient than
        // `Boolean::le_bits_to_fp(&bits)?.enforce_equal(&is_neg.select(&x.negate()?, &x)?)?`
        // Note that this enforces:
        // 1. The claimed absolute value `is_neg.select(&x.negate()?, &x)?` has
        //    exactly `length` bits.
        // 2. `is_neg` is indeed the sign of `x`, i.e., `is_neg = false` when
        //    `0 <= x < (|F| - 1) / 2`, and `is_neg = true` when
        //    `(|F| - 1) / 2 <= x < F`, thus the claimed absolute value is
        //    correct.
        //    If `is_neg` is incorrect, then:
        //        a. `0 <= x < (|F| - 1) / 2`, but `is_neg = true`, then
        //           `is_neg.select(&x.negate()?, &x)?` returns `|F| - x`,
        //           which is greater than `(|F| - 1) / 2` and cannot fit in
        //           `length` bits (given that `length` is small).
        //        b. `(|F| - 1) / 2 <= x < F`, but `is_neg = false`, then
        //           `is_neg.select(&x.negate()?, &x)?` returns `x`, which is
        //           greater than `(|F| - 1) / 2` and cannot fit in `length`
        //           bits.
        FpVar::from(is_neg).mul_equals(&x.double()?, &(x - Boolean::le_bits_to_fp(&bits)?))?;

        Ok(bits)
    }

    /// Compute `self + other`, without aligning the limbs.
    pub fn add_no_align(&self, other: &Self) -> Result<Self, SynthesisError> {
        let mut z = vec![FpVar::zero(); max(self.limbs.len(), other.limbs.len())];
        let mut bounds = vec![Bound::zero(); z.len()];
        for (i, v) in self.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&self.bounds[i])
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            z[i] += v;
        }
        for (i, v) in other.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&other.bounds[i])
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            z[i] += v;
        }
        Ok(Self {
            limbs: z,
            bounds: bounds,
        })
    }

    pub fn sub_no_align(&self, other: &Self) -> Result<Self, SynthesisError> {
        let mut z = vec![FpVar::zero(); max(self.limbs.len(), other.limbs.len())];
        let mut bounds = vec![Bound::zero(); z.len()];
        for (i, v) in self.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&self.bounds[i])
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            z[i] += v;
        }
        for (i, v) in other.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .sub(&other.bounds[i])
                .filter_safe::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            z[i] -= v;
        }
        Ok(Self {
            limbs: z,
            bounds: bounds,
        })
    }

    /// Compute `self * other`, without aligning the limbs.
    /// Implements the O(n) approach described in xJsnark, Section IV.B.1)
    pub fn mul_no_align(&self, other: &Self) -> Result<Self, SynthesisError> {
        let len = self.limbs.len() + other.limbs.len() - 1;
        if self.is_constant() || other.is_constant() {
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

            let z = (0..len)
                .map(|i| {
                    let start = max(i + 1, other.limbs.len()) - other.limbs.len();
                    let end = min(i + 1, self.limbs.len());
                    (start..end)
                        .map(|j| &self.limbs[j] * &other.limbs[i - j])
                        .sum()
                })
                .collect();
            return Ok(Self {
                limbs: z,
                bounds: bounds,
            });
        }
        let cs = self.cs().or(other.cs());
        let mode = if cs.is_none() {
            AllocationMode::Constant
        } else {
            AllocationMode::Witness
        };

        // Compute the result `z` outside the circuit and provide it as hints.
        let (z, bounds) = {
            let mut z = vec![F::zero(); len];
            let mut bounds = vec![Bound::zero(); len];
            for i in 0..self.limbs.len() {
                for j in 0..other.limbs.len() {
                    z[i + j] += self.limbs[i].value().unwrap_or_default()
                        * other.limbs[j].value().unwrap_or_default();
                    bounds[i + j] = bounds[i + j].add(&self.bounds[i].mul(&other.bounds[j]))
                }
            }
            (
                Vec::new_variable(cs.clone(), || Ok(z), mode)?,
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
            let o = z
                .iter()
                .zip(&c_powers)
                .map(|(v, t)| v * *t)
                .sum::<FpVar<_>>();
            // Enforce `o = l * r`
            l.mul_equals(&r, &o)?;
        }

        Ok(Self {
            limbs: z,
            bounds: bounds,
        })
    }

    /// Convert `Self` to an element in `M`, i.e., compute `Self % M::MODULUS`.
    pub fn modulo<M: PrimeField>(&self) -> Result<Self, SynthesisError> {
        let cs = self.cs();
        let m = BigInt::from_biguint(Sign::Plus, M::MODULUS.into());
        // Provide the quotient and remainder as hints
        let q = Self::new_variable_with_inferred_mode(cs.clone(), || {
            let (lb, ub) = (self.lbound().div_floor(&m), self.ubound().div_floor(&m));
            Ok((self.value()?.div_floor(&m), Bound::new(lb, ub)))
        })?;
        let r = Self::new_variable_with_inferred_mode(cs.clone(), || {
            Ok((self.value()?.abs() % &m, Bound::new_ub(m.clone())))
        })?;

        let m = Self::constant(m)?;

        // Enforce `self = q * m + r`
        q.mul_no_align(&m)?
            .add_no_align(&r)?
            .enforce_equal_unaligned(self)?;
        // Enforce `r < m` (and `r >= 0` already holds)
        r.enforce_lt(&m)?;

        Ok(r)
    }

    /// Enforce that `self` is congruent to `other` modulo `M::MODULUS`.
    pub fn enforce_congruent<M: PrimeField>(&self, other: &Self) -> Result<(), SynthesisError> {
        let cs = self.cs();
        let m = BigInt::from_biguint(Sign::Plus, M::MODULUS.into());
        // Provide the quotient as hint
        let q = Self::new_variable_with_inferred_mode(cs.clone(), || {
            let (lb, ub) = (self.lbound().div_floor(&m), self.ubound().div_floor(&m));
            Ok((self.value()?.div_floor(&m), Bound::new(lb, ub)))
        })?;

        let m = Self::constant(m)?;

        // Enforce `self - other = q * m`
        self.sub_no_align(other)?
            .enforce_equal_unaligned(&q.mul_no_align(&m)?)
    }
}

impl<F: SonobeField, M: PrimeField> EquivalenceGadget<M> for NonNativeUintVar<F> {
    fn enforce_equivalent(&self, other: &Self) -> Result<(), SynthesisError> {
        self.enforce_congruent::<M>(other)
    }
}

impl<F: SonobeField> FromBitsGadget<F> for NonNativeUintVar<F> {
    fn from_bits_le(bits: &[Boolean<F>]) -> Result<Self, SynthesisError> {
        Ok(Self {
            limbs: bits
                .as_ref()
                .chunks(F::BITS_PER_LIMB)
                .map(Boolean::le_bits_to_fp)
                .collect::<Result<_, _>>()?,
            bounds: bits
                .as_ref()
                .chunks(F::BITS_PER_LIMB)
                .map(|i| Bound::new_n_bits(i.len()))
                .collect(),
        })
    }
}

impl<F: SonobeField> ToBitsGadget<F> for NonNativeUintVar<F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        Ok(self
            .limbs
            .iter()
            .map(|limb| limb.to_n_bits_le(F::BITS_PER_LIMB))
            .collect::<Result<Vec<_>, _>>()?
            .concat())
    }
}

impl<F: SonobeField> AbsorbableGadget<FpVar<F>> for NonNativeUintVar<F> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        let bits_per_limb = F::MODULUS_BIT_SIZE as usize - 1;

        self.to_bits_le()?
            .chunks(bits_per_limb)
            .try_for_each(|i| Ok(dest.push(Boolean::le_bits_to_fp(i)?)))
    }
}

impl<F: SonobeField> VectorGadget<NonNativeUintVar<F>> for [NonNativeUintVar<F>] {
    fn add(&self, other: &Self) -> Result<Vec<NonNativeUintVar<F>>, SynthesisError> {
        self.iter()
            .zip(other.iter())
            .map(|(x, y)| x.add_no_align(y))
            .collect()
    }

    fn hadamard(&self, other: &Self) -> Result<Vec<NonNativeUintVar<F>>, SynthesisError> {
        self.iter()
            .zip(other.iter())
            .map(|(x, y)| x.mul_no_align(y))
            .collect()
    }

    fn scale(
        &self,
        other: &NonNativeUintVar<F>,
    ) -> Result<Vec<NonNativeUintVar<F>>, SynthesisError> {
        self.iter().map(|x| x.mul_no_align(other)).collect()
    }
}

impl<CF: PrimeField> MatrixGadget<NonNativeUintVar<CF>> for SparseMatrixVar<NonNativeUintVar<CF>> {
    fn mul_vector(
        &self,
        v: &impl Index<usize, Output = NonNativeUintVar<CF>>,
    ) -> Result<Vec<NonNativeUintVar<CF>>, SynthesisError> {
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
                let v = (0..len)
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
                Ok(NonNativeUintVar {
                    limbs: v,
                    bounds: bounds,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use ark_pallas::{Fq, Fr};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand, error::Error};
    use num_bigint::RandBigInt;

    use super::*;

    #[test]
    fn test_mul_biguint() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let size = 256;

        let rng = &mut test_rng();
        let a = rng.gen_biguint(size as u64);
        let b = rng.gen_biguint(size as u64);
        let ab = &a * &b;
        let aab = &a * &ab;
        let abb = &ab * &b;

        let a_var =
            NonNativeUintVar::new_witness(cs.clone(), || Ok((a.into(), Bound::new_n_bits(size))))?;
        let b_var =
            NonNativeUintVar::new_witness(cs.clone(), || Ok((b.into(), Bound::new_n_bits(size))))?;
        let ab_var = NonNativeUintVar::new_witness(cs.clone(), || {
            Ok((ab.into(), Bound::new_n_bits(size * 2)))
        })?;
        let aab_var = NonNativeUintVar::new_witness(cs.clone(), || {
            Ok((aab.into(), Bound::new_n_bits(size * 3)))
        })?;
        let abb_var = NonNativeUintVar::new_witness(cs.clone(), || {
            Ok((abb.into(), Bound::new_n_bits(size * 3)))
        })?;

        a_var
            .mul_no_align(&b_var)?
            .enforce_equal_unaligned(&ab_var)?;
        a_var
            .mul_no_align(&ab_var)?
            .enforce_equal_unaligned(&aab_var)?;
        ab_var
            .mul_no_align(&b_var)?
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

        let a_var = NonNativeUintVar::new_witness(cs.clone(), || Ok(a))?;
        let b_var = NonNativeUintVar::new_witness(cs.clone(), || Ok(b))?;
        let ab_var = NonNativeUintVar::new_witness(cs.clone(), || Ok(ab))?;
        let aab_var = NonNativeUintVar::new_witness(cs.clone(), || Ok(aab))?;
        let abb_var = NonNativeUintVar::new_witness(cs.clone(), || Ok(abb))?;

        a_var
            .mul_no_align(&b_var)?
            .enforce_congruent::<Fq>(&ab_var)?;
        a_var
            .mul_no_align(&ab_var)?
            .enforce_congruent::<Fq>(&aab_var)?;
        ab_var
            .mul_no_align(&b_var)?
            .enforce_congruent::<Fq>(&abb_var)?;

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_pow() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let rng = &mut test_rng();

        let a = Fq::rand(rng);

        let a_var = NonNativeUintVar::new_witness(cs.clone(), || Ok(a))?;

        let mut r_var = a_var.clone();
        for _ in 0..16 {
            r_var = r_var.mul_no_align(&r_var)?.modulo::<Fq>()?;
        }
        r_var = r_var.mul_no_align(&a_var)?.modulo::<Fq>()?;
        assert_eq!(
            BigInt::from_biguint(Sign::Plus, a.pow([65537u64]).into()),
            r_var.value()?
        );
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

        let a_var = Vec::<NonNativeUintVar<Fr>>::new_witness(cs.clone(), || Ok(a))?;
        let b_var = Vec::<NonNativeUintVar<Fr>>::new_witness(cs.clone(), || Ok(b))?;
        let c_var = NonNativeUintVar::new_witness(cs.clone(), || Ok(c))?;

        let mut r_var = NonNativeUintVar::constant(BigUint::zero().into())?;
        for (a, b) in a_var.into_iter().zip(b_var.into_iter()) {
            r_var = r_var.add_no_align(&a.mul_no_align(&b)?)?;
        }
        r_var.enforce_congruent::<Fq>(&c_var)?;
        println!("{}", cs.num_constraints());

        assert!(cs.is_satisfied()?);
        Ok(())
    }
}
