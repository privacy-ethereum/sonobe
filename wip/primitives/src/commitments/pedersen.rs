use ark_r1cs_std::{
    boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar, groups::CurveVar,
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{iter::repeat_with, marker::PhantomData, rand::RngCore, UniformRand};

use super::{
    CommitmentKey, Error, VectorCommitmentDef, VectorCommitmentGadgetDef, VectorCommitmentOps,
};
use crate::{
    algebra::{
        field::emulated::{EmulatedFieldVar, IntVarInner},
        group::emulated::EmulatedAffineVar,
    },
    commitments::{GroupBasedVectorCommitment, VectorCommitmentGadgetOps},
    traits::{SonobeCurve, CF1, CF2},
    utils::null::Null,
};

#[derive(Clone)]
pub struct PedersenKey<C: SonobeCurve, const H: bool> {
    pub g: Vec<C::Affine>,
    pub h: C,
}

impl<C: SonobeCurve, const H: bool> CommitmentKey for PedersenKey<C, H> {
    fn max_scalars_len(&self) -> usize {
        self.g.len()
    }
}

impl<C: SonobeCurve, const H: bool> PedersenKey<C, H> {
    fn new(len: usize, mut rng: impl RngCore) -> Self {
        let generators = repeat_with(|| C::rand(&mut rng))
            .take(len.next_power_of_two())
            .collect::<Vec<_>>();
        Self {
            g: C::normalize_batch(&generators),
            h: if H { C::rand(&mut rng) } else { C::zero() },
        }
    }
}

impl<C: SonobeCurve> PedersenKey<C, true> {
    fn commit(&self, v: &[C::ScalarField], r: &C::ScalarField) -> Result<C, Error> {
        if self.g.len() < v.len() {
            return Err(Error::MessageTooLong(self.g.len(), v.len()));
        }
        // <g, v> + h * r
        // use msm_unchecked because we already ensured at the if that generators are long enough
        Ok(C::msm_unchecked(&self.g, v) + self.h.mul(r))
    }
}

impl<C: SonobeCurve> PedersenKey<C, false> {
    fn commit(&self, v: &[C::ScalarField]) -> Result<C, Error> {
        if self.g.len() < v.len() {
            return Err(Error::MessageTooLong(self.g.len(), v.len()));
        }
        // <g, v>
        // use msm_unchecked because we already ensured at the if that generators are long enough
        Ok(C::msm_unchecked(&self.g, v))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pedersen<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenEmulatedGadget<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve> VectorCommitmentDef for Pedersen<C, false> {
    const IS_HIDING: bool = false;

    type Key = PedersenKey<C, false>;
    type Scalar = C::ScalarField;
    type Commitment = C;
    type Randomness = Null;
}

impl<C: SonobeCurve> VectorCommitmentDef for Pedersen<C, true> {
    const IS_HIDING: bool = true;

    type Key = PedersenKey<C, true>;
    type Scalar = C::ScalarField;
    type Commitment = C;
    type Randomness = C::ScalarField;
}

impl<C: SonobeCurve> VectorCommitmentGadgetDef for PedersenGadget<C, false> {
    type ConstraintField = CF2<C>;

    type KeyVar = Vec<C::Var>;

    type ScalarVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type IntermediateScalarVar = IntVarInner<CF2<C>, CF1<C>, false>;

    type CommitmentVar = C::Var;

    type RandomnessVar = Null;

    type Native = Pedersen<C, false>;
}

impl<C: SonobeCurve> VectorCommitmentGadgetDef for PedersenGadget<C, true> {
    type ConstraintField = CF2<C>;

    type KeyVar = (Vec<C::Var>, C::Var);

    type ScalarVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type IntermediateScalarVar = IntVarInner<CF2<C>, CF1<C>, false>;

    type CommitmentVar = C::Var;

    type RandomnessVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type Native = Pedersen<C, true>;
}

impl<C: SonobeCurve> VectorCommitmentGadgetDef for PedersenEmulatedGadget<C, false> {
    type ConstraintField = CF1<C>;

    type KeyVar = Vec<EmulatedAffineVar<CF1<C>, C>>;

    type ScalarVar = FpVar<CF1<C>>;

    type IntermediateScalarVar = FpVar<CF1<C>>;

    type CommitmentVar = EmulatedAffineVar<CF1<C>, C>;

    type RandomnessVar = Null;

    type Native = Pedersen<C, false>;
}

impl<C: SonobeCurve> VectorCommitmentGadgetDef for PedersenEmulatedGadget<C, true> {
    type ConstraintField = CF1<C>;

    type KeyVar = (
        Vec<EmulatedAffineVar<CF1<C>, C>>,
        EmulatedAffineVar<CF1<C>, C>,
    );

    type ScalarVar = FpVar<CF1<C>>;

    type IntermediateScalarVar = FpVar<CF1<C>>;

    type CommitmentVar = EmulatedAffineVar<CF1<C>, C>;

    type RandomnessVar = FpVar<CF1<C>>;

    type Native = Pedersen<C, true>;
}

impl<C: SonobeCurve> GroupBasedVectorCommitment for Pedersen<C, false> {
    type Gadget1 = PedersenGadget<C, false>;
    type Gadget2 = PedersenEmulatedGadget<C, false>;
}

impl<C: SonobeCurve> GroupBasedVectorCommitment for Pedersen<C, true> {
    type Gadget1 = PedersenGadget<C, true>;
    type Gadget2 = PedersenEmulatedGadget<C, true>;
}

impl<C: SonobeCurve> VectorCommitmentOps for Pedersen<C, false> {
    fn generate_key(len: usize, rng: impl RngCore) -> Result<PedersenKey<C, false>, Error> {
        Ok(PedersenKey::new(len, rng))
    }

    fn commit(
        ck: &PedersenKey<C, false>,
        v: &[CF1<C>],
        _rng: &mut impl RngCore,
    ) -> Result<(C, Null), Error> {
        Ok((ck.commit(v)?, Null))
    }

    fn open(ck: &PedersenKey<C, false>, v: &[CF1<C>], _r: &Null, cm: &C) -> Result<(), Error> {
        (&ck.commit(v)? == cm)
            .then_some(())
            .ok_or(Error::CommitmentVerificationFail)
    }
}

impl<C: SonobeCurve> VectorCommitmentOps for Pedersen<C, true> {
    fn generate_key(len: usize, rng: impl RngCore) -> Result<PedersenKey<C, true>, Error> {
        Ok(PedersenKey::new(len, rng))
    }

    fn commit(
        ck: &PedersenKey<C, true>,
        v: &[CF1<C>],
        rng: &mut impl RngCore,
    ) -> Result<(C, CF1<C>), Error> {
        let r = C::ScalarField::rand(rng);
        Ok((ck.commit(v, &r)?, r))
    }

    fn open(ck: &PedersenKey<C, true>, v: &[CF1<C>], r: &CF1<C>, cm: &C) -> Result<(), Error> {
        (&(ck.commit(v, r)?) == cm)
            .then_some(())
            .ok_or(Error::CommitmentVerificationFail)
    }
}

#[derive(Clone)]
pub struct PedersenGadget<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

// fn joint_scalar_mul_be<P: SWCurveConfig<BaseField: PrimeField>>(
//     p: &Projective<P>,
//     q: &Projective<P>,
//     bits1: impl Iterator<Item = Boolean<P::BaseField>>,
//     bits2: impl Iterator<Item = Boolean<P::BaseField>>,
// ) -> Result<ProjectiveVar<P, FpVar<P::BaseField>>, SynthesisError> {
//     // prepare bits decomposition
//     let mut bits1 = bits1.collect::<Vec<_>>();
//     if bits1.len() == 0 {
//         return Ok(ProjectiveVar::zero());
//     }
//     // Remove unnecessary constant zeros in the most-significant positions.
//     bits1 = bits1
//         .into_iter()
//         // We iterate from the MSB down.
//         .rev()
//         // Skip leading zeros, if they are constants.
//         .skip_while(|b| b.is_constant() && (b.value().unwrap() == false))
//         .collect();

//     let mut bits2 = bits2.collect::<Vec<_>>();
//     if bits2.len() == 0 {
//         return Ok(ProjectiveVar::zero());
//     }
//     // Remove unnecessary constant zeros in the most-significant positions.
//     bits2 = bits2
//         .into_iter()
//         // We iterate from the MSB down.
//         .rev()
//         // Skip leading zeros, if they are constants.
//         .skip_while(|b| b.is_constant() && (b.value().unwrap() == false))
//         .collect();

//     let acc = p.double().into_affine();
//     let sum = (p + q).into_affine();
//     let diff = (p - q).into_affine();

//     let (sum_x, sum_y) = (FpVar::Constant(sum.x), FpVar::Constant(sum.y));
//     let (diff_x, diff_y) = (FpVar::Constant(diff.x), FpVar::Constant(diff.y));
//     let (mut x, mut y) = (FpVar::Constant(acc.x), FpVar::Constant(acc.y));

//     // double-and-add loop
//     for (bit1, bit2) in (bits1.iter().rev().skip(1).rev()).zip(bits2.iter().rev().skip(1).rev()) {
//         let xor = *bit1 ^ *bit2;
//         let xx = xor.select(&diff_x, &sum_x)?;
//         let yy = xor.select(&diff_y, &sum_y)?;
//         let yy = bit1.select(&yy, &yy.negate()?)?;

//         if [&x, &y].is_constant() || ([&xx, &yy].is_constant()) {
//             let p = NonZeroAffineVar::new(x.clone(), y.clone())
//                 .double()?
//                 .add_unchecked(&NonZeroAffineVar::new(xx, yy))?;
//             x = p.x;
//             y = p.y;
//         } else {
//             let lambda_1 = (&yy - &y).mul_by_inverse_unchecked(&(&xx - &x))?;
//             let lambda_1_square = lambda_1.square()?;

//             let lambda_2 = y
//                 .mul_by_inverse_unchecked(&(&x.double()? + &xx - &lambda_1_square))?
//                 .double()?
//                 - lambda_1;

//             let x4 = lambda_2.square()? - lambda_1_square + &xx;
//             let y4 = lambda_2 * &(&x - &x4) - &y;
//             x = x4;
//             y = y4;
//         };
//     }

//     let mut acc = NonZeroAffineVar::new(x, y);
//     // last bit
//     aff1_neg = aff1_neg.add_unchecked(&acc)?;
//     acc = bits1[bits1.len() - 1].select(&acc, &aff1_neg)?;
//     aff2_neg = aff2_neg.add_unchecked(&acc)?;
//     acc = bits2[bits1.len() - 1].select(&acc, &aff2_neg)?;

//     acc.into_projective().add_mixed(&{
//         let mut p = diff;
//         for _ in 0..bits1.len() - 1 {
//             p = p.double()?;
//         }
//         NonZeroAffineVar::new(p.x, p.y.negate()?)
//     })
// }

impl<C: SonobeCurve, const H: bool> PedersenGadget<C, H> {
    fn msm(g: &[C::Var], v: &[Vec<Boolean<CF2<C>>>]) -> Result<C::Var, SynthesisError> {
        let mut res = C::Var::zero();
        let n = v.len();
        if n % 2 == 1 {
            res += g[n - 1].scalar_mul_le(v[n - 1].to_bits_le()?.iter())?;
        } else {
            res += g[n - 1].joint_scalar_mul_be(
                &g[n - 2],
                v[n - 1].to_bits_le()?.iter(),
                v[n - 2].to_bits_le()?.iter(),
            )?;
        }
        for i in (1..n - 1).step_by(2) {
            res += g[i - 1].joint_scalar_mul_be(
                &g[i],
                v[i - 1].to_bits_le()?.iter(),
                v[i].to_bits_le()?.iter(),
            )?;
        }
        Ok(res)
    }
}

impl<C: SonobeCurve> VectorCommitmentGadgetOps for PedersenGadget<C, false> {
    fn open(
        ck: &Vec<C::Var>,
        v: &[EmulatedFieldVar<CF2<C>, CF1<C>>],
        _r: &Null,
        cm: &C::Var,
    ) -> Result<(), SynthesisError> {
        Self::msm(
            ck,
            &v.iter()
                .map(|i| i.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?,
        )?
        .enforce_equal(cm)
    }
}

impl<C: SonobeCurve> VectorCommitmentGadgetOps for PedersenGadget<C, true> {
    fn open(
        (g, h): &(Vec<C::Var>, C::Var),
        v: &[EmulatedFieldVar<CF2<C>, CF1<C>>],
        r: &EmulatedFieldVar<CF2<C>, CF1<C>>,
        cm: &C::Var,
    ) -> Result<(), SynthesisError> {
        let gv = Self::msm(
            g,
            &v.iter()
                .map(|i| i.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let hr = h.scalar_mul_le(r.to_bits_le()?.iter())?;
        (gv + hr).enforce_equal(cm)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use ark_std::{error::Error, rand::Rng, test_rng};

    use super::*;
    use crate::commitments::tests::test_commitment_correctness;

    #[test]
    fn test_pedersen_commitment() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        for i in 0..10 {
            let len = rng.gen_range((1 << i)..(1 << (i + 1)));
            test_commitment_correctness::<Pedersen<G1Projective, false>>(&mut rng, len)?;
            test_commitment_correctness::<Pedersen<G1Projective, true>>(&mut rng, len)?;
        }
        Ok(())
    }

    // TODO: add back gadget tests
}
