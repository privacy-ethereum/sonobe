use ark_r1cs_std::{boolean::Boolean, convert::ToBitsGadget, groups::CurveVar};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{iter::repeat_with, marker::PhantomData, rand::RngCore, UniformRand};

use super::{Error, VectorCommitment};
use crate::traits::{Null, SonobeCurve, CF2};

#[derive(Debug, PartialEq)]
pub struct Pedersen<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve, const H: bool> Pedersen<C, H> {
    fn msm(g: &[C::Affine], v: &[C::ScalarField]) -> Result<C, Error> {
        if g.len() < v.len() {
            return Err(Error::MessageTooLong(g.len(), v.len()));
        }
        // <g, v>
        // use msm_unchecked because we already ensured at the if that generators are long enough
        Ok(C::msm_unchecked(g, v))
    }
}

impl<C: SonobeCurve> VectorCommitment for Pedersen<C, false> {
    const IS_HIDING: bool = false;

    type Key = Vec<C::Affine>;
    type Scalar = C::ScalarField;
    type Commitment = C;
    type Randomness = Null;

    fn generate_key(mut rng: impl RngCore, len: usize) -> Result<Self::Key, Error> {
        let generators = repeat_with(|| C::rand(&mut rng))
            .take(len.next_power_of_two())
            .collect::<Vec<_>>();
        Ok(C::normalize_batch(&generators))
    }

    fn commit(
        g: &Self::Key,
        v: &[Self::Scalar],
        _rng: impl RngCore,
    ) -> Result<(Self::Commitment, Self::Randomness), Error> {
        Ok((Self::msm(g, v)?, Null))
    }

    fn open(
        ck: &Self::Key,
        v: &[Self::Scalar],
        _r: &Self::Randomness,
        cm: &Self::Commitment,
    ) -> Result<bool, Error> {
        Ok(&Self::msm(ck, v)? == cm)
    }
}

impl<C: SonobeCurve> VectorCommitment for Pedersen<C, true> {
    const IS_HIDING: bool = true;

    type Key = (Vec<C::Affine>, C);
    type Scalar = C::ScalarField;
    type Commitment = C;
    type Randomness = C::ScalarField;

    fn generate_key(mut rng: impl RngCore, len: usize) -> Result<Self::Key, Error> {
        Ok((
            Pedersen::<C, false>::generate_key(&mut rng, len)?,
            C::rand(&mut rng),
        ))
    }

    fn commit(
        (g, h): &Self::Key,
        v: &[Self::Scalar],
        mut rng: impl RngCore,
    ) -> Result<(Self::Commitment, Self::Randomness), Error> {
        let r = C::ScalarField::rand(&mut rng);
        Ok((Self::msm(g, v)? + h.mul(r), r))
    }

    fn open(
        (g, h): &Self::Key,
        v: &[Self::Scalar],
        r: &Self::Randomness,
        cm: &Self::Commitment,
    ) -> Result<bool, Error> {
        Ok(&(Self::msm(g, v)? + h.mul(r)) == cm)
    }
}

pub struct PedersenGadget<C: SonobeCurve, const H: bool = false> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve, const H: bool> PedersenGadget<C, H> {
    pub fn commit(
        h: &C::Var,
        g: &[C::Var],
        v: &[Vec<Boolean<CF2<C>>>],
        r: &[Boolean<CF2<C>>],
    ) -> Result<C::Var, SynthesisError> {
        let mut res = C::Var::zero();
        if H {
            res += h.scalar_mul_le(r.iter())?;
        }
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

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use ark_std::{error::Error, rand::Rng, test_rng};

    use crate::commitments::tests::test_commitment_correctness;

    use super::*;

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
