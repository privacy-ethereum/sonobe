//! Implementation of the Pedersen commitment scheme, including out-of-circuit
//! widgets and in-circuit gadgets.
//!
//! The Pedersen commitment to a vector `v` is computed as `<g, v> + h · r`,
//! where `g` and `h` are generators, `r` is a random scalar, and `<g, v>` is
//! the multi-scalar multiplication of `g` and `v`.

use ark_ec::AffineRepr;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, borrow::Borrow, iter::repeat_with, marker::PhantomData, rand::RngCore};

use super::{
    CommitmentDef, CommitmentDefGadget, CommitmentKey, CommitmentOps, Error, FieldFriendly,
    GroupFriendly,
};
use crate::{
    algebra::{
        field::emulated::EmulatedFieldVar,
        group::{BF, HasGroup, SF, emulated::EmulatedAffineVar},
    },
    circuits::linkage::{Canonical, HasConstraintField, HasGadget, HasWidget, Var},
    commitments::CommitmentOpsGadget,
    traits::SonobeCurve,
    utils::null::Null,
};

/// [`PedersenKey`] stores the public parameters for the Pedersen commitment
/// scheme, where `H` controls whether the scheme is hiding or not.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenKey<C: SonobeCurve, const H: bool> {
    g: Vec<C::Affine>,
    h: C,
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
    fn commit(&self, v: &[SF<C>], r: &SF<C>) -> Result<C, Error> {
        if self.g.len() < v.len() {
            return Err(Error::MessageTooLong(self.g.len(), v.len()));
        }
        // <g, v> + h * r
        // use msm_unchecked because we already ensured at the if that generators are long enough
        Ok(C::msm_unchecked(&self.g, v) + self.h.mul(r))
    }
}

impl<C: SonobeCurve> PedersenKey<C, false> {
    fn commit(&self, v: &[SF<C>]) -> Result<C, Error> {
        if self.g.len() < v.len() {
            return Err(Error::MessageTooLong(self.g.len(), v.len()));
        }
        // <g, v>
        // use msm_unchecked because we already ensured at the if that generators are long enough
        Ok(C::msm_unchecked(&self.g, v))
    }
}

/// [`PedersenKeyVar`] is the in-circuit variable for [`PedersenKey`], whose
/// generators are encoded in the canonical form.
pub struct PedersenKeyVar<C: SonobeCurve, const H: bool> {
    g: Vec<Var<C, Canonical>>,
    h: Var<C, Canonical>,
}

/// [`PedersenEmulatedKeyVar`] is the in-circuit variable for [`PedersenKey`],
/// whose generators are encoded in the emulated form.
pub struct PedersenEmulatedKeyVar<C: SonobeCurve, const H: bool> {
    #[allow(dead_code)]
    g: Vec<EmulatedAffineVar<SF<C>, C>>,
    #[allow(dead_code)]
    h: EmulatedAffineVar<SF<C>, C>,
}

impl<C: SonobeCurve, const H: bool> AllocVar<PedersenKey<C, H>, BF<C>> for PedersenKeyVar<C, H> {
    fn new_variable<T: Borrow<PedersenKey<C, H>>>(
        cs: impl Into<Namespace<BF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let PedersenKey { g, h } = v.borrow();

        Ok(Self {
            g: AllocVar::new_variable(cs.clone(), || Ok(&g[..]), mode)?,
            h: AllocVar::new_variable(cs.clone(), || Ok(*h), mode)?,
        })
    }
}

impl<C: SonobeCurve, const H: bool> AllocVar<PedersenKey<C, H>, SF<C>>
    for PedersenEmulatedKeyVar<C, H>
{
    fn new_variable<T: Borrow<PedersenKey<C, H>>>(
        cs: impl Into<Namespace<SF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let PedersenKey { g, h } = v.borrow();

        Ok(Self {
            g: AllocVar::new_variable(
                cs.clone(),
                || Ok(g.iter().map(|i| i.into_group()).collect::<Vec<_>>()),
                mode,
            )?,
            h: AllocVar::new_variable(cs.clone(), || Ok(*h), mode)?,
        })
    }
}

/// [`Pedersen`] defines the out-of-circuit Pedersen widget, where `H` controls
/// whether the scheme is hiding or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pedersen<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve> CommitmentDef for Pedersen<C, false> {
    const IS_HIDING: bool = false;

    type Key = PedersenKey<C, false>;
    type Unit = SF<C>;
    type Commitment = C;
    type Randomness = Null;
}

impl<C: SonobeCurve> CommitmentDef for Pedersen<C, true> {
    const IS_HIDING: bool = true;

    type Key = PedersenKey<C, true>;
    type Unit = SF<C>;
    type Commitment = C;
    type Randomness = SF<C>;
}

impl<C: SonobeCurve> HasGadget<GroupFriendly> for Pedersen<C, false> {
    type Gadget = PedersenGadget<C, false>;
}
impl<C: SonobeCurve> HasGadget<FieldFriendly> for Pedersen<C, false> {
    type Gadget = PedersenEmulatedGadget<C, false>;
}
impl<C: SonobeCurve> HasGroup for Pedersen<C, false> {
    type Group = C;
}

impl<C: SonobeCurve> HasGadget<GroupFriendly> for Pedersen<C, true> {
    type Gadget = PedersenGadget<C, true>;
}
impl<C: SonobeCurve> HasGadget<FieldFriendly> for Pedersen<C, true> {
    type Gadget = PedersenEmulatedGadget<C, true>;
}
impl<C: SonobeCurve> HasGroup for Pedersen<C, true> {
    type Group = C;
}

impl<C: SonobeCurve> CommitmentOps for Pedersen<C, false> {
    fn generate_key(len: usize, rng: impl RngCore) -> Result<PedersenKey<C, false>, Error> {
        Ok(PedersenKey::new(len, rng))
    }

    fn commit(
        ck: &PedersenKey<C, false>,
        v: &[SF<C>],
        _rng: impl RngCore,
    ) -> Result<(C, Null), Error> {
        Ok((ck.commit(v)?, Null))
    }

    fn open(ck: &PedersenKey<C, false>, v: &[SF<C>], _r: &Null, cm: &C) -> Result<(), Error> {
        (&ck.commit(v)? == cm)
            .then_some(())
            .ok_or(Error::CommitmentVerificationFail)
    }
}

impl<C: SonobeCurve> CommitmentOps for Pedersen<C, true> {
    fn generate_key(len: usize, rng: impl RngCore) -> Result<PedersenKey<C, true>, Error> {
        Ok(PedersenKey::new(len, rng))
    }

    fn commit(
        ck: &PedersenKey<C, true>,
        v: &[SF<C>],
        mut rng: impl RngCore,
    ) -> Result<(C, SF<C>), Error> {
        let r = UniformRand::rand(&mut rng);
        Ok((ck.commit(v, &r)?, r))
    }

    fn open(ck: &PedersenKey<C, true>, v: &[SF<C>], r: &SF<C>, cm: &C) -> Result<(), Error> {
        (&(ck.commit(v, r)?) == cm)
            .then_some(())
            .ok_or(Error::CommitmentVerificationFail)
    }
}

/// [`PedersenGadget`] defines the in-circuit Pedersen gadget that operates over
/// the base field of the curve and supports canonical elliptic curve point
/// variables as commitments, where `H` controls whether the scheme is hiding or
/// not.
#[derive(Clone)]
pub struct PedersenGadget<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve, const H: bool> PedersenGadget<C, H> {
    /// [`PedersenGadget::msm`] performs multi-scalar multiplication in-circuit
    /// with the given generators `g` and scalar bits `v`.
    fn msm(
        g: &[Var<C, Canonical>],
        v: &[Vec<Boolean<BF<C>>>],
    ) -> Result<Var<C, Canonical>, SynthesisError> {
        let mut res = CurveVar::zero();
        for (g_i, v_i) in g.iter().zip(v) {
            res += g_i.scalar_mul_le(v_i.to_bits_le()?.iter())?;
        }
        Ok(res)
    }
}

impl<C: SonobeCurve> CommitmentOpsGadget for PedersenGadget<C, false> {
    fn open(
        ck: &PedersenKeyVar<C, false>,
        v: &[EmulatedFieldVar<BF<C>, SF<C>>],
        _r: &Null,
        cm: &Var<C, Canonical>,
    ) -> Result<(), SynthesisError> {
        Self::msm(
            &ck.g,
            &v.iter()
                .map(|i| i.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?,
        )?
        .enforce_equal(cm)
    }
}

impl<C: SonobeCurve> CommitmentOpsGadget for PedersenGadget<C, true> {
    fn open(
        ck: &PedersenKeyVar<C, true>,
        v: &[EmulatedFieldVar<BF<C>, SF<C>>],
        r: &EmulatedFieldVar<BF<C>, SF<C>>,
        cm: &Var<C, Canonical>,
    ) -> Result<(), SynthesisError> {
        let gv = Self::msm(
            &ck.g,
            &v.iter()
                .map(|i| i.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let hr = ck.h.scalar_mul_le(r.to_bits_le()?.iter())?;
        (gv + hr).enforce_equal(cm)
    }
}

/// [`PedersenEmulatedGadget`] defines the in-circuit Pedersen gadget that
/// operates over the scalar field of the curve and supports emulated elliptic
/// curve point variables as commitments, where `H` controls whether the scheme
/// is hiding or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenEmulatedGadget<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve> HasConstraintField for PedersenGadget<C, false> {
    type ConstraintField = BF<C>;
}

impl<C: SonobeCurve> HasWidget for PedersenGadget<C, false> {
    type Widget = Pedersen<C, false>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenGadget<C, false> {
    type KeyVar = PedersenKeyVar<C, false>;

    type UnitVar = EmulatedFieldVar<BF<C>, SF<C>>;

    type CommitmentVar = Var<C, Canonical>;

    type RandomnessVar = Null;
}

impl<C: SonobeCurve> HasConstraintField for PedersenGadget<C, true> {
    type ConstraintField = BF<C>;
}

impl<C: SonobeCurve> HasWidget for PedersenGadget<C, true> {
    type Widget = Pedersen<C, true>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenGadget<C, true> {
    type KeyVar = PedersenKeyVar<C, true>;

    type UnitVar = EmulatedFieldVar<BF<C>, SF<C>>;

    type CommitmentVar = Var<C, Canonical>;

    type RandomnessVar = EmulatedFieldVar<BF<C>, SF<C>>;
}

impl<C: SonobeCurve> HasConstraintField for PedersenEmulatedGadget<C, false> {
    type ConstraintField = SF<C>;
}

impl<C: SonobeCurve> HasWidget for PedersenEmulatedGadget<C, false> {
    type Widget = Pedersen<C, false>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenEmulatedGadget<C, false> {
    type KeyVar = PedersenEmulatedKeyVar<C, false>;

    type UnitVar = FpVar<SF<C>>;

    type CommitmentVar = EmulatedAffineVar<SF<C>, C>;

    type RandomnessVar = Null;
}

impl<C: SonobeCurve> HasConstraintField for PedersenEmulatedGadget<C, true> {
    type ConstraintField = SF<C>;
}

impl<C: SonobeCurve> HasWidget for PedersenEmulatedGadget<C, true> {
    type Widget = Pedersen<C, true>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenEmulatedGadget<C, true> {
    type KeyVar = PedersenEmulatedKeyVar<C, true>;

    type UnitVar = FpVar<SF<C>>;

    type CommitmentVar = EmulatedAffineVar<SF<C>, C>;

    type RandomnessVar = FpVar<SF<C>>;
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use ark_std::{
        error::Error,
        rand::{Rng, thread_rng},
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::commitments::tests::{
        test_commitment_correctness, test_commitment_gadget_correctness,
    };

    #[test]
    fn test_pedersen_commitment() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for i in 0..10 {
            let len = rng.gen_range((1 << i)..(1 << (i + 1)));
            test_commitment_correctness::<Pedersen<G1Projective, false>>(&mut rng, len)?;
            test_commitment_correctness::<Pedersen<G1Projective, true>>(&mut rng, len)?;
        }
        Ok(())
    }

    #[test]
    fn test_pedersen_commitment_circuit() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for i in 0..5 {
            let len = rng.gen_range((1 << i)..(1 << (i + 1)));
            test_commitment_gadget_correctness::<PedersenGadget<G1Projective, false>>(
                &mut rng, len,
            )?;
            test_commitment_gadget_correctness::<PedersenGadget<G1Projective, true>>(
                &mut rng, len,
            )?;
        }
        Ok(())
    }
}
