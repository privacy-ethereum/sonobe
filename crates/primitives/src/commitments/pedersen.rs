//! Implementation of the Pedersen commitment scheme, including out-of-circuit
//! widgets and in-circuit gadgets.
//!
//! The Pedersen commitment to a vector `v` is computed as `<g, v> + h · r`,
//! where `g` and `h` are generators, `r` is a random scalar, and `<g, v>` is
//! the multi-scalar multiplication of `g` and `v`.

use ark_ec::AffineRepr;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    UniformRand, any::TypeId, borrow::Borrow, iter::repeat_with, marker::PhantomData, rand::RngCore,
};

use super::{CommitmentDef, CommitmentDefGadget, CommitmentKey, CommitmentOps, Error};
use crate::{
    algebra::{
        field::emulated::EmulatedFieldVar,
        group::{JointScalarMul, emulated::EmulatedAffineVar},
    },
    circuits::{
        WitnessToPublic,
        alloc::{CommitmentKeyCache, CommittedCache, RandomnessCache, UsizeSet},
    },
    commitments::{CommitmentOpsGadget, GroupBasedCommitment},
    traits::{CF1, CF2, SonobeCurve},
    utils::null::Null,
};

/// [`PedersenKey`] stores the public parameters for the Pedersen commitment
/// scheme, where `H` controls whether the scheme is hiding or not.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenKey<C: SonobeCurve, const H: bool> {
    pub g: Vec<C::Affine>,
    pub h: C::Affine,
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
            h: if H {
                C::Affine::rand(&mut rng)
            } else {
                C::Affine::zero()
            },
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
        Ok(C::msm_unchecked(&self.g, v) + self.h * r)
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

/// [`PedersenKeyVar`] is the in-circuit variable for [`PedersenKey`], whose
/// generators are encoded in the canonical form.
pub struct PedersenKeyVar<C: SonobeCurve, const H: bool> {
    g: Vec<C::Var>,
    h: C::Var,
}

/// [`PedersenEmulatedKeyVar`] is the in-circuit variable for [`PedersenKey`],
/// whose generators are encoded in the emulated form.
pub struct PedersenEmulatedKeyVar<C: SonobeCurve, const H: bool> {
    #[allow(dead_code)]
    g: Vec<EmulatedAffineVar<CF1<C>, C>>,
    #[allow(dead_code)]
    h: EmulatedAffineVar<CF1<C>, C>,
}

pub struct PedersenFakeKeyVar<C: SonobeCurve, const H: bool>(PedersenKey<C, H>);

impl<C: SonobeCurve, const H: bool> AllocVar<PedersenKey<C, H>, C::BaseField>
    for PedersenKeyVar<C, H>
{
    fn new_variable<T: Borrow<PedersenKey<C, H>>>(
        cs: impl Into<Namespace<C::BaseField>>,
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

impl<C: SonobeCurve, const H: bool> AllocVar<PedersenKey<C, H>, CF1<C>>
    for PedersenEmulatedKeyVar<C, H>
{
    fn new_variable<T: Borrow<PedersenKey<C, H>>>(
        cs: impl Into<Namespace<CF1<C>>>,
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
            h: AllocVar::new_variable(cs.clone(), || Ok(h.into_group()), mode)?,
        })
    }
}

impl<C: SonobeCurve, const H: bool> AllocVar<PedersenKey<C, H>, CF1<C>>
    for PedersenFakeKeyVar<C, H>
{
    fn new_variable<T: Borrow<PedersenKey<C, H>>>(
        cs: impl Into<Namespace<CF1<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let v = f()?;
        Ok(PedersenFakeKeyVar(v.borrow().clone()))
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
    type Scalar = C::ScalarField;
    type Commitment = C;
    type Randomness = Null;
}

impl<C: SonobeCurve> CommitmentDef for Pedersen<C, true> {
    const IS_HIDING: bool = true;

    type Key = PedersenKey<C, true>;
    type Scalar = C::ScalarField;
    type Commitment = C;
    type Randomness = C::ScalarField;
}

impl<C: SonobeCurve> GroupBasedCommitment for Pedersen<C, false> {
    type Gadget1 = PedersenGadget<C, false>;
    type Gadget2 = PedersenCommitAndProveGadget<C, false>;
}

impl<C: SonobeCurve> GroupBasedCommitment for Pedersen<C, true> {
    type Gadget1 = PedersenGadget<C, true>;
    type Gadget2 = PedersenCommitAndProveGadget<C, true>;
}

impl<C: SonobeCurve> CommitmentOps for Pedersen<C, false> {
    fn generate_key(len: usize, rng: impl RngCore) -> Result<PedersenKey<C, false>, Error> {
        Ok(PedersenKey::new(len, rng))
    }

    fn commit(
        ck: &PedersenKey<C, false>,
        v: &[CF1<C>],
        _rng: impl RngCore,
    ) -> Result<(C, Null), Error> {
        Ok((ck.commit(v)?, Null))
    }

    fn open(ck: &PedersenKey<C, false>, v: &[CF1<C>], _r: &Null, cm: &C) -> Result<(), Error> {
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
        v: &[CF1<C>],
        mut rng: impl RngCore,
    ) -> Result<(C, CF1<C>), Error> {
        let r = C::ScalarField::rand(&mut rng);
        Ok((ck.commit(v, &r)?, r))
    }

    fn open(ck: &PedersenKey<C, true>, v: &[CF1<C>], r: &CF1<C>, cm: &C) -> Result<(), Error> {
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

impl<C: SonobeCurve> CommitmentOpsGadget for PedersenGadget<C, false> {
    fn open(
        ck: &PedersenKeyVar<C, false>,
        v: &[EmulatedFieldVar<CF2<C>, CF1<C>>],
        _r: &Null,
        cm: &C::Var,
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
        v: &[EmulatedFieldVar<CF2<C>, CF1<C>>],
        r: &EmulatedFieldVar<CF2<C>, CF1<C>>,
        cm: &C::Var,
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

impl<C: SonobeCurve> CommitmentDefGadget for PedersenGadget<C, false> {
    type ConstraintField = CF2<C>;

    type KeyVar = PedersenKeyVar<C, false>;

    type ScalarVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type CommitmentVar = C::Var;

    type RandomnessVar = Null;

    type Widget = Pedersen<C, false>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenGadget<C, true> {
    type ConstraintField = CF2<C>;

    type KeyVar = PedersenKeyVar<C, true>;

    type ScalarVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type CommitmentVar = C::Var;

    type RandomnessVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type Widget = Pedersen<C, true>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenEmulatedGadget<C, false> {
    type ConstraintField = CF1<C>;

    type KeyVar = PedersenEmulatedKeyVar<C, false>;

    type ScalarVar = FpVar<CF1<C>>;

    type CommitmentVar = EmulatedAffineVar<CF1<C>, C>;

    type RandomnessVar = Null;

    type Widget = Pedersen<C, false>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenEmulatedGadget<C, true> {
    type ConstraintField = CF1<C>;

    type KeyVar = PedersenEmulatedKeyVar<C, true>;

    type ScalarVar = FpVar<CF1<C>>;

    type CommitmentVar = EmulatedAffineVar<CF1<C>, C>;

    type RandomnessVar = FpVar<CF1<C>>;

    type Widget = Pedersen<C, true>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCommitAndProveGadget<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenCommitAndProveGadget<C, false> {
    type ConstraintField = CF1<C>;

    type KeyVar = PedersenFakeKeyVar<C, false>;

    type ScalarVar = FpVar<CF1<C>>;

    type CommitmentVar = EmulatedAffineVar<CF1<C>, C>;

    type RandomnessVar = Null;

    type Widget = Pedersen<C, false>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenCommitAndProveGadget<C, true> {
    type ConstraintField = CF1<C>;

    type KeyVar = PedersenFakeKeyVar<C, true>;

    type ScalarVar = FpVar<CF1<C>>;

    type CommitmentVar = EmulatedAffineVar<CF1<C>, C>;

    type RandomnessVar = FpVar<CF1<C>>;

    type Widget = Pedersen<C, true>;
}

impl<C: SonobeCurve> CommitmentOpsGadget for PedersenCommitAndProveGadget<C, false> {
    fn open(
        ck: &PedersenFakeKeyVar<C, false>,
        v: &[FpVar<CF1<C>>],
        _r: &Null,
        cm: &EmulatedAffineVar<CF1<C>, C>,
    ) -> Result<(), SynthesisError> {
        todo!()
    }
}

impl<C: SonobeCurve> CommitmentOpsGadget for PedersenCommitAndProveGadget<C, true> {
    fn open(
        ck: &PedersenFakeKeyVar<C, true>,
        v: &[FpVar<CF1<C>>],
        r: &FpVar<CF1<C>>,
        cm: &EmulatedAffineVar<CF1<C>, C>,
    ) -> Result<(), SynthesisError> {
        cm.mark_as_public()?;

        let cs = v.cs().or(r.cs()).or(cm.cs());

        let cs = cs.borrow_mut().ok_or(SynthesisError::MissingCS)?;
        let mut cache = cs.cache_map.borrow_mut();
        if !cs.is_in_setup_mode() {
            cache
                .get_mut(&TypeId::of::<RandomnessCache>())
                .ok_or(SynthesisError::AssignmentMissing)?
                .downcast_mut::<Vec<CF1<C>>>()
                .ok_or(SynthesisError::AssignmentMissing)?
                .push(r.value()?);
        } else {
            cache
                .get_mut(&TypeId::of::<CommitmentKeyCache>())
                .ok_or(SynthesisError::AssignmentMissing)?
                .downcast_mut::<Vec<PedersenKey<C, true>>>()
                .ok_or(SynthesisError::AssignmentMissing)?
                .push(PedersenKey {
                    g: ck.0.g[..v.len()].to_vec(),
                    h: ck.0.h,
                });
        }
        // TODO: independent on alloc order
        let indices = v
            .iter()
            .map(|i| match i {
                FpVar::Constant(_) => Err(SynthesisError::AssignmentMissing),
                FpVar::Var(fp) => {
                    if !fp.variable.is_witness() {
                        Err(SynthesisError::AssignmentMissing)
                    } else {
                        Ok(fp.variable.index().unwrap())
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        cache
            .get_mut(&TypeId::of::<CommittedCache>())
            .ok_or(SynthesisError::AssignmentMissing)?
            .downcast_mut::<UsizeSet>()
            .ok_or(SynthesisError::AssignmentMissing)?
            .extend(indices);

        Ok(())
    }
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
