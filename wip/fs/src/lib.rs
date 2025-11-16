pub mod hypernova;
pub mod nova;
pub mod ova;
pub mod protogalaxy;

use std::ops::{Deref, DerefMut};

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, fmt::Debug, rand::RngCore};
use sonobe_primitives::{
    arithmetizations::{Arith, ArithConfig},
    circuits::AssignmentsOwned,
    commitments::{GroupBasedVectorCommitment, VectorCommitment, VectorCommitmentGadget},
    relations::{Relation, WitnessInstanceSampler},
    sumcheck::Error as SumCheckError,
    traits::{Dummy, SonobeField, CF2},
    transcripts::{Absorbable, AbsorbableGadget, Transcript, TranscriptVar},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    ArithError(#[from] sonobe_primitives::arithmetizations::Error),
    #[error(transparent)]
    CommitmentError(#[from] sonobe_primitives::commitments::Error),
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    #[error(transparent)]
    SumCheckError(#[from] SumCheckError),
    #[error("Unsupported use case: {0}")]
    Unsupported(String),
    #[error("Failed to create domain")]
    DomainCreationFailure,
}

pub trait FoldingWitness<VC: VectorCommitment>: Debug {
    const N_OPENINGS: usize;

    /// Returns the reference to all openings contained in the witness, each
    /// being a tuple of the values being committed to and the randomness.
    fn openings(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)>;
}

pub trait FoldingInstance<VC: VectorCommitment>: Clone + Debug + PartialEq + Absorbable {
    const N_COMMITMENTS: usize;

    /// Returns the commitments contained in the committed instance.
    fn commitments(&self) -> Vec<&VC::Commitment>;

    fn public_inputs(&self) -> &[VC::Scalar];

    fn public_inputs_mut(&mut self) -> &mut [VC::Scalar];
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainWitness<V>(pub Vec<V>);

impl<V> Deref for PlainWitness<V> {
    type Target = Vec<V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V> DerefMut for PlainWitness<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<V> From<Vec<V>> for PlainWitness<V> {
    fn from(v: Vec<V>) -> Self {
        Self(v)
    }
}

impl<V: Absorbable> Absorbable for PlainWitness<V> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest)
    }
}

impl<F: PrimeField, V: AbsorbableGadget<F>> AbsorbableGadget<F> for PlainWitness<V> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)
    }
}

impl<X: AllocVar<Y, F>, Y, F: Field> AllocVar<PlainWitness<Y>, F> for PlainWitness<X> {
    fn new_variable<T: Borrow<PlainWitness<Y>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let v = f()?;
        Vec::new_variable(cs, || Ok(&v.borrow()[..]), mode).map(|v| Self(v))
    }
}

impl<F: PrimeField, X: CondSelectGadget<F>> CondSelectGadget<F> for PlainWitness<X> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.len() != false_value.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self(
            true_value
                .0
                .iter()
                .zip(false_value.0.iter())
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl<F: Field, V: GR1CSVar<F>> GR1CSVar<F> for PlainWitness<V> {
    type Value = PlainWitness<V::Value>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.value().map(PlainWitness)
    }
}

impl<V: Default + Clone, A: ArithConfig> Dummy<&A> for PlainWitness<V> {
    fn dummy(cfg: &A) -> Self {
        vec![V::default(); cfg.n_witnesses()].into()
    }
}

impl<VC: VectorCommitment> FoldingWitness<VC> for PlainWitness<VC::Scalar> {
    const N_OPENINGS: usize = 0;

    fn openings(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)> {
        vec![]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainInstance<V>(pub Vec<V>);

impl<V> Deref for PlainInstance<V> {
    type Target = Vec<V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V> DerefMut for PlainInstance<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<V> From<Vec<V>> for PlainInstance<V> {
    fn from(v: Vec<V>) -> Self {
        Self(v)
    }
}

impl<V: Absorbable> Absorbable for PlainInstance<V> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest)
    }
}

impl<F: PrimeField, V: AbsorbableGadget<F>> AbsorbableGadget<F> for PlainInstance<V> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)
    }
}

impl<X: AllocVar<Y, F>, Y, F: Field> AllocVar<PlainInstance<Y>, F> for PlainInstance<X> {
    fn new_variable<T: Borrow<PlainInstance<Y>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let v = f()?;
        Vec::new_variable(cs, || Ok(&v.borrow()[..]), mode).map(|v| Self(v))
    }
}

impl<F: PrimeField, X: CondSelectGadget<F>> CondSelectGadget<F> for PlainInstance<X> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.len() != false_value.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self(
            true_value
                .0
                .iter()
                .zip(false_value.0.iter())
                .map(|(t, f)| cond.select(t, f))
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl<F: Field, V: GR1CSVar<F>> GR1CSVar<F> for PlainInstance<V> {
    type Value = PlainInstance<V::Value>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.value().map(PlainInstance)
    }
}

impl<V: Default + Clone, A: ArithConfig> Dummy<&A> for PlainInstance<V> {
    fn dummy(cfg: &A) -> Self {
        vec![V::default(); cfg.n_public_inputs()].into()
    }
}

impl<VC: VectorCommitment> FoldingWitness<VC> for PlainInstance<VC::Scalar> {
    const N_OPENINGS: usize = 0;

    fn openings(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)> {
        vec![]
    }
}

impl<VC: VectorCommitment> FoldingInstance<VC> for PlainInstance<VC::Scalar> {
    const N_COMMITMENTS: usize = 0;

    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![]
    }

    fn public_inputs(&self) -> &[VC::Scalar] {
        self
    }

    fn public_inputs_mut(&mut self) -> &mut [VC::Scalar] {
        self
    }
}

pub trait DeciderKey {}

pub trait FoldingScheme<const M: usize = 1, const N: usize = 1> {
    type VC: VectorCommitment<Scalar: SonobeField>;
    type RW: FoldingWitness<Self::VC> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    type RU: FoldingInstance<Self::VC> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    type IW: FoldingWitness<Self::VC> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    type IU: FoldingInstance<Self::VC> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    type TranscriptField: SonobeField;
    type Arith: Arith;
    type Config;
    type PublicParam;
    type ProverKey;
    type VerifierKey;
    type DeciderKey: Clone
        + Relation<Self::RW, Self::RU, Error = Error>
        + Relation<Self::IW, Self::IU, Error = Error>
        + WitnessInstanceSampler<Self::RW, Self::RU, Source = (), Error = Error>
        + WitnessInstanceSampler<
            Self::IW,
            Self::IU,
            Source = AssignmentsOwned<<Self::VC as VectorCommitment>::Scalar>,
            Error = Error,
        >;
    type Challenge;
    type Proof: Clone + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;

    /// The preprocessing method is a randomized algorithm that takes as input
    /// the size bounds of the folding scheme, which are contained in the
    /// `config` parameter, and outputs the public parameters.
    ///
    /// Here, the randomness source is controlled by `rng`.
    ///
    /// The security parameter is implicitly specified by the size of underlying
    /// fields and groups.
    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;

    /// The key generation method is a deterministic algorithm that takes as
    /// input the public parameters `pp` and the constraint system `arith`, and
    /// outputs a prover key and a verifier key.
    fn generate_keys(
        pp: Self::PublicParam,
        arith: Self::Arith,
    ) -> Result<(Self::ProverKey, Self::VerifierKey, Self::DeciderKey), Error>;

    /// The proof generation method is a deterministic algorithm that takes as
    /// input the prover key `pk`, the transcript `transcript` between the
    /// prover and the verifier, the first witness-instance pair `W`, `U`, the
    /// second witness-instance pair `w`, `u`, and outputs the folded witness
    /// and instance, the proof, and the (intermediate) randomness.
    ///
    /// Here, the randomness source is controlled by `transcript`. The returned
    /// intermediate randomness is useful for the construction of CycleFold
    /// circuits in our CycleFold-based folding-to-IVC compiler.
    #[allow(non_snake_case)]
    fn prove(
        pk: &Self::ProverKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        Ws: &[impl Borrow<Self::RW>; M],
        Us: &[impl Borrow<Self::RU>; M],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof, Self::Challenge), Error>;

    #[allow(non_snake_case)]
    fn verify(
        vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof,
    ) -> Result<Self::RU, Error>;

    #[allow(non_snake_case)]
    fn decide_running(dk: &Self::DeciderKey, W: &Self::RW, U: &Self::RU) -> Result<(), Error> {
        Relation::<Self::RW, Self::RU>::check_relation(dk, W, U)
    }

    fn decide_incoming(dk: &Self::DeciderKey, w: &Self::IW, u: &Self::IU) -> Result<(), Error> {
        Relation::<Self::IW, Self::IU>::check_relation(dk, w, u)
    }
}

pub trait FoldingWitnessVar<VC: VectorCommitmentGadget>:
    AllocVar<Self::Value, VC::ConstraintField>
    + GR1CSVar<VC::ConstraintField, Value: FoldingWitness<VC::Native>>
{
}

impl<VC: VectorCommitmentGadget, T> FoldingWitnessVar<VC> for T where
    T: AllocVar<Self::Value, VC::ConstraintField>
        + GR1CSVar<VC::ConstraintField, Value: FoldingWitness<VC::Native>>
{
}

pub trait FoldingInstanceVar<VC: VectorCommitmentGadget>:
    AllocVar<Self::Value, VC::ConstraintField>
    + GR1CSVar<VC::ConstraintField, Value: FoldingInstance<VC::Native>>
    + AbsorbableGadget<VC::ConstraintField>
    + CondSelectGadget<VC::ConstraintField>
{
    /// Returns the commitments contained in the committed instance.
    fn commitments(&self) -> Vec<&VC::CommitmentVar>;

    fn public_inputs(&self) -> &Vec<VC::ScalarVar>;

    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<VC::ConstraintField>>,
        u: &Self::Value,
        x: Vec<VC::ScalarVar>,
    ) -> Result<Self, SynthesisError>;
}

pub type PlainWitnessVar<VC> = PlainWitness<<VC as VectorCommitmentGadget>::ScalarVar>;
pub type PlainInstanceVar<VC> = PlainInstance<<VC as VectorCommitmentGadget>::ScalarVar>;

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for PlainInstanceVar<VC> {
    fn commitments(&self) -> Vec<&VC::CommitmentVar> {
        vec![]
    }

    fn public_inputs(&self) -> &Vec<VC::ScalarVar> {
        self
    }

    fn new_witness_with_public_inputs(
        _cs: impl Into<Namespace<VC::ConstraintField>>,
        _u: &Self::Value,
        x: Vec<VC::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self(x))
    }
}

pub trait GroupBasedFoldingSchemePrimary<const M: usize = 1, const N: usize = 1>:
    FoldingScheme<
    M,
    N,
    VC: GroupBasedVectorCommitment,
    TranscriptField = <<Self as FoldingScheme<M, N>>::VC as VectorCommitment>::Scalar,
>
{
    type Gadget: FoldingSchemePartialGadget<
        M,
        N,
        Native = Self,
        VC = <Self::VC as GroupBasedVectorCommitment>::EmulatedGadget,
    >;
}

pub trait GroupBasedFoldingSchemeSecondary<const M: usize = 1, const N: usize = 1>:
    FoldingScheme<
    M,
    N,
    VC: GroupBasedVectorCommitment,
    TranscriptField = CF2<<<Self as FoldingScheme<M, N>>::VC as VectorCommitment>::Commitment>,
>
{
    type Gadget: FoldingSchemeFullGadget<
        M,
        N,
        Native = Self,
        VC = <Self::VC as VectorCommitment>::Gadget,
    >;
}

pub trait FoldingSchemePartialGadget<const M: usize = 1, const N: usize = 1> {
    type Native: FoldingScheme<M, N>;

    type VC: VectorCommitmentGadget<Native = <Self::Native as FoldingScheme<M, N>>::VC>;
    type RW: FoldingWitnessVar<Self::VC, Value = <Self::Native as FoldingScheme<M, N>>::RW>;
    type RU: FoldingInstanceVar<Self::VC, Value = <Self::Native as FoldingScheme<M, N>>::RU>;
    type IW: FoldingWitnessVar<Self::VC, Value = <Self::Native as FoldingScheme<M, N>>::IW>;
    type IU: FoldingInstanceVar<Self::VC, Value = <Self::Native as FoldingScheme<M, N>>::IU>;

    type VerifierKey;

    type Challenge;

    type Proof: AllocVar<
            <Self::Native as FoldingScheme<M, N>>::Proof,
            <Self::VC as VectorCommitmentGadget>::ConstraintField,
        > + GR1CSVar<
            <Self::VC as VectorCommitmentGadget>::ConstraintField,
            Value = <Self::Native as FoldingScheme<M, N>>::Proof,
        >;

    #[allow(non_snake_case)]
    fn verify_hinted(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<<Self::VC as VectorCommitmentGadget>::ConstraintField>,
        Us: [&Self::RU; M],
        us: [&Self::IU; N],
        proof: &Self::Proof,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError>;
}

pub trait FoldingSchemeFullGadget<const M: usize = 1, const N: usize = 1>:
    FoldingSchemePartialGadget<M, N>
{
    #[allow(non_snake_case)]
    fn verify(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<<Self::VC as VectorCommitmentGadget>::ConstraintField>,
        Us: [&Self::RU; M],
        us: [&Self::IU; N],
        proof: &Self::Proof,
    ) -> Result<Self::RU, SynthesisError>;
}

#[cfg(test)]
mod tests {
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::{error::Error, rand::Rng, sync::Arc};
    use sonobe_primitives::{
        circuits::{AssignmentsOwned, ConstraintSystemBuilder},
        relations::WitnessInstanceSampler,
        transcripts::griffin::{GriffinParams, sponge::GriffinSponge},
    };

    use super::*;

    #[allow(non_snake_case)]
    pub fn test_folding_scheme<FS: FoldingScheme<M, N>, const M: usize, const N: usize>(
        config: FS::Config,
        circuit: impl ConstraintSynthesizer<<FS::VC as VectorCommitment>::Scalar>,
        assignments_vec: Vec<AssignmentsOwned<<FS::VC as VectorCommitment>::Scalar>>,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>>
    where
        FS::Arith: From<ConstraintSystem<<FS::VC as VectorCommitment>::Scalar>>,
    {
        let pp = FS::preprocess(config, &mut rng)?;

        let cs = ConstraintSystemBuilder::new()
            .with_setup_mode()
            .with_circuit(circuit);
        let cs = cs.synthesize()?;
        let (pk, vk, dk) = FS::generate_keys(pp, cs.into())?;

        let mut Ws = vec![];
        let mut Us = vec![];
        for _ in 0..M {
            let (W, U) = WitnessInstanceSampler::<FS::RW, FS::RU>::sample(&dk, (), &mut rng)?;
            FS::decide_running(&dk, &W, &U)?;
            Ws.push(W);
            Us.push(U);
        }
        let mut Ws = Ws.try_into().unwrap();
        let mut Us = Us.try_into().unwrap();

        let config = Arc::new(GriffinParams::new(16, 5, 9));

        let mut transcript_p = GriffinSponge::new(&config);
        let mut transcript_v = GriffinSponge::new(&config);

        for assignments in assignments_vec {
            let mut ws = vec![];
            let mut us = vec![];
            for _ in 0..N {
                let (w, u) = WitnessInstanceSampler::<FS::IW, FS::IU>::sample(
                    &dk,
                    assignments.clone(),
                    &mut rng,
                )?;
                FS::decide_incoming(&dk, &w, &u)?;
                ws.push(w);
                us.push(u);
            }
            let ws = ws.try_into().unwrap();
            let us = us.try_into().unwrap();

            let (WW, UU, pi, _) = FS::prove(&pk, &mut transcript_p, &Ws, &Us, &ws, &us, &mut rng)?;
            FS::decide_running(&dk, &WW, &UU)?;
            assert_eq!(FS::verify(&vk, &mut transcript_v, &Us, &us, &pi)?, UU);

            for i in 0..M {
                let (W, U) = WitnessInstanceSampler::<FS::RW, FS::RU>::sample(&dk, (), &mut rng)?;
                FS::decide_running(&dk, &W, &U)?;
                Ws[i] = W;
                Us[i] = U;
            }
            if M != 0 {
                let idx = rng.gen_range(0..M);
                Ws[idx] = WW;
                Us[idx] = UU;
            }
        }

        Ok(())
    }
}
