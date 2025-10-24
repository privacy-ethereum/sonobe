pub mod hypernova;
pub mod hypernova2;
pub mod nova;
pub mod nova2;
pub mod ova;
pub mod protogalaxy;
pub mod protogalaxy2;

use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;
use ark_std::{borrow::Borrow, fmt::Debug, rand::RngCore};
use thiserror::Error;

use sonobe_primitives::algebra::group::PointScalarMulGadget;
use sonobe_primitives::circuits::AssignmentsOwned;
use sonobe_primitives::commitments::VectorCommitmentGadget;
use sonobe_primitives::relations::WitnessInstanceSampler;
use sonobe_primitives::transcripts::TranscriptVar;
use sonobe_primitives::{
    arithmetizations::Arith,
    commitments::VectorCommitment,
    relations::{Referenceable, Relation},
    sumcheck::Error as SumCheckError,
    traits::SonobeField,
    transcripts::Transcript,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Arithmetization error: {0}")]
    ArithError(#[from] sonobe_primitives::arithmetizations::Error),
    #[error("Commitment error: {0}")]
    CommitmentError(#[from] sonobe_primitives::commitments::Error),
    #[error("Synthesis error: {0}")]
    SynthesisError(#[from] SynthesisError),
    #[error("Sumcheck error: {0}")]
    SumCheckError(#[from] SumCheckError),
    #[error("Unsupported use case: {0}")]
    Unsupported(String),
    #[error("Failed to create domain")]
    DomainCreationFailure,
}

pub trait FoldingWitness<VC: VectorCommitment>: Debug + Referenceable + Sync {
    /// Returns the reference to all openings contained in the witness, each
    /// being a tuple of the values being committed to and the randomness.
    fn openings_ref(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)>;
}

impl<VC: VectorCommitment> FoldingWitness<VC> for Vec<VC::Scalar> {
    fn openings_ref(&self) -> Vec<(&[VC::Scalar], &VC::Randomness)> {
        vec![]
    }
}

pub trait FoldingInstance<VC: VectorCommitment>: Debug + PartialEq + Referenceable + Sync {
    /// Returns the commitments contained in the committed instance.
    fn commitments(&self) -> Vec<&VC::Commitment>;
}

impl<VC: VectorCommitment> FoldingInstance<VC> for Vec<VC::Scalar> {
    fn commitments(&self) -> Vec<&VC::Commitment> {
        vec![]
    }
}

pub trait FoldingScheme<const M: usize = 1, const N: usize = 1> {
    type VC: VectorCommitment<Scalar: SonobeField>;
    type RW: FoldingWitness<Self::VC>;
    type RU: FoldingInstance<Self::VC>;
    type IW: FoldingWitness<Self::VC>;
    type IU: FoldingInstance<Self::VC>;
    type TranscriptField: SonobeField;
    type Arith: Arith;
    type Config;
    type PublicParam;
    type ProverKey;
    type VerifierKey;
    type DeciderKey: Relation<Self::RW, Self::RU, Error = Error>
        + Relation<Self::IW, Self::IU, Error = Error>
        + WitnessInstanceSampler<Self::RW, Self::RU, Source = (), Error = Error>
        + WitnessInstanceSampler<
            Self::IW,
            Self::IU,
            Source = AssignmentsOwned<<Self::VC as VectorCommitment>::Scalar>,
            Error = Error,
        >;
    type Challenge;
    type Proof;

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
    fn prove(
        pk: &Self::ProverKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        Ws: &[impl Borrow<Self::RW>; M],
        Us: &[impl Borrow<Self::RU>; M],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof, Self::Challenge), Error>;

    fn verify(
        vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof,
    ) -> Result<Self::RU, Error>;

    fn decide_running(dk: &Self::DeciderKey, W: &Self::RW, U: &Self::RU) -> Result<(), Error> {
        Relation::<Self::RW, Self::RU>::check_relation(dk, W.reference(), U.reference())
    }

    fn decide_incoming(dk: &Self::DeciderKey, w: &Self::IW, u: &Self::IU) -> Result<(), Error> {
        Relation::<Self::IW, Self::IU>::check_relation(dk, w.reference(), u.reference())
    }
}

pub trait FoldingWitnessVar<VC: VectorCommitmentGadget> {
    type Native: FoldingWitness<VC::Native>;
}

pub trait FoldingInstanceVar<VC: VectorCommitmentGadget> {
    type Native: FoldingInstance<VC::Native>;
}

impl<VC: VectorCommitmentGadget> FoldingWitnessVar<VC> for Vec<VC::ScalarVar> {
    type Native = Vec<<VC::Native as VectorCommitment>::Scalar>;
}

impl<VC: VectorCommitmentGadget> FoldingInstanceVar<VC> for Vec<VC::ScalarVar> {
    type Native = Vec<<VC::Native as VectorCommitment>::Scalar>;
}

pub trait FoldingSchemePartialGadget<const M: usize = 1, const N: usize = 1> {
    type Native: FoldingScheme<M, N>;

    type VC: VectorCommitmentGadget;
    type RW: FoldingWitnessVar<Self::VC, Native = <Self::Native as FoldingScheme<M, N>>::RW>;
    type RU: FoldingInstanceVar<Self::VC, Native = <Self::Native as FoldingScheme<M, N>>::RU>;
        // + AllocVar<<Self::Native as FoldingScheme<M, N>>::RU, Self::TranscriptField>;
    type IW: FoldingWitnessVar<Self::VC, Native = <Self::Native as FoldingScheme<M, N>>::IW>;
    type IU: FoldingInstanceVar<Self::VC, Native = <Self::Native as FoldingScheme<M, N>>::IU>;
        // + AllocVar<<Self::Native as FoldingScheme<M, N>>::RU, Self::TranscriptField>;

    type TranscriptField: SonobeField;

    type VerifierKey;

    type Challenge;

    type Proof;

    type Hint;

    fn verify_hinted(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<Self::TranscriptField>,
        Us: &[Self::RU; M],
        us: &[Self::IU; N],
        proof: &Self::Proof,
        hint: Self::Hint,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError>;
}

pub trait FoldingSchemeFullGadget<const M: usize = 1, const N: usize = 1>:
    FoldingSchemePartialGadget<M, N>
{
    fn verify(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptVar<Self::TranscriptField>,
        Us: &[Self::RU; M],
        us: &[Self::IU; N],
        proof: &Self::Proof,
    ) -> Result<Self::RU, SynthesisError>;
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use ark_relations::gr1cs::ConstraintSynthesizer;
    use ark_std::{error::Error, rand::Rng};
    use sonobe_primitives::{
        arithmetizations::r1cs::R1CS,
        circuits::{AssignmentsOwned, ConstraintSystemBuilder, ConstraintSystemExt},
        relations::WitnessInstanceSampler,
        transcripts::poseidon::poseidon_canonical_config,
    };

    use super::*;

    pub fn test_folding_scheme<FS, const M: usize, const N: usize>(
        config: FS::Config,
        circuit: impl ConstraintSynthesizer<<FS::VC as VectorCommitment>::Scalar>,
        assignments_vec: Vec<AssignmentsOwned<<FS::VC as VectorCommitment>::Scalar>>,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>>
    where
        FS: FoldingScheme<M, N>,
        FS::Arith: From<R1CS<<FS::VC as VectorCommitment>::Scalar>>,
    {
        let pp = FS::preprocess(config, &mut rng)?;

        let arith = ConstraintSystemBuilder::new()
            .with_setup_mode()
            .with_circuit(circuit)
            .synthesize()?
            .constraints()?;
        let (pk, vk, dk) = FS::generate_keys(pp, arith.into())?;

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

        let mut transcript_p = PoseidonSponge::new(&poseidon_canonical_config());
        let mut transcript_v = PoseidonSponge::new(&poseidon_canonical_config());

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
