pub mod hypernova;
pub mod hypernova2;
pub mod nova;
pub mod nova2;
pub mod ova;
pub mod protogalaxy;
pub mod protogalaxy2;

use ark_relations::gr1cs::SynthesisError;
use ark_std::{fmt::Debug, rand::RngCore};
use thiserror::Error;

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

// pub trait WitnessOps<F: PrimeField>: PartialEq + Clone + Debug {
//     /// The in-circuit representation of the witness.
//     type Var: AllocVar<Self, F> + WitnessVarOps<F>;

//     /// Returns the openings (i.e., the values being committed to and the
//     /// randomness) contained in the witness.
//     fn get_openings(&self) -> Vec<(&[F], F)>;
// }

// pub trait WitnessVarOps<F: PrimeField> {
//     /// Returns the openings (i.e., the values being committed to and the
//     /// randomness) contained in the witness.
//     fn get_openings(&self) -> Vec<(&[FpVar<F>], FpVar<F>)>;
// }

// pub trait CommittedInstanceOps<F: PrimeField>: Inputize<F> + PartialEq + Clone + Debug {
//     type C: Curve;

//     /// The in-circuit representation of the committed instance.
//     type Var: AllocVar<Self, F> + CommittedInstanceVarOps<F>;
//     /// `hash` implements the committed instance hash compatible with the
//     /// in-circuit implementation from `CommittedInstanceVarOps::hash`.
//     ///
//     /// Returns `H(i, z_0, z_i, U_i)`, where `i` can be `i` but also `i+1`, and
//     /// `U_i` is the committed instance `self`.
//     fn hash<T: Transcript<F>>(&self, sponge: &T, i: F, z_0: &[F], z_i: &[F]) -> F
//     where
//         Self: Sized + Absorb,
//         F: Absorb,
//     {
//         let mut sponge = sponge.clone();
//         sponge.absorb(&i);
//         sponge.absorb(&z_0);
//         sponge.absorb(&z_i);
//         sponge.absorb(&self);
//         sponge.squeeze_field_elements(1)[0]
//     }

//     /// Returns the commitments contained in the committed instance.
//     fn get_commitments(&self) -> Vec<Self::C>;

//     /// Returns `true` if the committed instance is an incoming instance, and
//     /// `false` if it is a running instance.
//     fn is_incoming(&self) -> bool;

//     /// Checks if the committed instance is an incoming instance.
//     fn check_incoming(&self) -> Result<(), Error> {
//         self.is_incoming()
//             .then_some(())
//             .ok_or(Error::NotIncomingCommittedInstance)
//     }
// }

// pub trait CommittedInstanceVarOps<F: PrimeField> {
//     type PointVar;
//     /// `hash` implements the in-circuit committed instance hash compatible with
//     /// the native implementation from `CommittedInstanceOps::hash`.
//     /// Returns `H(i, z_0, z_i, U_i)`, where `i` can be `i` but also `i+1`, and
//     /// `U_i` is the committed instance `self`.
//     ///
//     /// Additionally it returns the in-circuit representation of the committed
//     /// instance `self` as a vector of field elements, so they can be reused in
//     /// other gadgets avoiding recalculating (reconstraining) them.
//     #[allow(clippy::type_complexity)]
//     fn hash<T: Transcript<F>>(
//         &self,
//         sponge: &impl TranscriptVar<F, T>,
//         i: &FpVar<F>,
//         z_0: &[FpVar<F>],
//         z_i: &[FpVar<F>],
//     ) -> Result<(FpVar<F>, Vec<FpVar<F>>), SynthesisError>
//     where
//         Self: AbsorbGadget<F>,
//     {
//         let mut sponge = sponge.clone();
//         let vec = self.to_sponge_field_elements()?;
//         sponge.absorb(&i)?;
//         sponge.absorb(&z_0)?;
//         sponge.absorb(&z_i)?;
//         sponge.absorb(&vec)?;
//         Ok((
//             // `unwrap` is safe because the sponge is guaranteed to return a single element
//             sponge.squeeze_field_elements(1)?.pop().unwrap(),
//             vec,
//         ))
//     }

//     /// Returns the commitments contained in the committed instance.
//     fn get_commitments(&self) -> Vec<Self::PointVar>;

//     /// Returns the public inputs contained in the committed instance.
//     fn get_public_inputs(&self) -> &[FpVar<F>];

//     /// Generates constraints to enforce that the committed instance is an
//     /// incoming instance.
//     fn enforce_incoming(&self) -> Result<(), SynthesisError>;

//     /// Generates constraints to enforce that the committed instance `self` is
//     /// partially equal to another committed instance `other`.
//     /// Here, only field elements are compared, while commitments (points) are
//     /// not.
//     fn enforce_partial_equal(&self, other: &Self) -> Result<(), SynthesisError>;
// }

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
        + Relation<Self::IW, Self::IU, Error = Error>;
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
        Ws: &[Self::RW; M],
        Us: &[Self::RU; M],
        ws: &[Self::IW; N],
        us: &[Self::IU; N],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof), Error>;

    fn verify(
        vk: &Self::VerifierKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        Us: &[Self::RU; M],
        us: &[Self::IU; N],
        proof: &Self::Proof,
    ) -> Result<Self::RU, Error>;

    fn decide_running(dk: &Self::DeciderKey, W: &Self::RW, U: &Self::RU) -> Result<(), Error> {
        Relation::<Self::RW, Self::RU>::check_relation(dk, W.reference(), U.reference())
    }

    fn decide_incoming(dk: &Self::DeciderKey, w: &Self::IW, u: &Self::IU) -> Result<(), Error> {
        Relation::<Self::IW, Self::IU>::check_relation(dk, w.reference(), u.reference())
    }
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
        FS: FoldingScheme<
            M,
            N,
            Arith: From<R1CS<<<FS as FoldingScheme<M, N>>::VC as VectorCommitment>::Scalar>>,
            DeciderKey: WitnessInstanceSampler<
                FS::IW,
                FS::IU,
                Source = AssignmentsOwned<<FS::VC as VectorCommitment>::Scalar>,
            > + WitnessInstanceSampler<FS::RW, FS::RU, Source = ()>,
        >,
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

            let (WW, UU, pi) = FS::prove(&pk, &mut transcript_p, &Ws, &Us, &ws, &us, &mut rng)?;
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
