pub mod algorithms;
pub mod instances;
pub mod keys;
pub mod utils;
pub mod witnesses;

use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::{fmt::Debug, marker::PhantomData, ops::Range, rand::RngCore};
use sonobe_primitives::{
    algebra::{
        field::SonobeField,
        ops::pow::Pow,
        ring::{PolynomialRingConfig, PolynomialRingOverField},
    },
    arithmetizations::{
        ArithConfig, ArithRelation,
        ccs::{self, CCS},
    },
    commitments::{CommitmentDef, CommitmentOps},
    traits::{Dummy, SonobePrimeField},
    utils::null::Null,
};

use self::{
    instances::{IncomingInstance as IU, RunningInstance as RU},
    witnesses::{IncomingWitness as IW, RunningWitness as RW},
};
use crate::{FoldingSchemeDef, superneo::keys::SuperNeoKey};

pub trait SuperNeoConfig: Clone + Debug + Eq + PartialEq {
    type P: PolynomialRingConfig;
    type K: SonobeField<BasePrimeField = Self::F>;
    type F: SonobePrimeField;
    type CM: CommitmentOps<
            Scalar = PolynomialRingOverField<Self::P, Self::F>,
            Commitment = Vec<PolynomialRingOverField<Self::P, Self::F>>,
            Randomness = Null,
        >;
    const KAPPA: usize;
    const M: usize;
    const B: usize;
    const CHALLENGE_COEFF_RANGE: Range<i8>;
}

#[derive(Clone)]
pub struct SuperNeoProof<Cfg: SuperNeoConfig, const N: usize> {
    sc_proof: Vec<Vec<Cfg::K>>,
    y_prime: Vec<Vec<PolynomialRingOverField<Cfg::P, Cfg::K>>>,
    y: Vec<Vec<PolynomialRingOverField<Cfg::P, Cfg::K>>>,
    c_prime: Vec<Vec<PolynomialRingOverField<Cfg::P, Cfg::F>>>,
}

impl<Cfg: SuperNeoConfig, const N: usize> Dummy<&ArithConfig> for SuperNeoProof<Cfg, N> {
    fn dummy(cfg: &ArithConfig) -> Self {
        let s = cfg.log_constraints();
        Self {
            sc_proof: vec![vec![Zero::zero(); cfg.degree.max(Cfg::B * 2 - 1) + 1 + 2]; s],
            y_prime: vec![vec![Default::default(); cfg.n_matrices]; Cfg::M + N],
            y: vec![vec![Default::default(); cfg.n_matrices]; Cfg::M],
            c_prime: vec![vec![Default::default(); Cfg::KAPPA]; Cfg::M],
        }
    }
}

pub struct SuperNeo<Cfg, A> {
    _t: PhantomData<(Cfg, A)>,
}

impl<Cfg: SuperNeoConfig, A: CCS<Field = Cfg::F> + ArithRelation<Vec<Cfg::F>, Vec<Cfg::F>>>
    FoldingSchemeDef for SuperNeo<Cfg, A>
{
    type CM = Cfg::CM;
    type RW = RW<Cfg>;
    type RU = RU<Cfg>;
    type IW = IW<Cfg::F>;
    type IU = IU<<Cfg::CM as CommitmentDef>::Commitment, Cfg::F>;

    type TranscriptField = Cfg::F;
    type Arith = A;

    type Config = usize;
    type PublicParam = <Cfg::CM as CommitmentDef>::Key;
    type DeciderKey = SuperNeoKey<Self::Arith, Cfg>;
    type Challenge = Vec<PolynomialRingOverField<Cfg::P, Cfg::F>>;
    type Proof<const M: usize, const N: usize> = SuperNeoProof<Cfg, N>;
}

#[cfg(test)]
mod tests {
    use ark_ff::{FftField, Fp2, Fp2Config, MontFp, SmallFp, SmallFpConfig, UniformRand};
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::gr1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Matrix, R1CS_PREDICATE_LABEL,
        SynthesisError,
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{
        cfg_into_iter,
        error::Error,
        rand::{RngCore, thread_rng},
    };
    use sonobe_primitives::{
        algebra::ring::Config1,
        arithmetizations::{Arith, Error as ArithError, r1cs::R1CS},
        circuits::{ArithExtractor, Assignments},
        commitments::{ajtai::Ajtai, pedersen::Pedersen},
        relations::Relation,
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::tests::test_folding_scheme;

    #[derive(SmallFpConfig)]
    #[modulus = "18446744069414584321"] // Goldilocks, 2^64 - 2^32 + 1
    #[generator = "7"]
    pub struct GoldilocksConfig;

    pub type Goldilocks = SmallFp<GoldilocksConfig>;

    // F_{q^2} = F_q[X] / (X^2 - 7)
    pub struct GoldilocksFp2Config;
    impl Fp2Config for GoldilocksFp2Config {
        type Fp = Goldilocks;

        // MontFp! can't build a SmallFp and `new` isn't const — but the
        // multiplicative generator is always a non-residue, and you set it to 7:
        const NONRESIDUE: Goldilocks = <Goldilocks as FftField>::GENERATOR; // = 7

        // a^p = c0 - c1*X  ->  coeffs [1, -1], both available as consts:
        const FROBENIUS_COEFF_FP2_C1: &[Goldilocks] =
            &[<Goldilocks as Field>::ONE, <Goldilocks as Field>::NEG_ONE];
    }
    pub type GoldilocksFp2 = Fp2<GoldilocksFp2Config>;
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Cfg {}
    impl SuperNeoConfig for Cfg {
        type P = Config1;

        type K = GoldilocksFp2;

        type F = Goldilocks;

        type CM = Ajtai<Config1, Goldilocks, 18>;

        const KAPPA: usize = 18;

        const M: usize = 14;

        const B: usize = 2;

        const CHALLENGE_COEFF_RANGE: Range<i8> = -2..3;
    }

    pub struct CircuitForTest<F: PrimeField> {
        /// [`CircuitForTest::x`] is the input variable `x` of the circuit.
        pub x: F,
        pub n_witness: usize,
        pub n_public: usize,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for CircuitForTest<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let witnesses = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
                Ok(vec![self.x * F::from(self.n_public as u64); self.n_witness])
            })?;
            let public_input = Vec::<FpVar<F>>::new_input(cs.clone(), || {
                Ok(vec![self.x * F::from(self.n_witness as u64); self.n_public])
            })?;

            for _ in 0..self.n_witness + self.n_public + 1 {
                witnesses
                    .iter()
                    .sum::<FpVar<F>>()
                    .enforce_equal(&public_input.iter().sum::<FpVar<F>>())?;
            }
            Ok(())
        }
    }

    /// [`satisfying_assignments_for_test`] returns a satisfying assignment for the
    /// test circuit given an input `x`.
    pub fn satisfying_assignments_for_test<F: Field>(
        x: F,
        n_witness: usize,
        n_public: usize,
    ) -> Assignments<F, Vec<F>> {
        Assignments::from((
            F::one(),
            vec![x * F::from(n_witness as u64); n_public],
            vec![x * F::from(n_public as u64); n_witness],
        ))
    }

    #[test]
    fn test_circuit() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let n_witness = 54 * 10;
        let n_public = 54 * 1 - 1;

        let mut cs = ArithExtractor::new();
        cs.execute_synthesizer(CircuitForTest {
            x: UniformRand::rand(&mut rng),
            n_witness,
            n_public,
        })?;
        println!("{} {}", cs.num_constraints(), cs.num_variables());
        let r1cs: R1CS<_> = cs.arith()?;

        let assignments =
            satisfying_assignments_for_test(Goldilocks::rand(&mut rng), n_witness, n_public);

        assert!(
            r1cs.check_relation(&assignments.private, &assignments.public)
                .is_ok()
        );
        Ok(())
    }

    fn test_superneo_opt(rounds: usize, mut rng: impl RngCore) -> Result<(), Box<dyn Error>> {
        let n_witness: usize = 54 * 10;
        let n_public = 54 * 1 - 1;

        test_folding_scheme::<SuperNeo<Cfg, R1CS<Goldilocks>>, 1, 1>(
            n_witness.next_power_of_two(),
            CircuitForTest {
                x: UniformRand::rand(&mut rng),
                n_witness,
                n_public,
            },
            (0..rounds)
                .map(|_| {
                    satisfying_assignments_for_test(
                        UniformRand::rand(&mut rng),
                        n_witness,
                        n_public,
                    )
                })
                .collect(),
            &mut rng,
        )?;
        Ok(())
    }

    #[test]
    fn test_superneo() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_superneo_opt(10, &mut rng)?;
        Ok(())
    }
}
