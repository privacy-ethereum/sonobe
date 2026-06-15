use ark_ec::{
    AffineRepr, CurveGroup, VariableBaseMSM,
    pairing::{Pairing, PairingOutput},
    scalar_mul::BatchMulPreprocessing,
};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_groth16::{
    Proof as Groth16Proof,
    r1cs_to_qap::{LibsnarkReduction, R1CSToQAP},
};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{
    borrow::Borrow, cfg_into_iter, cfg_iter, cfg_iter_mut, end_timer, hash::BuildHasherDefault,
    marker::PhantomData, rand::RngCore, start_timer,
};
use hashbrown::HashSet;
#[cfg(not(feature = "parallel"))]
use itertools::{Either, Itertools};
#[cfg(feature = "parallel")]
use rayon::{iter::Either, prelude::*};
use sonobe_primitives::{
    arithmetizations::{Arith, ccs::CCS, r1cs::R1CS},
    circuits::alloc::{IdentityHasher, UsizeSet},
    commitments::pedersen::PedersenKey,
    traits::{SonobeCurve, SonobePrimeField},
};
use thiserror::Error;

use crate::{
    cp::CPSNARK,
    linear_subspace::{
        LinearSubspaceSNARK, ProverKey as LinearSubspacePK, VerifierKey as LinearSubspaceVK,
    },
};

pub struct CCGroth16ProverKey<E: Pairing> {
    /// The element `beta * G` in `E::G1`.
    pub alpha_g1: E::G1Affine,
    pub beta_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: E::G1Affine,
    pub delta_g2: E::G2Affine,
    /// The element `eta*delta^-1 * G` in `E::G1`.
    pub eta_delta_inv_g1: E::G1Affine,
    /// The element `eta*gamma^-1 * G` in `E::G1`.
    pub eta_gamma_inv_g1: E::G1Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: Vec<E::G1Affine>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: Vec<E::G1Affine>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: Vec<E::G2Affine>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: Vec<E::G1Affine>,
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: Vec<E::G1Affine>,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is
    /// the generator of `E::G1`.
    pub gamma_abc_g1_cm: Vec<E::G1Affine>,
}

pub struct CCGroth16VerifierKey<E: Pairing> {
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: PairingOutput<E>,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: E::G2Prepared,
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: E::G2Prepared,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is
    /// the generator of `E::G1`.
    pub gamma_abc_g1_pub: Vec<E::G1Affine>,
}

pub struct ProverKey<E: Pairing> {
    pub r1cs: R1CS<E::ScalarField>,
    pub committed_variable_indices: HashSet<usize, BuildHasherDefault<IdentityHasher>>,
    pub cc_pk: CCGroth16ProverKey<E>,
    pub link_ek: LinearSubspacePK<E>,
}

pub struct VerifierKey<E: Pairing> {
    pub cc_vk: CCGroth16VerifierKey<E>,
    pub link_vk: LinearSubspaceVK<E>,
}

pub struct Proof<E: Pairing> {
    pub groth16_proof: Groth16Proof<E>,
    /// The `D` element in `G1`. Commits to a subset of private inputs of the
    /// circuit
    pub d: E::G1Affine,
    /// proof of commitment opening equality between `cp_{link}` and `d`
    pub link_pi: E::G1Affine,
}

/// [`Error`] enumerates possible errors during LegoGroth16 operations.
#[derive(Debug, Error)]
pub enum Error {
    /// [`Error::SynthesisError`] indicates an error during constraint
    /// synthesis.
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    /// [`Error::VerificationFail`] indicates that the verification has
    /// failed.
    #[error("Verification failed")]
    VerificationFail,
}

pub struct LegoGroth16<
    E: Pairing<G1: SonobeCurve, BaseField: SonobePrimeField, ScalarField: SonobePrimeField>,
    QAP: R1CSToQAP = LibsnarkReduction,
> {
    _p: PhantomData<(E, QAP)>,
}

impl<E: Pairing<G1: SonobeCurve, BaseField: SonobePrimeField, ScalarField: SonobePrimeField>, QAP: R1CSToQAP>
    CPSNARK for LegoGroth16<E, QAP>
{
    type Field = E::ScalarField;

    type Relation = (R1CS<E::ScalarField>, UsizeSet);

    type Commitment = E::G1Affine;
    type CommitmentKey = PedersenKey<E::G1, true>;
    type CommitmentOpening = E::ScalarField;

    type ProverKey = ProverKey<E>;
    type VerifierKey = VerifierKey<E>;
    type Error = SynthesisError;
    type Proof = Proof<E>;

    fn generate_keys(
        (r1cs, committed_variable_indices): Self::Relation,
        commitment_key: &[impl Borrow<Self::CommitmentKey> + Sync],
        mut rng: impl RngCore,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), Self::Error> {
        let alpha = E::ScalarField::rand(&mut rng);
        let beta = E::ScalarField::rand(&mut rng);
        let gamma = E::ScalarField::rand(&mut rng);
        let delta = E::ScalarField::rand(&mut rng);
        let eta = E::ScalarField::rand(&mut rng);

        let gamma_inverse = gamma.inverse().ok_or(SynthesisError::DivisionByZero)?;
        let delta_inverse = delta.inverse().ok_or(SynthesisError::DivisionByZero)?;

        let g1_generator = E::G1::rand(&mut rng);
        let g2_generator = E::G2::rand(&mut rng);

        let setup_time = start_timer!(|| "Groth16::Generator");

        let r1cs_config = r1cs.config();
        let n_instance_variables = r1cs_config.n_public_inputs + 1;
        let n_constraints = r1cs_config.n_constraints;
        let n_variables = r1cs_config.n_variables;
        let matrices = r1cs.matrices();

        let n_committed_variables = committed_variable_indices.len();

        // Following is the mapping of symbols from the Groth16 paper to this
        // implementation l -> num_instance_variables
        // m -> qap_num_variables
        // x -> t
        // t(x) - zt
        // u_i(x) -> a
        // v_i(x) -> b
        // w_i(x) -> c

        ///////////////////////////////////////////////////////////////////////////
        let domain_time = start_timer!(|| "Constructing evaluation domain");

        let domain = GeneralEvaluationDomain::new(n_constraints + n_instance_variables)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let t = domain.sample_element_outside_domain(&mut rng);
        let zt_over_delta = domain.evaluate_vanishing_polynomial(t) * delta_inverse;

        end_timer!(domain_time);
        ///////////////////////////////////////////////////////////////////////////

        let reduction_time = start_timer!(|| "R1CS to QAP Instance Map with Evaluation");

        // Evaluate all Lagrange polynomials
        let coefficients_time = start_timer!(|| "Evaluate Lagrange coefficients");
        let u = domain.evaluate_all_lagrange_coefficients(t);
        end_timer!(coefficients_time);

        let mut a = vec![E::ScalarField::zero(); n_variables];
        let mut b = vec![E::ScalarField::zero(); n_variables];
        let mut c = vec![E::ScalarField::zero(); n_variables];

        a[0..n_instance_variables]
            .copy_from_slice(&u[n_constraints..(n_instance_variables + n_constraints)]);

        for (i, u_i) in u.into_iter().enumerate().take(n_constraints) {
            for &(ref coeff, index) in &matrices[0][i] {
                a[index] += &(u_i * coeff);
            }
            for &(ref coeff, index) in &matrices[1][i] {
                b[index] += &(u_i * coeff);
            }
            for &(ref coeff, index) in &matrices[2][i] {
                c[index] += &(u_i * coeff);
            }
        }

        end_timer!(reduction_time);

        // Compute query densities
        let non_zero_a = cfg_into_iter!(0..n_variables)
            .map(|i| usize::from(!a[i].is_zero()))
            .sum::<usize>();

        let non_zero_b = cfg_into_iter!(0..n_variables)
            .map(|i| usize::from(!b[i].is_zero()))
            .sum::<usize>();

        let (gamma_abc, l): (Vec<_>, Vec<_>) = cfg_iter!(a)
            .zip(&b)
            .zip(&c)
            .enumerate()
            .partition_map(|(i, ((a, b), c))| {
                if i < n_instance_variables
                    || committed_variable_indices.contains(&(i - n_instance_variables))
                {
                    Either::Left((beta * a + alpha * b + c) * gamma_inverse)
                } else {
                    Either::Right((beta * a + alpha * b + c) * delta_inverse)
                }
            });

        drop(c);

        // Compute B window table
        let g2_time = start_timer!(|| "Compute G2 table");
        let g2_table = BatchMulPreprocessing::new(g2_generator, non_zero_b);
        end_timer!(g2_time);

        // Compute the B-query in G2
        let b_g2_time = start_timer!(|| format!("Calculate B G2 of size {}", b.len()));
        let b_g2_query = g2_table.batch_mul(&b);
        drop(g2_table);
        end_timer!(b_g2_time);

        // Compute G window table
        let g1_window_time = start_timer!(|| "Compute G1 window table");
        let num_scalars = non_zero_a + non_zero_b + n_variables + domain_size - 1;
        let g1_table = BatchMulPreprocessing::new(g1_generator, num_scalars);
        end_timer!(g1_window_time);

        // Generate the R1CS proving key
        let proving_key_time = start_timer!(|| "Generate the R1CS proving key");

        // Compute the A-query
        let a_time = start_timer!(|| "Calculate A");
        let a_query = g1_table.batch_mul(&a);
        drop(a);
        end_timer!(a_time);

        // Compute the B-query in G1
        let b_g1_time = start_timer!(|| "Calculate B G1");
        let b_g1_query = g1_table.batch_mul(&b);
        drop(b);
        end_timer!(b_g1_time);

        // Compute the H-query
        let h_time = start_timer!(|| "Calculate H");
        let h_scalars = cfg_into_iter!(0..domain_size - 1)
            .map(|i| zt_over_delta * t.pow([i as u64]))
            .collect::<Vec<_>>();
        let h_query = g1_table.batch_mul(&h_scalars);
        end_timer!(h_time);

        // Compute the L-query
        let l_time = start_timer!(|| "Calculate L");
        let l_query = g1_table.batch_mul(&l);
        drop(l);
        end_timer!(l_time);

        end_timer!(proving_key_time);

        // Generate R1CS verification key
        let verifying_key_time = start_timer!(|| "Generate the R1CS verification key");
        let mut gamma_abc_g1 = g1_table.batch_mul(&gamma_abc);
        let gamma_abc_g1_part_2 = gamma_abc_g1.split_off(n_instance_variables);
        drop(g1_table);

        end_timer!(verifying_key_time);

        let eta_gamma_inv_g1 = (g1_generator * (eta * gamma_inverse)).into_affine();

        let eta_delta_inv_g1 = (g1_generator * (eta * delta_inverse)).into_affine();

        // Setup public params for the Subspace Snark
        let (link_ek, link_vk) = LinearSubspaceSNARK::generate_keys(
            commitment_key.len() + 1,
            |k| {
                let mut p = cfg_iter!(commitment_key)
                    .zip(&k)
                    .flat_map(|(ck, u)| cfg_iter!(ck.borrow().g).map(move |i| *i * u))
                    .chain(
                        cfg_iter!(commitment_key)
                            .zip(&k)
                            .map(|(ck, u)| ck.borrow().h * u),
                    )
                    .collect::<Vec<_>>();
                assert_eq!(p.len(), n_committed_variables + commitment_key.len());

                cfg_iter_mut!(p)
                    .zip(&gamma_abc_g1_part_2)
                    .for_each(|(v, i)| {
                        *v += *i * k[commitment_key.len()];
                    });
                p.push(eta_gamma_inv_g1 * k[commitment_key.len()]);

                p
            },
            &mut rng,
        );

        end_timer!(setup_time);

        let alpha_g1 = (g1_generator * alpha).into_affine();
        let beta_g1 = (g1_generator * beta).into_affine();
        let beta_g2 = (g2_generator * beta).into_affine();
        let delta_g1 = (g1_generator * delta).into_affine();
        let delta_g2 = (g2_generator * delta).into_affine();

        Ok((
            ProverKey {
                r1cs,
                committed_variable_indices,
                cc_pk: CCGroth16ProverKey {
                    alpha_g1,
                    beta_g1,
                    beta_g2,
                    delta_g1,
                    delta_g2,
                    eta_delta_inv_g1,
                    eta_gamma_inv_g1,
                    a_query,
                    b_g1_query,
                    b_g2_query,
                    h_query,
                    l_query,
                    gamma_abc_g1_cm: gamma_abc_g1_part_2,
                },
                link_ek,
            },
            VerifierKey {
                cc_vk: CCGroth16VerifierKey {
                    alpha_g1_beta_g2: E::pairing(alpha_g1, beta_g2),
                    gamma_g2_neg_pc: (g2_generator * -gamma).into_affine().into(),
                    delta_g2_neg_pc: (-delta_g2).into(),
                    gamma_abc_g1_pub: gamma_abc_g1,
                },
                link_vk,
            },
        ))
    }

    fn prove(
        pk: &Self::ProverKey,
        x: &[Self::Field],
        w: &[Self::Field],
        o: &[Self::CommitmentOpening],
        mut rng: impl RngCore,
    ) -> Result<Self::Proof, Self::Error> {
        let r = E::ScalarField::rand(&mut rng);
        let s = E::ScalarField::rand(&mut rng);
        let v = E::ScalarField::rand(&mut rng);

        let r1cs_config = pk.r1cs.config();
        let num_inputs = r1cs_config.n_public_inputs + 1;
        let num_constraints = r1cs_config.n_constraints;

        let prover_time = start_timer!(|| "Groth16::Prover");

        let assignment = [&[E::ScalarField::one()][..], x, w].concat();

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map_from_matrices::<_, GeneralEvaluationDomain<_>>(
            pk.r1cs.matrices(),
            num_inputs,
            num_constraints,
            &assignment,
        )?;

        end_timer!(witness_map_time);

        let assignment_bigint = cfg_into_iter!(assignment)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();

        // Compute A
        let a_acc_time = start_timer!(|| "Compute A");
        let g_a = pk.cc_pk.delta_g1 * r
            + E::G1::msm_bigint(&pk.cc_pk.a_query, &assignment_bigint)
            + pk.cc_pk.alpha_g1;
        end_timer!(a_acc_time);

        // Compute B in G1 if needed
        let b_g1_acc_time = start_timer!(|| "Compute B in G1");
        let g1_b = if !r.is_zero() {
            pk.cc_pk.delta_g1 * s
                + E::G1::msm_bigint(&pk.cc_pk.b_g1_query, &assignment_bigint)
                + pk.cc_pk.beta_g1
        } else {
            E::G1::zero()
        };
        end_timer!(b_g1_acc_time);

        // Compute B in G2
        let b_g2_acc_time = start_timer!(|| "Compute B in G2");
        let g2_b = pk.cc_pk.delta_g2 * s
            + E::G2::msm_bigint(&pk.cc_pk.b_g2_query, &assignment_bigint)
            + pk.cc_pk.beta_g2;

        end_timer!(b_g2_acc_time);

        // Compute C
        let c_time = start_timer!(|| "Compute C");
        let mut g_c = g_a * s;
        g_c += g1_b * r;
        g_c -= pk.cc_pk.delta_g1 * (r * s);

        let (witness_bigint, committed_bigint) = cfg_into_iter!(assignment_bigint)
            .skip(num_inputs)
            .enumerate()
            .partition_map::<Vec<_>, Vec<_>, _, _, _>(|(i, v)| {
                if pk.committed_variable_indices.contains(&i) {
                    Either::Right(v)
                } else {
                    Either::Left(v)
                }
            });
        g_c += E::G1::msm_bigint(&pk.cc_pk.l_query, &witness_bigint);
        drop(witness_bigint);

        let h_bigint = cfg_into_iter!(h)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        g_c += E::G1::msm_bigint(&pk.cc_pk.h_query, &h_bigint);
        drop(h_bigint);

        g_c -= pk.cc_pk.eta_delta_inv_g1 * v;
        end_timer!(c_time);

        // Compute D
        let d_acc_time = start_timer!(|| "Compute D");
        let g_d = E::G1::msm_bigint(&pk.cc_pk.gamma_abc_g1_cm, &committed_bigint)
            + pk.cc_pk.eta_gamma_inv_g1 * v;
        end_timer!(d_acc_time);

        let link_time = start_timer!(|| "Compute CP_{link}");
        let mut ss_snark_witness = committed_bigint;
        ss_snark_witness.extend(o.iter().chain([&v]).map(|i| i.into_bigint()));
        let link_pi = LinearSubspaceSNARK::prove(&pk.link_ek, &ss_snark_witness);
        end_timer!(link_time);

        end_timer!(prover_time);

        Ok(Proof {
            groth16_proof: Groth16Proof {
                a: g_a.into_affine(),
                b: g2_b.into_affine(),
                c: g_c.into_affine(),
            },

            d: g_d.into_affine(),

            link_pi,
        })
    }

    fn verify(
        vk: &Self::VerifierKey,
        x: &[Self::Field],
        c: &[Self::Commitment],
        proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        let mut g_ic = vk.cc_vk.gamma_abc_g1_pub[0].into_group();
        for (i, b) in x.iter().zip(vk.cc_vk.gamma_abc_g1_pub.iter().skip(1)) {
            g_ic += *b * i;
        }

        if E::multi_pairing(
            [
                E::G1Prepared::from(proof.groth16_proof.a),
                (proof.d + g_ic).into_affine().into(),
                proof.groth16_proof.c.into(),
            ],
            [
                proof.groth16_proof.b.into(),
                vk.cc_vk.gamma_g2_neg_pc.clone(),
                vk.cc_vk.delta_g2_neg_pc.clone(),
            ],
        ) != vk.cc_vk.alpha_g1_beta_g2
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        if !LinearSubspaceSNARK::verify(&vk.link_vk, &[c, &[proof.d][..]].concat(), &proof.link_pi)
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef},
        lc,
    };
    use ark_std::rand::thread_rng;
    use sonobe_primitives::circuits::{ArithExtractor, AssignmentsExtractor};

    use super::*;

    struct MySillyCircuit<F: Field> {
        a: F,
        b: F,
        c: F,
        d: F,
        e: F,
        f: F,
    }

    impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ConstraintF>,
        ) -> Result<(), SynthesisError> {
            let d = cs.new_witness_variable(|| Ok(self.d))?;
            let a = cs.new_witness_variable(|| Ok(self.a))?;
            let b = cs.new_witness_variable(|| Ok(self.b))?;
            let e = cs.new_witness_variable(|| Ok(self.e))?;
            let c = cs.new_witness_variable(|| Ok(self.c))?;
            let g = cs.new_input_variable(|| {
                Ok((self.a + self.b + self.c) * (self.d + self.e + self.f))
            })?;
            let f = cs.new_witness_variable(|| Ok(self.f))?;

            cs.enforce_r1cs_constraint(|| lc![a, b, c], || lc![d, e, f], || lc![g])?;

            Ok(())
        }
    }

    fn test_prove_and_verify<
        E: Pairing<G1: SonobeCurve, BaseField: SonobePrimeField, ScalarField: SonobePrimeField>,
    >(
        n_iters: usize,
    ) {
        let mut rng = thread_rng();

        let g = vec![E::G1Affine::rand(&mut rng)];
        let h = E::G1Affine::rand(&mut rng);
        let generators = [&g[..], &[h]].concat();
        let ck = PedersenKey { g, h };

        let mut cs = ArithExtractor::new();
        cs.execute_synthesizer(MySillyCircuit {
            a: Default::default(),
            b: Default::default(),
            c: Default::default(),
            d: Default::default(),
            e: Default::default(),
            f: Default::default(),
        })
        .unwrap();

        let (pk, vk) = LegoGroth16::<E>::generate_keys(
            (cs.arith().unwrap(), UsizeSet::from_iter(vec![0, 3, 5])),
            &[&ck, &ck, &ck],
            &mut rng,
        )
        .unwrap();

        for _ in 0..n_iters {
            let a = E::ScalarField::rand(&mut rng);
            let b = E::ScalarField::rand(&mut rng);
            let c = E::ScalarField::rand(&mut rng);
            let d = E::ScalarField::rand(&mut rng);
            let e = E::ScalarField::rand(&mut rng);
            let f = E::ScalarField::rand(&mut rng);

            let mut cs = AssignmentsExtractor::new();
            cs.execute_synthesizer(MySillyCircuit { a, b, c, d, e, f })
                .unwrap();
            let assignments = cs.assignments().unwrap();

            let o = [
                E::ScalarField::rand(&mut rng),
                E::ScalarField::rand(&mut rng),
                E::ScalarField::rand(&mut rng),
            ];

            let cm = vec![
                E::G1::msm_unchecked(&generators, &[d, o[0]]).into_affine(),
                E::G1::msm_unchecked(&generators, &[e, o[1]]).into_affine(),
                E::G1::msm_unchecked(&generators, &[f, o[2]]).into_affine(),
            ];

            let proof = LegoGroth16::<E>::prove(
                &pk,
                &assignments.public,
                &assignments.private,
                &o,
                &mut rng,
            )
            .unwrap();

            assert!(
                LegoGroth16::<E>::verify(&vk, &[(a + b + c) * (d + e + f)], &cm, &proof).is_ok()
            );
            assert!(LegoGroth16::<E>::verify(&vk, &[a], &cm, &proof).is_err());
        }
    }

    fn test_prove_and_verify2<
        E: Pairing<G1: SonobeCurve, BaseField: SonobePrimeField, ScalarField: SonobePrimeField>,
    >(
        n_iters: usize,
    ) {
        let mut rng = thread_rng();

        let g = vec![E::G1Affine::rand(&mut rng), E::G1Affine::rand(&mut rng)];
        let h = E::G1Affine::rand(&mut rng);
        let generators1 = [&g[..], &[h]].concat();
        let ck1 = PedersenKey { g, h };

        let g = vec![E::G1Affine::rand(&mut rng)];
        let h = E::G1Affine::rand(&mut rng);
        let generators2 = [&g[..], &[h]].concat();
        let ck2 = PedersenKey { g, h };

        let mut cs = ArithExtractor::new();
        cs.execute_synthesizer(MySillyCircuit {
            a: Default::default(),
            b: Default::default(),
            c: Default::default(),
            d: Default::default(),
            e: Default::default(),
            f: Default::default(),
        })
        .unwrap();

        let (pk, vk) = LegoGroth16::<E>::generate_keys(
            (cs.arith().unwrap(), UsizeSet::from_iter(vec![0, 3, 5])),
            &[&ck1, &ck2],
            &mut rng,
        )
        .unwrap();

        for _ in 0..n_iters {
            let a = E::ScalarField::rand(&mut rng);
            let b = E::ScalarField::rand(&mut rng);
            let c = E::ScalarField::rand(&mut rng);
            let d = E::ScalarField::rand(&mut rng);
            let e = E::ScalarField::rand(&mut rng);
            let f = E::ScalarField::rand(&mut rng);

            let mut cs = AssignmentsExtractor::new();
            cs.execute_synthesizer(MySillyCircuit { a, b, c, d, e, f })
                .unwrap();
            let assignments = cs.assignments().unwrap();

            let o = [
                E::ScalarField::rand(&mut rng),
                E::ScalarField::rand(&mut rng),
            ];

            let cm = vec![
                E::G1::msm_unchecked(&generators1, &[d, e, o[0]]).into_affine(),
                E::G1::msm_unchecked(&generators2, &[f, o[1]]).into_affine(),
            ];

            let proof = LegoGroth16::<E>::prove(
                &pk,
                &assignments.public,
                &assignments.private,
                &o,
                &mut rng,
            )
            .unwrap();

            assert!(
                LegoGroth16::<E>::verify(&vk, &[(a + b + c) * (d + e + f)], &cm, &proof).is_ok()
            );
            assert!(LegoGroth16::<E>::verify(&vk, &[a], &cm, &proof).is_err());
        }
    }

    fn test_prove_and_verify3<
        E: Pairing<G1: SonobeCurve, BaseField: SonobePrimeField, ScalarField: SonobePrimeField>,
    >(
        n_iters: usize,
    ) {
        let mut rng = thread_rng();

        let g = vec![
            E::G1Affine::rand(&mut rng),
            E::G1Affine::rand(&mut rng),
            E::G1Affine::rand(&mut rng),
        ];
        let h = E::G1Affine::rand(&mut rng);
        let generators = [&g[..], &[h]].concat();
        let ck = PedersenKey { g, h };

        let mut cs = ArithExtractor::new();
        cs.execute_synthesizer(MySillyCircuit {
            a: Default::default(),
            b: Default::default(),
            c: Default::default(),
            d: Default::default(),
            e: Default::default(),
            f: Default::default(),
        })
        .unwrap();

        let (pk, vk) = LegoGroth16::<E>::generate_keys(
            (cs.arith().unwrap(), UsizeSet::from_iter(vec![0, 3, 5])),
            &[&ck],
            &mut rng,
        )
        .unwrap();

        for _ in 0..n_iters {
            let a = E::ScalarField::rand(&mut rng);
            let b = E::ScalarField::rand(&mut rng);
            let c = E::ScalarField::rand(&mut rng);
            let d = E::ScalarField::rand(&mut rng);
            let e = E::ScalarField::rand(&mut rng);
            let f = E::ScalarField::rand(&mut rng);

            let mut cs = AssignmentsExtractor::new();
            cs.execute_synthesizer(MySillyCircuit { a, b, c, d, e, f })
                .unwrap();
            let assignments = cs.assignments().unwrap();

            let o = [E::ScalarField::rand(&mut rng)];

            let cm = vec![E::G1::msm_unchecked(&generators, &[d, e, f, o[0]]).into_affine()];

            let proof = LegoGroth16::<E>::prove(
                &pk,
                &assignments.public,
                &assignments.private,
                &o,
                &mut rng,
            )
            .unwrap();

            assert!(
                LegoGroth16::<E>::verify(&vk, &[(a + b + c) * (d + e + f)], &cm, &proof).is_ok()
            );
            assert!(LegoGroth16::<E>::verify(&vk, &[a], &cm, &proof).is_err());
        }
    }

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bn254>(5);
        test_prove_and_verify2::<Bn254>(5);
        test_prove_and_verify3::<Bn254>(5);
    }
}
