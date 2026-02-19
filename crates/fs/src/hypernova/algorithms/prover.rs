//! Proof generation for HyperNova.

use ark_ff::One;
use ark_poly::{DenseMultilinearExtension as MLE, MultilinearExtension};
use ark_std::{borrow::Borrow, rand::RngCore};
use sonobe_primitives::{
    algebra::ops::{
        bits::FromBits,
        pow::Pow,
        rlc::{ScalarRLC, SliceRLC},
    },
    arithmetizations::{Arith, ArithConfig, ccs::CCSVariant},
    commitments::GroupBasedCommitment,
    sumcheck::{
        SumCheck,
        utils::{EqPoly, VPAuxInfo, VirtualPolynomial},
    },
    transcripts::Transcript,
};

use crate::{
    Error, FoldingSchemeProver,
    hypernova::{HyperNova, HyperNova2, HyperNovaKey, NIMFSProof},
};

impl<
    CM: GroupBasedCommitment,
    V: CCSVariant,
    const M: usize,
    const N: usize,
    const CHALLENGE_BITS: usize,
> FoldingSchemeProver<M, N> for HyperNova<CM, V, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &HyperNovaKey<Self::Arith, CM>,
        transcript: &mut impl Transcript<CM::Scalar>,
        Ws: &[impl Borrow<Self::RW>; M],
        Us: &[impl Borrow<Self::RU>; M],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        _rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<M, N>, Self::Challenge), Error> {
        let Ws = &Ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let Us = &Us.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let ws = &ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let ccs = &pk.arith;
        let d = V::degree();
        let s = ccs.config().log_constraints();
        let t = V::n_matrices();
        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<CM::Scalar>();

        // absorb instances to transcript
        transcript.add(&Us[..]);
        transcript.add(&us[..]);

        // Step 1: Get some challenges
        let gamma = transcript.challenge_field_element();
        let beta = transcript.challenge_field_elements(s);

        let gamma_powers = gamma.powers(M * t + N);
        let (running_gammas, incoming_gammas) = gamma_powers.split_at(M * t);

        // Compute g(x)
        let running_mles = Ws
            .iter()
            .zip(Us)
            .flat_map(|(W, U)| ccs.mles((U.u, &U.x, &W.w).into()));
        let incoming_mles = ws
            .iter()
            .zip(us)
            .flat_map(|(w, u)| ccs.mles((One::one(), &u.x, &w.w).into()));
        let eq_mles = Us
            .iter()
            .map(|U| &U.r_x)
            .chain([&beta])
            .map(|r| MLE::from_evaluations_vec(s, EqPoly::fix_y_evals(r)));

        let running_products = running_gammas
            .iter()
            .enumerate()
            .map(|(i, &gamma)| (gamma, vec![i, (M + N) * t + i / t]));
        let incoming_products = incoming_gammas.iter().enumerate().flat_map(|(k, gamma)| {
            S.iter().zip(c).map(move |(S_i, &c_i)| {
                (
                    c_i * gamma,
                    S_i.iter()
                        .map(|j| (M + k) * t + j)
                        .chain([(M + N) * t + M])
                        .collect(),
                )
            })
        });

        let g = VirtualPolynomial {
            aux_info: VPAuxInfo {
                num_variables: s,
                max_degree: d + 1,
            },
            flattened_ml_extensions: running_mles.chain(incoming_mles).chain(eq_mles).collect(),
            products: running_products.chain(incoming_products).collect(),
        };

        // Step 3: Run the sumcheck prover
        // Step 2: dig into the sumcheck and extract r_x_prime
        let (sumcheck_proof, r_x_prime, mles) = SumCheck::prove(g, transcript)?;

        // Step 4: compute sigmas and thetas
        let sigmas = mles[0..t * M]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();
        let thetas = mles[t * M..t * (M + N)]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();

        // Step 6: Get the folding challenge
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = CM::Scalar::from_bits_le(&rho_bits);

        let rho_powers = rho.powers(M + N);

        Ok((
            Self::RW {
                w: Ws
                    .iter()
                    .map(|w| &w.w[..])
                    .chain(ws.iter().map(|w| &w.w[..]))
                    .slice_rlc(&rho_powers),
                r: Ws
                    .iter()
                    .map(|w| w.r)
                    .chain(ws.iter().map(|w| w.r))
                    .scalar_rlc(&rho_powers),
            },
            Self::RU {
                cm: Us
                    .iter()
                    .map(|u| u.cm)
                    .chain(us.iter().map(|u| u.cm))
                    .scalar_rlc(&rho_powers),
                u: Us
                    .iter()
                    .map(|u| u.u)
                    .chain([CM::Scalar::one(); N])
                    .scalar_rlc(&rho_powers),
                x: Us
                    .iter()
                    .map(|u| &u.x[..])
                    .chain(us.iter().map(|u| &u.x[..]))
                    .slice_rlc(&rho_powers),
                r_x: r_x_prime,
                v: sigmas
                    .chunks(t)
                    .chain(thetas.chunks(t))
                    .slice_rlc(&rho_powers),
            },
            NIMFSProof {
                sc_proof: sumcheck_proof,
                sigmas,
                thetas,
            },
            rho_bits.try_into().unwrap(),
        ))
    }
}

impl<
    CM: GroupBasedCommitment,
    V: CCSVariant,
    const M: usize,
    const N: usize,
    const CHALLENGE_BITS: usize,
> FoldingSchemeProver<M, N> for HyperNova2<CM, V, CHALLENGE_BITS>
{
    #[allow(non_snake_case)]
    fn prove(
        pk: &HyperNovaKey<Self::Arith, CM>,
        transcript: &mut impl Transcript<CM::Scalar>,
        Ws: &[impl Borrow<Self::RW>; M],
        Us: &[impl Borrow<Self::RU>; M],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        mut rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<M, N>, Self::Challenge), Error> {
        let Ws = &Ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let Us = &Us.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let ws = &ws.iter().map(|i| i.borrow()).collect::<Vec<_>>();
        let us = &us.iter().map(|i| i.borrow()).collect::<Vec<_>>();

        let ccs = &pk.arith;
        let d = V::degree();
        let s = ccs.config().log_constraints();
        let t = V::n_matrices();
        let S = &V::multisets_vec();
        let c = &V::coefficients_vec::<CM::Scalar>();

        let mut cms = [CM::Commitment::default(); N];
        let mut rs = [CM::Randomness::default(); N];
        for i in 0..N {
            let (cm, r) = CM::commit(&pk.ck, ws[i], &mut rng)?;
            cms[i] = cm;
            rs[i] = r;
        }

        // absorb instances to transcript
        transcript.add(&Us[..]);
        transcript.add(&us[..]);
        transcript.add(&cms[..]);

        // Step 1: Get some challenges
        let gamma = transcript.challenge_field_element();
        let beta = transcript.challenge_field_elements(s);

        let gamma_powers = gamma.powers(M * t + N);
        let (running_gammas, incoming_gammas) = gamma_powers.split_at(M * t);

        // Compute g(x)
        let running_mles = Ws
            .iter()
            .zip(Us)
            .flat_map(|(W, U)| ccs.mles((U.u, &U.x, &W.w).into()));
        let incoming_mles = ws
            .iter()
            .zip(us)
            .flat_map(|(w, u)| ccs.mles((One::one(), &u[..], &w[..]).into()));
        let eq_mles = Us
            .iter()
            .map(|U| &U.r_x)
            .chain([&beta])
            .map(|r| MLE::from_evaluations_vec(s, EqPoly::fix_y_evals(r)));

        let running_products = running_gammas
            .iter()
            .enumerate()
            .map(|(i, &gamma)| (gamma, vec![i, (M + N) * t + i / t]));
        let incoming_products = incoming_gammas.iter().enumerate().flat_map(|(k, gamma)| {
            S.iter().zip(c).map(move |(S_i, &c_i)| {
                (
                    c_i * gamma,
                    S_i.iter()
                        .map(|j| (M + k) * t + j)
                        .chain([(M + N) * t + M])
                        .collect(),
                )
            })
        });

        let g = VirtualPolynomial {
            aux_info: VPAuxInfo {
                num_variables: s,
                max_degree: d + 1,
            },
            flattened_ml_extensions: running_mles.chain(incoming_mles).chain(eq_mles).collect(),
            products: running_products.chain(incoming_products).collect(),
        };

        // Step 3: Run the sumcheck prover
        // Step 2: dig into the sumcheck and extract r_x_prime
        let (sumcheck_proof, r_x_prime, mles) = SumCheck::prove(g, transcript)?;

        // Step 4: compute sigmas and thetas
        let sigmas = mles[0..t * M]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();
        let thetas = mles[t * M..t * (M + N)]
            .iter()
            .map(|mle| mle.fix_variables(&[])[0])
            .collect::<Vec<_>>();

        // Step 6: Get the folding challenge
        let rho_bits = transcript.challenge_bits(CHALLENGE_BITS);
        let rho = CM::Scalar::from_bits_le(&rho_bits);

        let rho_powers = rho.powers(M + N);

        Ok((
            Self::RW {
                w: Ws
                    .iter()
                    .map(|w| &w.w[..])
                    .chain(ws.iter().map(|w| &w[..]))
                    .slice_rlc(&rho_powers),
                r: Ws.iter().map(|w| w.r).chain(rs).scalar_rlc(&rho_powers),
            },
            Self::RU {
                cm: Us
                    .iter()
                    .map(|u| u.cm)
                    .chain(cms.iter().copied())
                    .scalar_rlc(&rho_powers),
                u: Us
                    .iter()
                    .map(|u| u.u)
                    .chain([CM::Scalar::one(); N])
                    .scalar_rlc(&rho_powers),
                x: Us
                    .iter()
                    .map(|u| &u.x[..])
                    .chain(us.iter().map(|u| &u[..]))
                    .slice_rlc(&rho_powers),
                r_x: r_x_prime,
                v: sigmas
                    .chunks(t)
                    .chain(thetas.chunks(t))
                    .slice_rlc(&rho_powers),
            },
            (
                cms,
                NIMFSProof {
                    sc_proof: sumcheck_proof,
                    sigmas,
                    thetas,
                },
            ),
            rho_bits.try_into().unwrap(),
        ))
    }
}
