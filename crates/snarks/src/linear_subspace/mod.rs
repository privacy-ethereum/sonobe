use ark_ec::{CurveGroup, ScalarMul, VariableBaseMSM, pairing::Pairing};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverKey<E: Pairing> {
    pub p: Vec<E::G1Affine>,
}

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierKey<E: Pairing> {
    pub c: Vec<E::G2Affine>,
    pub a_neg: E::G2Affine,
}

pub struct LinearSubspaceSNARK {}

impl LinearSubspaceSNARK {
    pub fn generate_keys<E: Pairing>(
        n_rows: usize,
        mvm: impl Fn(Vec<E::ScalarField>) -> Vec<E::G1>,
        rng: &mut impl Rng,
    ) -> (ProverKey<E>, VerifierKey<E>) {
        let k = (0..n_rows)
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let a = E::G2::rand(rng);
        let c = a.batch_mul(&k);

        (
            ProverKey {
                p: E::G1::normalize_batch(&mvm(k)),
            },
            VerifierKey {
                c,
                a_neg: -a.into_affine(),
            },
        )
    }

    pub fn prove<E: Pairing>(
        ek: &ProverKey<E>,
        w: &[<E::ScalarField as PrimeField>::BigInt],
    ) -> E::G1Affine {
        assert_eq!(ek.p.len(), w.len());
        E::G1::msm_bigint(&ek.p, w).into_affine()
    }

    pub fn verify<E: Pairing>(vk: &VerifierKey<E>, x: &[E::G1Affine], pi: &E::G1Affine) -> bool {
        // `E::multi_pairing` internally uses `zip_eq`
        E::multi_pairing([x, &[*pi][..]].concat(), [&vk.c, &[vk.a_neg][..]].concat()).is_zero()
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254, Fr, G1Affine};
    use ark_ec::AffineRepr;
    use ark_ff::One;
    use ark_std::rand::thread_rng;

    use super::*;

    fn test_mvm<A: AffineRepr>(m: &[Vec<A>]) -> impl Fn(Vec<A::ScalarField>) -> Vec<A::Group> {
        move |k| {
            (0..m[0].len())
                .map(|i| k.iter().zip(m).map(|(u, v)| v[i] * u).sum::<A::Group>())
                .collect::<Vec<_>>()
        }
    }

    #[test]
    fn test_basic() {
        // Prove knowledge of all `x_i` in `y = \sum_i g_i * x_i`
        let mut rng = thread_rng();
        let g1 = G1Affine::rand(&mut rng);

        let m = vec![vec![g1, g1]];

        let x = vec![Fr::one().into_bigint(), Fr::zero().into_bigint()];

        let x_bad = vec![Fr::one().into_bigint(), Fr::one().into_bigint()];

        let y: Vec<G1Affine> = vec![g1];

        let (ek, vk) = LinearSubspaceSNARK::generate_keys::<Bn254>(m.len(), test_mvm(&m), &mut rng);

        let pi = LinearSubspaceSNARK::prove(&ek, &x);
        let pi_bad = LinearSubspaceSNARK::prove(&ek, &x_bad);

        assert!(LinearSubspaceSNARK::verify(&vk, &y, &pi));
        assert!(!LinearSubspaceSNARK::verify(&vk, &y, &pi_bad));
    }

    #[test]
    fn test_basic_1() {
        // Prove knowledge of all `w_i` in `y = \sum_i h_i * w_i`
        let mut rng = thread_rng();

        let h1 = G1Affine::rand(&mut rng);
        let h2 = G1Affine::rand(&mut rng);
        let m = vec![vec![h1, h2]];

        let two = Fr::one() + Fr::one();
        let three = Fr::one() + two;

        // Correct witness
        let w = vec![two.into_bigint(), three.into_bigint()];
        // Incorrect witness
        let w_bad = vec![Fr::one().into_bigint(), Fr::one().into_bigint()];

        // y is a Pedersen-like commitment to `two` and `three` and bases `h1` and `h2`,
        // i.e `y = h1 * two + h2 * three`
        let y: Vec<G1Affine> = vec![
            (h1.mul_bigint(two.into_bigint()) + h2.mul_bigint(three.into_bigint())).into_affine(),
        ];

        let (ek, vk) = LinearSubspaceSNARK::generate_keys::<Bn254>(m.len(), test_mvm(&m), &mut rng);

        let pi = LinearSubspaceSNARK::prove(&ek, &w);
        let pi_bad = LinearSubspaceSNARK::prove(&ek, &w_bad);

        assert!(LinearSubspaceSNARK::verify(&vk, &y, &pi));
        assert!(!LinearSubspaceSNARK::verify(&vk, &y, &pi_bad));
    }

    #[test]
    fn test_same_value_different_bases() {
        // Given `bases1 = [h1, h2]` and `bases2 = [h3, h4]`, prove knowledge of `x1, x2
        // x3` in `y0 = h1 * x0 + h2 * x2` and `y1 = h3 * x1 + h4 * x2`

        let mut rng = thread_rng();

        let bases1 = [G1Affine::rand(&mut rng), G1Affine::rand(&mut rng)];
        let bases2 = [G1Affine::rand(&mut rng), G1Affine::rand(&mut rng)];
        let m = vec![
            vec![bases1[0], G1Affine::zero(), bases1[1]],
            vec![G1Affine::zero(), bases2[0], bases2[1]],
        ];

        let w = vec![
            Fr::rand(&mut rng).into_bigint(),
            Fr::rand(&mut rng).into_bigint(),
            Fr::rand(&mut rng).into_bigint(),
        ];

        let x: Vec<G1Affine> = vec![
            (bases1[0].mul_bigint(w[0]) + bases1[1].mul_bigint(w[2])).into_affine(),
            (bases2[0].mul_bigint(w[1]) + bases2[1].mul_bigint(w[2])).into_affine(),
        ];

        let (ek, vk) = LinearSubspaceSNARK::generate_keys::<Bn254>(m.len(), test_mvm(&m), &mut rng);

        let pi = LinearSubspaceSNARK::prove(&ek, &w);

        assert!(LinearSubspaceSNARK::verify(&vk, &x, &pi));
    }

    #[test]
    fn test_some_vals_equal() {
        // Given `bases1 = [h1, h2, h3]` and `bases2 = [h4, h5, h6]`, prove knowledge of
        // `x1, x2 x3, x4` in `y0 = h1 * x0 + h2 * x2 + h3 * x3` and `y1 = h4 * x1 + h5
        // * x2 + h6 * x4`

        let mut rng = thread_rng();

        let bases1 = [
            G1Affine::rand(&mut rng),
            G1Affine::rand(&mut rng),
            G1Affine::rand(&mut rng),
        ];
        let bases2 = [
            G1Affine::rand(&mut rng),
            G1Affine::rand(&mut rng),
            G1Affine::rand(&mut rng),
        ];

        let m = vec![
            vec![bases1[0], bases1[1], bases1[2], G1Affine::zero()],
            vec![bases2[0], bases2[1], G1Affine::zero(), bases2[2]],
        ];

        let w = vec![
            Fr::rand(&mut rng).into_bigint(),
            Fr::rand(&mut rng).into_bigint(),
            Fr::rand(&mut rng).into_bigint(),
            Fr::rand(&mut rng).into_bigint(),
        ];

        let x: Vec<G1Affine> = vec![
            (bases1[0].mul_bigint(w[0]) + bases1[1].mul_bigint(w[1]) + bases1[2].mul_bigint(w[2]))
                .into_affine(),
            (bases2[0].mul_bigint(w[0]) + bases2[1].mul_bigint(w[1]) + bases2[2].mul_bigint(w[3]))
                .into_affine(),
        ];

        let (ek, vk) = LinearSubspaceSNARK::generate_keys::<Bn254>(m.len(), test_mvm(&m), &mut rng);

        let pi = LinearSubspaceSNARK::prove(&ek, &w);

        assert!(LinearSubspaceSNARK::verify(&vk, &x, &pi));
    }
}
