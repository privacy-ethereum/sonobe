//! Virtual polynomial implementation and polynomial utilities.
//!
//! The code is forked from our previous [multifolding PoC implementation],
//! which is itself forked from HyperPlonk's [virtual polynomial code].
//!
//! [multifolding PoC implementation]: https://github.com/privacy-scaling-explorations/multifolding-poc/blob/main/src/espresso/virtual_polynomial.rs,
//! [virtual polynomial code]: https://github.com/EspressoSystems/hyperplonk/blob/main/arithmetic/src/virtual_polynomial.rs

// Below we attach HyperPlonk's original license notice.
//
// The MIT License (MIT)
//
// Copyright (c) 2022 Espresso Systems (espressosys.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use ark_ff::{Field, PrimeField, batch_inversion};
use ark_poly::{DenseMultilinearExtension, DenseUVPolynomial, univariate::DensePolynomial};
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_serialize::CanonicalSerialize;
use ark_std::cfg_into_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// [`VirtualPolynomial`] is a sum of products of multilinear polynomials;
/// where the multilinear polynomials are stored via their multilinear
/// extensions:  `(coefficient, DenseMultilinearExtension)`
///
/// * Number of products n = `polynomial.products.len()`,
/// * Number of multiplicands of ith product m_i =
///   `polynomial.products[i].1.len()`,
/// * Coefficient of ith product c_i = `polynomial.products[i].0`
///
/// The resulting polynomial is
///
/// $$ \sum_{i=0}^{n} c_i \cdot \prod_{j=0}^{m_i} P_{ij} $$
///
/// Example:
///  f = c0 * f0 * f1 * f2 + c1 * f3 * f4
/// where f0 ... f4 are multilinear polynomials
///
/// - `flattened_ml_extensions` stores the multilinear extension representation
///   of f0, f1, f2, f3 and f4
/// - `products` is `[(c0, [0, 1, 2]), (c1, [3, 4])]`
/// - raw_pointers_lookup_table maps fi to i
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VirtualPolynomial<F: Field> {
    /// [`VirtualPolynomial::aux_info`] is the aux information about the
    /// multilinear polynomial.
    pub aux_info: VPAuxInfo,
    /// [`VirtualPolynomial::flattened_ml_extensions`] stores multilinear
    /// extensions in which product multiplicand can refer to.
    pub flattened_ml_extensions: Vec<DenseMultilinearExtension<F>>,
    /// [`VirtualPolynomial::products`] is a list of reference to products
    /// (as usize) of multilinear extension
    pub products: Vec<(F, Vec<usize>)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize)]
/// [`VPAuxInfo`] is auxiliary information about the multilinear polynomial.
pub struct VPAuxInfo {
    /// [`VPAuxInfo::max_degree`] is the max number of multiplicands in each
    /// product.
    pub max_degree: usize,
    /// [`VPAuxInfo::num_variables`] is the number of variables of the
    /// polynomial.
    pub num_variables: usize,
}

impl<F: PrimeField> VirtualPolynomial<F> {
    /// Creates a new virtual polynomial from a MLE and its coefficient.
    pub fn new_from_mle(mle: DenseMultilinearExtension<F>, coefficient: F) -> Self {
        VirtualPolynomial {
            aux_info: VPAuxInfo {
                // The max degree is the max degree of any individual variable
                max_degree: 1,
                num_variables: mle.num_vars,
            },
            // here `0` points to the first polynomial of `flattened_ml_extensions`
            products: vec![(coefficient, vec![0])],
            flattened_ml_extensions: vec![mle],
        }
    }
}

/// [`EqPoly`] represents the multilinear equality polynomial
/// `eq(x, y) = Π_{i ∈ {0,1}} (x_i y_i + (1 - x_i)(1 - y_i))`.
pub struct EqPoly;

impl EqPoly {
    /// [`EqPoly::fix_y_evals`] function evaluates `eq(x, y)` by fixing `y = r`
    /// and outputting the evaluations over all `x` in `[0, 2^n)`.
    pub fn fix_y_evals<F: Field>(r: &[F]) -> Vec<F> {
        // we build eq(x,r) from its evaluations
        // we want to evaluate eq(x,r) over all binary strings `x` of length `n`
        // for example, with n = 4, x is a binary string of length 4, then
        //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
        //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
        //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
        //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
        //  ....
        //  1 1 1 1 -> r0       * r1        * r2        * r3
        // we will need 2^num_var evaluations

        // initializing the buffer with [1]
        let mut buf = vec![F::one()];

        for i in r.iter().rev() {
            // suppose at the previous step we received [b_1, ..., b_k]
            // for the current step we will need
            // if x_i = 0:   (1-ri) * [b_1, ..., b_k]
            // if x_i = 1:   ri * [b_1, ..., b_k]
            buf = cfg_into_iter!(buf)
                .flat_map(|j| {
                    let v = j * i;
                    [j - v, v]
                })
                .collect();
        }

        buf
    }

    /// [`EqPoly::fix_xy_eval`] evaluates `eq(x, y)` by fixing both `x` and `y`.
    pub fn fix_xy_eval<F: Field>(x: &[F], y: &[F]) -> F {
        debug_assert_eq!(x.len(), y.len());
        x.iter()
            .zip(y.iter())
            .map(|(xi, yi)| xi.double() * yi - xi - yi + F::one())
            .product()
    }
}

/// [`EqPolyGadget`] is the in-circuit gadget of [`EqPoly`].
pub struct EqPolyGadget;

impl EqPolyGadget {
    /// [`EqPolyGadget::fix_xy_eval`] evaluates `eq(x, y)` in-circuit by fixing
    /// both `x` and `y`.
    pub fn fix_xy_eval<F: PrimeField>(x: &[FpVar<F>], y: &[FpVar<F>]) -> FpVar<F> {
        debug_assert_eq!(x.len(), y.len());
        let mut eval = FpVar::<F>::one();
        for (xi, yi) in x.iter().zip(y.iter()) {
            eval *= (xi + xi) * yi - xi - yi + F::one();
        }
        eval
    }
}

/// [`barycentric_weights`] computes the barycentric weights for a given set of
/// evaluation `points`.
///
/// Used to extrapolate polynomial evaluations via the barycentric formula.
#[allow(clippy::filter_map_bool_then)]
pub fn barycentric_weights<F: Field>(points: &[F]) -> Vec<F> {
    let mut weights = points
        .iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .iter()
                .enumerate()
                .filter_map(|(i, point_i)| (i != j).then(|| *point_j - point_i))
                .reduce(|acc, value| acc * value)
                .unwrap_or_else(F::one)
        })
        .collect::<Vec<_>>();
    batch_inversion(&mut weights);
    weights
}

/// [`extrapolate`] extrapolates the polynomial defined by `(points, evals)` to
/// a new point `at`, using the precomputed barycentric `weights`.
pub fn extrapolate<F: Field>(points: &[F], weights: &[F], evals: &[F], at: &F) -> F {
    let (coeffs, sum_inv) = {
        let mut coeffs = points.iter().map(|point| *at - point).collect::<Vec<_>>();
        batch_inversion(&mut coeffs);
        coeffs.iter_mut().zip(weights).for_each(|(coeff, weight)| {
            *coeff *= weight;
        });
        let sum_inv = coeffs.iter().sum::<F>().inverse().unwrap_or_default();
        (coeffs, sum_inv)
    };
    coeffs
        .iter()
        .zip(evals)
        .map(|(coeff, eval)| *coeff * eval)
        .sum::<F>()
        * sum_inv
}

/// [`compute_lagrange_interpolated_poly`] computes the lagrange interpolated
/// polynomial from the given points `p_i`.
pub fn compute_lagrange_interpolated_poly<F: Field>(p_i: &[F]) -> DensePolynomial<F> {
    let v = (0..p_i.len())
        .map(|i| F::from(i as u64))
        .collect::<Vec<_>>();

    // compute l(x), common to every basis polynomial
    let mut l_x = DensePolynomial::from_coefficients_vec(vec![F::ONE]);
    for i in &v {
        let prod_m = DensePolynomial::from_coefficients_vec(vec![-*i, F::ONE]);
        l_x = l_x.naive_mul(&prod_m);
    }

    // compute each w_j - barycentric weights
    let w_j_vector = barycentric_weights(&v);

    // compute each polynomial within the sum L(x)
    let mut lagrange_poly = DensePolynomial::from_coefficients_vec(vec![F::ZERO]);
    for (j, w_j) in w_j_vector.iter().enumerate() {
        let x_j = j;
        let y_j = p_i[j];
        // we multiply by l(x) here, otherwise the below division will not work - deg(0)/deg(d)
        let poly_numerator = &(&l_x * (*w_j)) * (y_j);
        let poly_denominator = DensePolynomial::from_coefficients_vec(vec![-v[x_j], F::ONE]);
        let poly = poly_numerator.naive_div(&poly_denominator);
        lagrange_poly = &lagrange_poly + &poly;
    }

    lagrange_poly
}

#[cfg(test)]
mod tests {
    use ark_pallas::Fr;
    use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
    use ark_std::{UniformRand, rand::thread_rng};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    /// Interpolate a uni-variate degree-`p_i.len()-1` polynomial and evaluate this
    /// polynomial at `eval_at`:
    ///
    ///   \sum_{i=0}^len p_i * (\prod_{j!=i} (eval_at - j)/(i-j) )
    ///
    /// This implementation is linear in number of inputs in terms of field
    /// operations. It also has a quadratic term in primitive operations which is
    /// negligible compared to field operations.
    /// TODO: The quadratic term can be removed by precomputing the lagrange
    /// coefficients.
    fn interpolate_uni_poly<F: PrimeField>(p_i: &[F], eval_at: F) -> F {
        let len = p_i.len();
        let mut evals = vec![];
        let mut prod = eval_at;
        evals.push(eval_at);

        // `prod = \prod_{j} (eval_at - j)`
        for e in 1..len {
            let tmp = eval_at - F::from(e as u64);
            evals.push(tmp);
            prod *= tmp;
        }
        let mut res = F::zero();
        // we want to compute \prod (j!=i) (i-j) for a given i
        //
        // we start from the last step, which is
        //  denom[len-1] = (len-1) * (len-2) *... * 2 * 1
        // the step before that is
        //  denom[len-2] = (len-2) * (len-3) * ... * 2 * 1 * -1
        // and the step before that is
        //  denom[len-3] = (len-3) * (len-4) * ... * 2 * 1 * -1 * -2
        //
        // i.e., for any i, the one before this will be derived from
        //  denom[i-1] = denom[i] * (len-i) / i
        //
        // that is, we only need to store
        // - the last denom for i = len-1, and
        // - the ratio between current step and fhe last step, which is the product of
        //   (len-i) / i from all previous steps and we store this product as a fraction
        //   number to reduce field divisions.

        // We know
        //  - 2^61 < factorial(20) < 2^62
        //  - 2^122 < factorial(33) < 2^123
        // so we will be able to compute the ratio
        //  - for len <= 20 with i64
        //  - for len <= 33 with i128
        //  - for len >  33 with BigInt
        if p_i.len() <= 20 {
            let last_denominator = F::from(u64_factorial(len - 1));
            let mut ratio_numerator = 1i64;
            let mut ratio_denominator = 1u64;

            for i in (0..len).rev() {
                let ratio_numerator_f = if ratio_numerator < 0 {
                    -F::from((-ratio_numerator) as u64)
                } else {
                    F::from(ratio_numerator as u64)
                };

                res += p_i[i] * prod * F::from(ratio_denominator)
                    / (last_denominator * ratio_numerator_f * evals[i]);

                // compute denom for the next step is current_denom * (len-i)/i
                if i != 0 {
                    ratio_numerator *= -(len as i64 - i as i64);
                    ratio_denominator *= i as u64;
                }
            }
        } else if p_i.len() <= 33 {
            let last_denominator = F::from(u128_factorial(len - 1));
            let mut ratio_numerator = 1i128;
            let mut ratio_denominator = 1u128;

            for i in (0..len).rev() {
                let ratio_numerator_f = if ratio_numerator < 0 {
                    -F::from((-ratio_numerator) as u128)
                } else {
                    F::from(ratio_numerator as u128)
                };

                res += p_i[i] * prod * F::from(ratio_denominator)
                    / (last_denominator * ratio_numerator_f * evals[i]);

                // compute denom for the next step is current_denom * (len-i)/i
                if i != 0 {
                    ratio_numerator *= -(len as i128 - i as i128);
                    ratio_denominator *= i as u128;
                }
            }
        } else {
            let mut denom_up = field_factorial::<F>(len - 1);
            let mut denom_down = F::one();

            for i in (0..len).rev() {
                res += p_i[i] * prod * denom_down / (denom_up * evals[i]);

                // compute denom for the next step is current_denom * (len-i)/i
                if i != 0 {
                    denom_up *= -F::from((len - i) as u64);
                    denom_down *= F::from(i as u64);
                }
            }
        }
        res
    }

    /// compute the factorial(a) = 1 * 2 * ... * a
    #[inline]
    fn field_factorial<F: PrimeField>(a: usize) -> F {
        let mut res = F::one();
        for i in 2..=a {
            res *= F::from(i as u64);
        }
        res
    }

    /// compute the factorial(a) = 1 * 2 * ... * a
    #[inline]
    fn u128_factorial(a: usize) -> u128 {
        let mut res = 1u128;
        for i in 2..=a {
            res *= i as u128;
        }
        res
    }

    /// compute the factorial(a) = 1 * 2 * ... * a
    #[inline]
    fn u64_factorial(a: usize) -> u64 {
        let mut res = 1u64;
        for i in 2..=a {
            res *= i as u64;
        }
        res
    }

    #[test]
    fn test_compute_lagrange_interpolated_poly() {
        let mut prng = thread_rng();
        for degree in 1..30 {
            let poly = DensePolynomial::<Fr>::rand(degree, &mut prng);
            // range (which is exclusive) is from 0 to degree + 1, since we need degree + 1 evaluations
            let evals = (0..(degree + 1))
                .map(|i| poly.evaluate(&Fr::from(i as u64)))
                .collect::<Vec<Fr>>();
            let lagrange_poly = compute_lagrange_interpolated_poly(&evals);
            for _ in 0..10 {
                let query = Fr::rand(&mut prng);
                let lagrange_eval = lagrange_poly.evaluate(&query);
                let eval = poly.evaluate(&query);
                assert_eq!(eval, lagrange_eval);
                assert_eq!(lagrange_poly.degree(), poly.degree());
            }
        }
    }

    #[test]
    fn test_interpolation() {
        let mut prng = thread_rng();

        // test a polynomial with 20 known points, i.e., with degree 19
        let poly = DensePolynomial::<Fr>::rand(20 - 1, &mut prng);
        let evals = (0..20)
            .map(|i| poly.evaluate(&Fr::from(i)))
            .collect::<Vec<Fr>>();
        let query = Fr::rand(&mut prng);

        assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query));
        assert_eq!(
            compute_lagrange_interpolated_poly(&evals).evaluate(&query),
            interpolate_uni_poly(&evals, query)
        );

        // test a polynomial with 33 known points, i.e., with degree 32
        let poly = DensePolynomial::<Fr>::rand(33 - 1, &mut prng);
        let evals = (0..33)
            .map(|i| poly.evaluate(&Fr::from(i)))
            .collect::<Vec<Fr>>();
        let query = Fr::rand(&mut prng);

        assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query));
        assert_eq!(
            compute_lagrange_interpolated_poly(&evals).evaluate(&query),
            interpolate_uni_poly(&evals, query)
        );

        // test a polynomial with 64 known points, i.e., with degree 63
        let poly = DensePolynomial::<Fr>::rand(64 - 1, &mut prng);
        let evals = (0..64)
            .map(|i| poly.evaluate(&Fr::from(i)))
            .collect::<Vec<Fr>>();
        let query = Fr::rand(&mut prng);

        assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query));
        assert_eq!(
            compute_lagrange_interpolated_poly(&evals).evaluate(&query),
            interpolate_uni_poly(&evals, query)
        );
    }
}
