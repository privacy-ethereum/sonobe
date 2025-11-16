use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use ark_ff::PrimeField;

pub mod sponge;

/// This Poseidon configuration generator produces a Poseidon configuration with custom parameters
pub fn poseidon_custom_config<F: PrimeField>(
    full_rounds: usize,
    partial_rounds: usize,
    alpha: u64,
    rate: usize,
    capacity: usize,
) -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}

/// This Poseidon configuration generator agrees with Circom's Poseidon(4) in the case of BN254's scalar field
pub fn poseidon_canonical_config<F: PrimeField>() -> PoseidonConfig<F> {
    // 120 bit security target as in
    // https://eprint.iacr.org/2019/458.pdf
    // t = rate + 1

    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5;
    let rate = 4;

    poseidon_custom_config(full_rounds, partial_rounds, alpha, rate, 1)
}
