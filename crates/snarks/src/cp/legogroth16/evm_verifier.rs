use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use askama::Template;

use crate::cp::legogroth16::VerifierKey;

#[derive(Template)]
#[template(path = "legogroth16.sol.askama")]
pub struct LegoGroth16VerifierTemplate<'a> {
    pub vk: &'a VerifierKey<Bn254>,
}

#[cfg(test)]
mod tests {
    use ark_std::{error::Error, rand::thread_rng};
    use sonobe_primitives::utils::evm::{compiler::SolidityCompiler, harness::TestEVM};

    use super::*;
    use crate::cp::legogroth16::tests::{toy_keygen, toy_prove};

    #[test]
    fn test_evm_verifier() -> Result<(), Box<dyn Error>> {
        let solc = SolidityCompiler::default();
        assert!(solc.available());

        let mut rng = thread_rng();
        let ck_sizes = [1, 1, 1];
        let (pk, vk, generators) = toy_keygen::<Bn254>(&ck_sizes, &mut rng);
        let (g, cm, proof) = toy_prove(&pk, &generators, &ck_sizes, &mut rng);

        let source = LegoGroth16VerifierTemplate { vk: &vk }.render()?;
        let (bytecode, selectors) = solc.compile(
            vec![("LegoGroth16Verifier.sol", source)],
            "LegoGroth16Verifier",
        )?;
        let mut evm = TestEVM::default();
        let addr = evm.deploy(&bytecode, ())?.unwrap();

        assert!(
            evm.view(
                addr,
                *selectors.get("verifyProof").unwrap(),
                ([g], cm, proof)
            )?
            .is_success()
        );
        Ok(())
    }
}
