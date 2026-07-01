//! Solidity codegen traits and templates for the on-chain decider verifier.

use ark_bn254::Bn254;
use ark_std::{borrow::Borrow, marker::PhantomData};
use askama::Template;
use sonobe_fs::{Error, FoldingSchemeVerifier};
use sonobe_primitives::circuits::FCircuit;
use sonobe_snarks::cp::legogroth16::VerifierKey;

pub struct DeciderFoldFragment {
    pub challenge: String,
    pub params: Vec<String>,
    pub body: String,
    pub commitments: Vec<String>,
}

pub trait FoldingSchemeEVMExt<const M: usize, const N: usize>: FoldingSchemeVerifier<M, N> {
    fn decider_fold_fragment() -> DeciderFoldFragment;

    #[allow(non_snake_case)]
    fn verify_calldata(
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Vec<u8>, Error>;
}

pub struct DeciderStateFragment {
    pub type_name: String,
    pub type_def: String,
    pub shape_check_body: String,
    pub flatten_body: String,
}

pub trait FCircuitEVMExt: FCircuit {
    fn decider_state_fragment(reference: &Self::State) -> DeciderStateFragment;
}

/// [`CycleFoldBasedIVCDeciderVerifierTemplate`] is rendered as the contract
/// `DeciderVerifier` via [`askama`].
#[derive(Template)]
#[template(path = "cyclefold_based_ivc_decider.sol.askama")]
pub struct CycleFoldBasedIVCDeciderVerifierTemplate<
    'a,
    FS: FoldingSchemeEVMExt<1, 1>,
    FC: FCircuitEVMExt,
> {
    _t: PhantomData<FS>,
    vk: &'a VerifierKey<Bn254>,
    reference_state: &'a FC::State,
}

impl<'a, FS: FoldingSchemeEVMExt<1, 1>, FC: FCircuitEVMExt>
    CycleFoldBasedIVCDeciderVerifierTemplate<'a, FS, FC>
{
    pub fn new(vk: &'a VerifierKey<Bn254>, reference_state: &'a FC::State) -> Self {
        Self {
            _t: PhantomData,
            vk,
            reference_state,
        }
    }
}
