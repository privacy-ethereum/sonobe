use ark_std::convert::Infallible;
use revm::{
    ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext, MainnetEvm,
    context::{Context, TxEnv, result::EVMError},
    context_interface::result::ExecutionResult,
    database::{CacheDB, EmptyDB},
    handler::MainnetContext,
    primitives::{Address, Bytes},
};

use super::serialize::EVMSerialize;

/// [`TestEVM`] is a minimal in-memory `revm` harness for deploying and invoking
/// rendered verifier contracts in tests.
pub struct TestEVM {
    evm: MainnetEvm<MainnetContext<CacheDB<EmptyDB>>>,
}

impl Default for TestEVM {
    fn default() -> Self {
        Self {
            evm: Context::mainnet()
                .with_db(CacheDB::default())
                .modify_cfg_chained(|cfg| cfg.disable_nonce_check = true)
                .build_mainnet(),
        }
    }
}

impl TestEVM {
    /// [`TestEVM::deploy`] deploys a smart contract's `bytecode`, calls its
    /// constructor with `args`, and returns the deployed contract's address.
    pub fn deploy(
        &mut self,
        bytecode: &Bytes,
        args: impl EVMSerialize,
    ) -> Result<Option<Address>, EVMError<Infallible>> {
        self.evm
            .transact_commit(
                TxEnv::builder()
                    .create()
                    .data([&bytecode[..], &args.to_calldata()].concat().into())
                    .build_fill(),
            )
            .map(|i| i.created_address())
    }

    /// [`TestEVM::send`] sends to the contract deployed at `to` a transaction,
    /// which calls the function specified by `selector` with `args`.
    ///
    /// This method mutates the onchain state and returns the execution result.
    pub fn send(
        &mut self,
        to: Address,
        selector: [u8; 4],
        args: impl EVMSerialize,
    ) -> Result<ExecutionResult, EVMError<Infallible>> {
        self.evm.transact_commit(
            TxEnv::builder()
                .call(to)
                .data([&selector[..], &args.to_calldata()].concat().into())
                .build_fill(),
        )
    }

    /// [`TestEVM::view`] simulates the execution of the contract deployed at
    /// `to` on a call to the function specified by `selector` with `args`.
    ///
    /// This method keeps the onchain state unchanged and returns the execution
    /// result.
    pub fn view(
        &mut self,
        to: Address,
        selector: [u8; 4],
        args: impl EVMSerialize,
    ) -> Result<ExecutionResult, EVMError<Infallible>> {
        self.evm
            .transact(
                TxEnv::builder()
                    .call(to)
                    .data([&selector[..], &args.to_calldata()].concat().into())
                    .build_fill(),
            )
            .map(|i| i.result)
    }
}
