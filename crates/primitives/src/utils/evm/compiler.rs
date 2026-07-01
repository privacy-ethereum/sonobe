use ark_std::{
    io::{Error as IOError, Write},
    process::{Command, Stdio},
};
use hashbrown::HashMap;
use revm::primitives::{
    Bytes,
    hex::{FromHexError, decode},
};
use serde::Deserialize;
use serde_json::{Error as JSONError, from_slice, json, to_vec};
use thiserror::Error;

/// [`Error`] enumerates possible errors during solidity compilation.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to run the `solc` process or read/write its pipes.
    #[error("solc i/o error: {0}")]
    Io(#[from] IOError),
    /// Failed to (de)serialize the `solc` Standard JSON.
    #[error("solc json error: {0}")]
    Json(#[from] JSONError),
    /// Failed to decode the `solc` bytecode hex.
    #[error("invalid bytecode hex: {0}")]
    Hex(#[from] FromHexError),
    /// `solc` reported a compilation failure, or produced no bytecode.
    #[error("solc compilation failed: {0}")]
    Solc(String),
    /// The compiled contract has no function with the requested name.
    #[error("no function named `{0}` in the compiled contract")]
    UnknownFunction(String),
}

#[derive(Deserialize)]
struct Output {
    #[serde(default)]
    errors: Vec<OutputError>,
    #[serde(default)]
    contracts: HashMap<String, HashMap<String, OutputContract>>,
}

#[derive(Deserialize)]
struct OutputError {
    severity: String,
    #[serde(rename = "formattedMessage")]
    formatted_message: String,
}

#[derive(Deserialize)]
struct OutputContract {
    evm: OutputEvm,
}

#[derive(Deserialize)]
struct OutputEvm {
    bytecode: OutputBytecode,
    #[serde(rename = "methodIdentifiers")]
    method_identifiers: HashMap<String, String>,
}

#[derive(Deserialize)]
struct OutputBytecode {
    object: String,
}

/// [`SolidityCompiler`] contains a handle to a Solidity compiler for compiling
/// rendered verifier contracts in tests.
pub struct SolidityCompiler {
    solc: String,
}

impl Default for SolidityCompiler {
    fn default() -> Self {
        Self::new("solc")
    }
}

impl SolidityCompiler {
    /// [`SolidityCompiler::new`] creates a compiler that uses a specific `solc`
    /// binary (a path, or a command on `PATH`).
    pub fn new(solc: impl Into<String>) -> Self {
        Self { solc: solc.into() }
    }

    /// [`SolidityCompiler::available`] tries to invoke the compiler and returns
    /// whether the invocation is successful.
    pub fn available(&self) -> bool {
        Command::new(&self.solc)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// [`SolidityCompiler::compile`] compiles `sources`, which is a list of
    /// file name and solidity code pairs, retrieves the compilation results for
    /// `contract`, and returns its bytecode and function selectors.
    pub fn compile(
        &self,
        sources: Vec<(impl Into<String>, impl Into<String>)>,
        contract: impl Into<String>,
    ) -> Result<(Bytes, HashMap<String, [u8; 4]>), Error> {
        let contract = &contract.into();

        let input = json!({
            "language": "Solidity",
            "sources": sources
                .into_iter()
                .map(|(name, src)| (name.into(), json!({ "content": src.into() })))
                .collect::<HashMap<_, _>>(),
            "settings": {
                "optimizer": { "enabled": true, "runs": 200 },
                "outputSelection": {
                    "*": { "*": ["evm.bytecode.object", "evm.methodIdentifiers"] },
                },
            },
        });

        let mut child = Command::new(&self.solc)
            .arg("--standard-json")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| Error::Solc("failed to open solc stdin".into()))?
            .write_all(&to_vec(&input)?)?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(Error::Solc(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }

        let output: Output = from_slice(&out.stdout)?;
        if let Some(e) = output.errors.iter().find(|e| e.severity == "error") {
            return Err(Error::Solc(e.formatted_message.clone()));
        }

        let evm = output
            .contracts
            .into_values()
            .find_map(|mut cs| cs.remove(contract))
            .map(|c| c.evm)
            .ok_or_else(|| Error::Solc(format!("no output for `{contract}`")))?;

        Ok((
            decode(evm.bytecode.object)?.into(),
            evm.method_identifiers
                .into_iter()
                .map(|(sig, sel)| {
                    // `sig` ("name(types)") -> name
                    let name = sig.split('(').next().unwrap_or(&sig).to_string();
                    // `sel` (hex string) -> bytes
                    let bytes: [u8; 4] = decode(&sel)?
                        .try_into()
                        .map_err(|_| Error::Solc(format!("bad selector for `{sig}`")))?;
                    Ok((name, bytes))
                })
                .collect::<Result<_, Error>>()?,
        ))
    }
}
