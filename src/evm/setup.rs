//! Declarative pre-fuzzing setup calls (`setup.json`).
//!
//! Some classes of bug are only reachable once the contracts under test are
//! already wired together -- an ERC4626 vault whose `asset` still points at
//! `0x0`, a pair that has never been initialized, a pool with no liquidity.
//! A black-box fuzzer that starts from a blank deployment has to discover the
//! *precondition* (`setAsset(realToken)`, a first `deposit`, ...) by chance
//! before it can even attempt the exploit, and that conjunction is routinely
//! out of reach in a short campaign.
//!
//! `setup.json`, placed next to a fixture's `.bin`/`.abi` files, lets the
//! fixture declare those precondition calls explicitly. They are executed
//! once, against the freshly-deployed state, *before* fuzzing begins -- so
//! the campaign starts from the already-wired state and only has to find the
//! exploit itself.
//!
//! Format:
//! ```json
//! { "calls": [
//!   { "to": "Vault",  "sig": "setAsset(address)",        "args": ["Token"] },
//!   { "to": "Token",  "sig": "mint(address,uint256)",    "args": ["$caller", "1000000"] },
//!   { "to": "Vault",  "sig": "deposit(uint256,address)", "args": ["1000", "$caller"] }
//! ] }
//! ```
//!
//! `to` and any address-typed argument accept either a deployed contract name
//! (matched against the fixture's file stem, e.g. `Vault`) or one of the
//! placeholders `$caller` (the first fuzzing caller) / `$deployer`.

use std::collections::HashMap;
use std::path::Path;

use alloy_dyn_abi::{JsonAbiExt, Specifier};
use alloy_json_abi::Function;
use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::InstructionResult;
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::evm::input::ConciseEVMInput;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMU256};
use crate::evm::vm::{EVMExecutor, EVMState};

/// A single declared setup call.
#[derive(Debug, Clone, Deserialize)]
pub struct SetupCall {
    /// Target: a deployed contract name (fixture file stem) or `$deployer`.
    pub to: String,
    /// Human-readable signature, e.g. `setAsset(address)`.
    pub sig: String,
    /// Arguments, one per ABI input. Address-typed args accept a contract name
    /// or `$caller` / `$deployer`; everything else is passed to the ABI
    /// encoder as a literal.
    #[serde(default)]
    pub args: Vec<String>,
}

/// The parsed contents of a `setup.json`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SetupSpec {
    #[serde(default)]
    pub calls: Vec<SetupCall>,
}

impl SetupSpec {
    /// Parse a `setup.json` file. Returns `None` (with a logged error) on any
    /// read/parse failure rather than aborting the campaign -- a malformed
    /// fixture helper should not take down fuzzing.
    pub fn from_file(path: &Path) -> Option<Self> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to read setup file {}: {}", path.display(), e);
                return None;
            }
        };
        match serde_json::from_str::<SetupSpec>(&content) {
            Ok(spec) => Some(spec),
            Err(e) => {
                error!("Failed to parse setup file {}: {}", path.display(), e);
                None
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }
}

/// Resolve a single argument string for a given ABI input type.
///
/// Address-typed arguments are the interesting case: they may name a deployed
/// contract (`Vault`) or a placeholder (`$caller`/`$deployer`), both of which
/// we turn into a concrete `0x...` string before handing it to the ABI encoder.
fn resolve_arg(
    raw: &str,
    is_address: bool,
    name_to_addr: &HashMap<String, EVMAddress>,
    caller: EVMAddress,
    deployer: EVMAddress,
) -> Option<String> {
    if !is_address {
        return Some(raw.to_string());
    }

    if let Some(stripped) = raw.strip_prefix('$') {
        return match stripped {
            "caller" => Some(format!("0x{}", hex::encode(caller))),
            "deployer" => Some(format!("0x{}", hex::encode(deployer))),
            _ => {
                warn!("Unknown setup placeholder '{}' -- treating as literal address", raw);
                Some(raw.to_string())
            }
        };
    }

    if raw.starts_with("0x") {
        return Some(raw.to_string());
    }

    match name_to_addr.get(raw) {
        Some(addr) => Some(format!("0x{}", hex::encode(addr))),
        None => {
            error!(
                "Setup call references unknown contract '{}' -- no deployed contract with that name",
                raw
            );
            None
        }
    }
}

/// Build the map from contract name (both the full glob prefix and its file
/// stem) to deployed address, so `setup.json` can say `"Vault"` instead of a
/// hardcoded address.
pub fn name_to_address_map(
    contracts: &[crate::evm::contract_utils::ContractInfo],
) -> HashMap<String, EVMAddress> {
    let mut map = HashMap::new();
    for c in contracts {
        map.insert(c.name.clone(), c.deployed_address);
        if let Some(stem) = c.name.split('/').next_back() {
            let stem = stem.trim_end_matches('*');
            map.insert(stem.to_string(), c.deployed_address);
        }
    }
    map
}

/// Execute every declared setup call against the freshly-deployed state.
///
/// Runs before `initialize_corpus`, so the resulting state becomes the
/// campaign's `initial_state`. Each call is best-effort: a call that reverts
/// is logged and skipped, never fatal.
pub fn run_setup_calls<SC>(
    executor: &mut EVMExecutor<EVMState, ConciseEVMInput, SC>,
    state: &mut EVMFuzzState,
    spec: &SetupSpec,
    contracts: &[crate::evm::contract_utils::ContractInfo],
) where
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    if spec.is_empty() {
        return;
    }

    let name_to_addr = name_to_address_map(contracts);
    let deployer = executor.deployer;
    let caller = state
        .callers_pool
        .first()
        .cloned()
        .unwrap_or(deployer);

    // Operate on a local copy of the state and write it back once at the end,
    // so `fast_call_` (which borrows the executor) and `state` don't alias.
    let mut vmstate = executor.host.evmstate.clone();

    for (i, call) in spec.calls.iter().enumerate() {
        let target = match name_to_addr.get(&call.to) {
            Some(addr) => *addr,
            None => {
                error!(
                    "setup.json call #{}: unknown target contract '{}' -- skipping",
                    i, call.to
                );
                continue;
            }
        };

        let function = match Function::parse(&call.sig) {
            Ok(f) => f,
            Err(e) => {
                error!("setup.json call #{}: bad signature '{}': {}", i, call.sig, e);
                continue;
            }
        };

        if function.inputs.len() != call.args.len() {
            error!(
                "setup.json call #{}: '{}' expects {} arg(s), got {} -- skipping",
                i,
                call.sig,
                function.inputs.len(),
                call.args.len()
            );
            continue;
        }

        let mut values = Vec::with_capacity(call.args.len());
        let mut ok = true;
        for (arg, param) in call.args.iter().zip(function.inputs.iter()) {
            let ty = match param.resolve() {
                Ok(t) => t,
                Err(e) => {
                    error!("setup.json call #{}: cannot resolve input type: {}", i, e);
                    ok = false;
                    break;
                }
            };
            let is_address = matches!(ty, alloy_dyn_abi::DynSolType::Address);
            let resolved = match resolve_arg(arg, is_address, &name_to_addr, caller, deployer) {
                Some(s) => s,
                None => {
                    ok = false;
                    break;
                }
            };
            match ty.coerce_str(&resolved) {
                Ok(v) => values.push(v),
                Err(e) => {
                    error!(
                        "setup.json call #{}: cannot coerce '{}' for '{}': {}",
                        i, arg, call.sig, e
                    );
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }

        let calldata = match function.abi_encode_input(&values) {
            Ok(d) => d,
            Err(e) => {
                error!("setup.json call #{}: ABI encode failed for '{}': {}", i, call.sig, e);
                continue;
            }
        };

        let (ret, result) = executor.fast_call_(
            target,
            Bytes::from(calldata),
            &mut vmstate,
            state,
            EVMU256::ZERO,
            caller,
        );

        if matches!(result, InstructionResult::Return | InstructionResult::Stop) {
            info!(
                "setup.json call #{}: {}.{} OK ({} bytes returned)",
                i,
                call.to,
                call.sig,
                ret.len()
            );
        } else {
            warn!(
                "setup.json call #{}: {}.{} did not succeed ({:?}) -- continuing",
                i, call.to, call.sig, result
            );
        }
    }

    executor.host.evmstate = vmstate;
    info!("Applied {} setup.json call(s) before fuzzing", spec.calls.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::types::fixed_address;

    fn addr_map() -> HashMap<String, EVMAddress> {
        let mut m = HashMap::new();
        m.insert("Vault".to_string(), fixed_address("0374004a00b3990a17ca0e76bc5ca8ca84855756"));
        m.insert("tests/evm/erc4626/Asset*".to_string(), fixed_address("887db5715868498cff494b5dcc8eda6ce5b7652a"));
        m
    }

    #[test]
    fn resolves_contract_name_to_address() {
        let m = addr_map();
        let caller = fixed_address("35c9dfd76bf02107ff4f7128bd69716612d31ddb");
        let deployer = fixed_address("8b21e662154b4bbc1ec0754d0238875fe3d22fa6");
        let out = resolve_arg("Vault", true, &m, caller, deployer).unwrap();
        assert_eq!(out, "0x0374004a00b3990a17ca0e76bc5ca8ca84855756");
    }

    #[test]
    fn resolves_placeholders() {
        let m = addr_map();
        let caller = fixed_address("35c9dfd76bf02107ff4f7128bd69716612d31ddb");
        let deployer = fixed_address("8b21e662154b4bbc1ec0754d0238875fe3d22fa6");
        assert_eq!(
            resolve_arg("$caller", true, &m, caller, deployer).unwrap(),
            format!("0x{}", hex::encode(caller))
        );
        assert_eq!(
            resolve_arg("$deployer", true, &m, caller, deployer).unwrap(),
            format!("0x{}", hex::encode(deployer))
        );
    }

    #[test]
    fn unknown_contract_name_is_rejected() {
        let m = addr_map();
        let caller = fixed_address("35c9dfd76bf02107ff4f7128bd69716612d31ddb");
        assert!(resolve_arg("Nope", true, &m, caller, caller).is_none());
    }

    #[test]
    fn non_address_args_pass_through() {
        let m = addr_map();
        let caller = fixed_address("35c9dfd76bf02107ff4f7128bd69716612d31ddb");
        assert_eq!(resolve_arg("1000", false, &m, caller, caller).unwrap(), "1000");
    }

    #[test]
    fn setup_spec_parses_the_fixture_shape() {
        let json = r#"{ "calls": [
            { "to": "Vault", "sig": "setAsset(address)", "args": ["Asset"] },
            { "to": "Asset", "sig": "mint(address,uint256)", "args": ["$caller", "1000"] }
        ] }"#;
        let spec: SetupSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.calls.len(), 2);
        assert_eq!(spec.calls[0].to, "Vault");
        assert_eq!(spec.calls[0].sig, "setAsset(address)");
        assert_eq!(spec.calls[0].args, vec!["Asset".to_string()]);
        assert_eq!(spec.calls[1].args.len(), 2);
    }

    #[test]
    fn setup_spec_defaults_to_empty() {
        let spec: SetupSpec = serde_json::from_str("{}").unwrap();
        assert!(spec.is_empty());
    }

    #[test]
    fn signature_encodes_to_expected_selector() {
        // setAsset(address) == 0xd0d552dd
        let f = Function::parse("setAsset(address)").unwrap();
        assert_eq!(hex::encode(f.selector().as_slice()), "d0d552dd");
    }
}
