//! Auto-derivation of wiring preconditions (`--auto-setup`).
//!
//! `setup.json` (see `crate::evm::setup`) removes the "discover the
//! precondition by chance" problem, but it must be written by hand, and the
//! `--target 0x...` path has no fixture directory to read it from at all.
//! This module closes the *mechanical* part of that gap: it derives the
//! wiring calls that connect deployed contracts to each other, directly from
//! the deployed contract set, so a multi-contract target no longer needs a
//! hand-written `setup.json` for the "setAsset(address)"-style links.
//!
//! What it derives (and what it deliberately does NOT):
//!
//! * DERIVED: for every deployed contract `C` that exposes a one-`address`
//!   setter (`setX(address)`, non-static), a call wiring that setter to
//!   another deployed contract -- preferring an address `C`'s own bytecode
//!   already references, otherwise any other deployed contract.
//! * NOT DERIVED: value-moving seeds (`mint(...)`, `deposit(...)`). Those
//!   depend on the target's own economics and cannot be guessed from
//!   signatures alone without risking a wrong, misleading precondition.
//!   A target that also needs a funding step still needs it written by hand
//!   (or supplied via `--setup-file`). This is a real, documented limit, not
//!   a silent one.
//!
//! Derivation is pure over the deployed contracts + their bytecode/ABI, so it
//! is unit-testable without a network or an EVM.

use crate::evm::contract_utils::ContractInfo;
use crate::evm::setup::{SetupCall, SetupSpec};
use crate::evm::types::EVMAddress;

/// Addresses `1..=10` are the EVM precompiles; they are never "contracts to
/// wire to" and must not be mistaken for external references.
const PRECOMPILE_MAX: u64 = 10;

/// Walk the runtime bytecode and collect every 20-byte constant pushed by
/// `PUSH20` (`0x73`). These are the addresses the contract was compiled to
/// refer to (as opposed to addresses computed at run time), so they are the
/// strongest static signal of "which other contracts this one points at".
pub fn scan_embedded_addresses(code: &[u8]) -> Vec<EVMAddress> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0usize;
    while i < code.len() {
        let op = code[i];
        if op == 0x73 {
            // PUSH20
            if i + 20 < code.len() {
                let word = &code[i + 1..i + 21];
                let addr = EVMAddress::from_slice(word);
                if !is_zero(&addr) && !is_precompile(&addr) && seen.insert(addr) {
                    out.push(addr);
                }
            }
            i += 21;
        } else if (0x60..=0x7f).contains(&op) {
            // PUSH1..PUSH32 -- skip the immediate data so a `0x73` byte that
            // is really push data is not mistaken for an opcode.
            i += 1 + (op as usize - 0x5f);
        } else {
            i += 1;
        }
    }
    out
}

fn is_zero(addr: &EVMAddress) -> bool {
    addr.as_slice().iter().all(|b| *b == 0)
}

fn is_precompile(addr: &EVMAddress) -> bool {
    // Precompiles live in the lowest addresses; treat anything with a
    // non-zero byte above the first as "not a precompile" cheaply.
    let bytes = addr.as_slice();
    if bytes[..19].iter().any(|b| *b != 0) {
        return false;
    }
    (bytes[19] as u64) <= PRECOMPILE_MAX
}

/// Derive a wiring `SetupSpec` from the deployed contract set.
///
/// Deterministic (no hashing order dependence in the output): contracts are
/// visited in their declared order and the first qualifying setter per
/// contract wins, so the result is stable run to run.
pub fn derive_setup_spec(contracts: &[ContractInfo]) -> SetupSpec {
    let deployed: Vec<EVMAddress> = contracts.iter().map(|c| c.deployed_address).collect();

    let mut calls: Vec<SetupCall> = Vec::new();
    let mut emitted: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for c in contracts {
        // Addresses this contract's own bytecode already references and that
        // are themselves deployed contracts -- the most likely wiring targets.
        let embedded = scan_embedded_addresses(&c.code);
        let embedded_deployed: Vec<EVMAddress> = embedded
            .iter()
            .copied()
            .filter(|a| *a != c.deployed_address && deployed.contains(a))
            .collect();

        for f in &c.abi {
            if f.is_static || f.is_payable || f.is_constructor {
                continue;
            }
            // Exactly one `address` argument is the wiring shape.
            if f.abi != "(address)" {
                continue;
            }
            if !f.function_name.to_ascii_lowercase().starts_with("set") {
                continue;
            }

            // Prefer a contract this one already references; otherwise any
            // other deployed contract (a fresh, unset pointer still needs a
            // concrete address, and another deployed contract is the only
            // sensible guess available).
            let candidate = embedded_deployed
                .first()
                .copied()
                .or_else(|| deployed.iter().copied().find(|a| *a != c.deployed_address));
            let Some(candidate) = candidate else {
                continue;
            };

            let sig = format!("{}{}", f.function_name, f.abi);
            if !emitted.insert((c.name.clone(), sig.clone())) {
                continue;
            }
            calls.push(SetupCall {
                to: c.name.clone(),
                sig,
                args: vec![format!("0x{}", hex::encode(candidate))],
            });
        }
    }

    SetupSpec { calls }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::contract_utils::ABIConfig;

    fn abi_cfg(name: &str, abi: &str, is_static: bool, is_payable: bool) -> ABIConfig {
        ABIConfig {
            abi: abi.to_string(),
            function: [0; 4],
            function_name: name.to_string(),
            is_static,
            is_payable,
            is_constructor: false,
            should_add_corpus: true,
        }
    }

    fn contract(name: &str, addr: &str, code: Vec<u8>, abi: Vec<ABIConfig>) -> ContractInfo {
        ContractInfo {
            name: name.to_string(),
            code,
            abi,
            is_code_deployed: true,
            balance: crate::evm::types::EVMU256::ZERO,
            constructor_args: vec![],
            deployed_address: crate::evm::types::fixed_address(addr),
            build_artifact: None,
            files: vec![],
            source_map_replacements: None,
            raw_source_map: None,
        }
    }

    #[test]
    fn scan_finds_push20_and_skips_push_data() {
        // PUSH20 <addr> ; then PUSH1 0x73 (0x73 here is DATA, not an opcode)
        let addr = [0x11u8; 20];
        let mut code = vec![0x73];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x60, 0x73, 0x00]); // PUSH1 0x73, STOP
        let found = scan_embedded_addresses(&code);
        assert_eq!(found, vec![EVMAddress::from_slice(&addr)]);
    }

    #[test]
    fn scan_ignores_zero_and_precompiles() {
        let mut code = vec![0x73];
        code.extend_from_slice(&[0u8; 20]); // zero
        code.push(0x73);
        let mut pc = [0u8; 20];
        pc[19] = 0x04; // precompile 0x04
        code.extend_from_slice(&pc);
        assert!(scan_embedded_addresses(&code).is_empty());
    }

    #[test]
    fn derives_wiring_setter_to_other_deployed_contract() {
        let asset = contract("Asset", "887db5715868498cff494b5dcc8eda6ce5b7652a", vec![0x00], vec![]);
        // Vault has setAsset(address); its bytecode does not yet embed Asset
        // (asset is unset), so the other deployed contract is used.
        let vault = contract(
            "Vault",
            "0374004a00b3990a17ca0e76bc5ca8ca84855756",
            vec![0x00],
            vec![abi_cfg("setAsset", "(address)", false, false)],
        );
        let spec = derive_setup_spec(&[asset, vault]);
        assert_eq!(spec.calls.len(), 1);
        assert_eq!(spec.calls[0].to, "Vault");
        assert_eq!(spec.calls[0].sig, "setAsset(address)");
        assert_eq!(spec.calls[0].args, vec!["0x887db5715868498cff494b5dcc8eda6ce5b7652a".to_string()]);
    }

    #[test]
    fn prefers_address_the_code_already_references() {
        let asset_addr = crate::evm::types::fixed_address("887db5715868498cff494b5dcc8eda6ce5b7652a");
        let other_addr = crate::evm::types::fixed_address("e1a425f1ac34a8a441566f93c82dd730639c8510");
        let asset = contract("Asset", "887db5715868498cff494b5dcc8eda6ce5b7652a", vec![0x00], vec![]);
        let other = contract("Other", "e1a425f1ac34a8a441566f93c82dd730639c8510", vec![0x00], vec![]);
        // Vault's code embeds `asset_addr` (PUSH20 asset) even though both
        // Asset and Other are deployed.
        let mut code = vec![0x73];
        code.extend_from_slice(asset_addr.as_slice());
        let vault = contract(
            "Vault",
            "0374004a00b3990a17ca0e76bc5ca8ca84855756",
            code,
            vec![abi_cfg("setAsset", "(address)", false, false)],
        );
        let spec = derive_setup_spec(&[asset, other, vault]);
        assert_eq!(spec.calls.len(), 1);
        assert_eq!(
            spec.calls[0].args,
            vec![format!("0x{}", hex::encode(asset_addr))]
        );
        let _ = other_addr;
    }

    #[test]
    fn ignores_view_and_non_address_setters() {
        let a = contract("A", "887db5715868498cff494b5dcc8eda6ce5b7652a", vec![0x00], vec![]);
        let b = contract(
            "B",
            "0374004a00b3990a17ca0e76bc5ca8ca84855756",
            vec![0x00],
            vec![
                abi_cfg("setFee", "(uint256)", false, false), // not an address
                abi_cfg("getAsset", "(address)", true, false), // view
                abi_cfg("configure", "(address)", false, false), // not a "set*" name
            ],
        );
        assert!(derive_setup_spec(&[a, b]).calls.is_empty());
    }
}
