use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashSet},
    hash::{Hash, Hasher},
    ops::Deref,
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::PROXY_INTEGRITY_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const INITIALIZE_SELECTOR: [u8; 4] = [0x81, 0x29, 0xfc, 0x1c]; // initialize()
const UPGRADE_TO_SELECTOR: [u8; 4] = [0x36, 0x59, 0xcf, 0xe6]; // upgradeTo(address)
const UPGRADE_TO_AND_CALL_SELECTOR: [u8; 4] = [0x4f, 0x1e, 0xf2, 0x86]; // upgradeToAndCall(address,bytes)
const CHANGE_ADMIN_SELECTOR: [u8; 4] = [0x8f, 0x28, 0x39, 0x70]; // changeAdmin(address)

// EIP-1967 storage slots come from the crate-canonical, keccak-verified
// constants (`crate::evm::EIP1967_*_SLOT`).

fn sub_bug_idx(target: &EVMAddress, tag: u8) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    tag.hash(&mut hasher);
    (hasher.finish() << 8) + PROXY_INTEGRITY_BUG_IDX
}

/// Detects two distinct upgradeable-proxy integrity bugs, both black-box:
///
/// 1. **Reinitialization**: a no-arg `initialize()` (the near-universal
///    OpenZeppelin `Initializable` selector) succeeding more than once on
///    the same contract. A correct initializer guard must reject every call
///    after the first, so a second success is proof the guard is missing
///    or broken -- a classic "anyone can re-initialize and take over"
///    primitive (Wormhole/Audius-class bugs start here).
///
/// 2. **Storage collision on the EIP-1967 slots**: the implementation or
///    admin storage slot changes as a side effect of a call whose selector
///    isn't one of the expected `upgradeTo`/`upgradeToAndCall`/
///    `changeAdmin`/`initialize` functions. That means some unrelated
///    function's own variable layout overlaps the reserved proxy slot and
///    corrupted it -- a storage-layout bug, independent of who called it
///    (unlike `AccessControlOracle`, which instead checks whether an
///    intentional upgrade call was authorized).
pub struct ProxyIntegrityOracle {
    initialized_once: RefCell<HashSet<EVMAddress>>,
    static_layout_checked: RefCell<HashSet<EVMAddress>>,
}

impl Default for ProxyIntegrityOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyIntegrityOracle {
    pub fn new() -> Self {
        Self {
            initialized_once: RefCell::new(HashSet::new()),
            static_layout_checked: RefCell::new(HashSet::new()),
        }
    }
}

impl
    Oracle<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
        EVMQueueExecutor,
    > for ProxyIntegrityOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let calldata = ctx.input.to_bytes();

        // A control-leak (post-execution) state is an INTERMEDIATE state:
        // feedback.rs's OracleFeedback unconditionally discards any oracle()
        // result produced on it, yet the one-shot bookkeeping below would
        // still be committed -- permanently suppressing the real, finished
        // execution that surfaces this finding (the same bug the sibling
        // oracles already guard against). Defer instead.
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }
        let target = ctx.input.get_contract();
        let mut violations = vec![];

        let selector: Option<[u8; 4]> = (calldata.len() >= 4).then(|| calldata[0..4].try_into().unwrap());

        // --- Check 1: reinitialization ---
        if selector == Some(INITIALIZE_SELECTOR) {
            let mut seen = self.initialized_once.borrow_mut();
            if seen.contains(&target) {
                let caller = ctx.input.get_caller();
                let bug_idx = sub_bug_idx(&target, 0);
                EVMBugResult::new_simple(
                    "Proxy Reinitialization".to_string(),
                    bug_idx,
                    format!(
                        "initialize() on {:?} succeeded again (caller {:?}) -- the initializer guard is missing or broken, allowing anyone to re-run initialization and potentially take ownership/admin.\n",
                        target, caller
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                )
                .push_to_output();
                violations.push(bug_idx);
            } else {
                seen.insert(target);
            }
        }

        // --- Check 2: EIP-1967 slot storage collision ---
        let is_expected_slot_writer = matches!(
            selector,
            Some(UPGRADE_TO_SELECTOR) | Some(UPGRADE_TO_AND_CALL_SELECTOR) | Some(CHANGE_ADMIN_SELECTOR) | Some(INITIALIZE_SELECTOR)
        );
        if !is_expected_slot_writer {
            let implementation_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_IMPLEMENTATION_SLOT);
            let admin_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_ADMIN_SLOT);

            let get_slot = |state: &EVMState, slot: &EVMU256| {
                state.state.get(&target).and_then(|m| m.get(slot).copied()).unwrap_or(EVMU256::ZERO)
            };

            let selector_hex = selector.map(hex::encode).unwrap_or_else(|| "none".to_string());

            let impl_pre = get_slot(ctx.pre_state, &implementation_slot);
            let impl_post = get_slot(&ctx.post_state, &implementation_slot);
            if impl_pre != impl_post {
                let bug_idx = sub_bug_idx(&target, 1);
                EVMBugResult::new_simple(
                    "Proxy Storage Collision".to_string(),
                    bug_idx,
                    format!(
                        "{:?}'s EIP-1967 implementation slot changed from {:?} to {:?} as a side effect of an unrelated call (selector 0x{}, not upgradeTo/upgradeToAndCall/changeAdmin/initialize) -- the proxy's and implementation's storage layouts likely overlap.\n",
                        target, impl_pre, impl_post, selector_hex
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                )
                .push_to_output();
                violations.push(bug_idx);
            }

            let admin_pre = get_slot(ctx.pre_state, &admin_slot);
            let admin_post = get_slot(&ctx.post_state, &admin_slot);
            if admin_pre != admin_post {
                let bug_idx = sub_bug_idx(&target, 2);
                EVMBugResult::new_simple(
                    "Proxy Storage Collision".to_string(),
                    bug_idx,
                    format!(
                        "{:?}'s EIP-1967 admin slot changed from {:?} to {:?} as a side effect of an unrelated call (selector 0x{}, not upgradeTo/upgradeToAndCall/changeAdmin/initialize) -- the proxy's and implementation's storage layouts likely overlap.\n",
                        target, admin_pre, admin_post, selector_hex
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                )
                .push_to_output();
                violations.push(bug_idx);
            }
        }

        // --- Check 3: static storage layout comparison ---
        // Unlike checks 1/2 above (both need a specific call to actually
        // happen during fuzzing), this runs ONCE per proxy address, the
        // first time its EIP-1967 implementation slot is observed
        // non-zero -- a pure bytecode comparison, no further execution
        // needed. Complements `StorageCollisionOracle`
        // (middlewares/storage_collision.rs's dynamic detector, which
        // needs the fuzzer to actually witness both contracts write the
        // SAME slot at some point in the campaign): this catches the
        // same bug class even if neither write path is ever exercised.
        {
            let implementation_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_IMPLEMENTATION_SLOT);
            let impl_addr_raw = ctx.post_state.state.get(&target).and_then(|m| m.get(&implementation_slot).copied());
            if let Some(impl_addr_raw) = impl_addr_raw {
                if impl_addr_raw != EVMU256::ZERO && !self.static_layout_checked.borrow().contains(&target) {
                    self.static_layout_checked.borrow_mut().insert(target);
                    let implementation = crate::evm::types::convert_u256_to_h160(impl_addr_raw);
                    // A proxy pointing its own implementation slot at
                    // itself is already a separate, degenerate bug on
                    // its own (every delegatecall would recurse); "it
                    // collides with itself" would just be vacuous noise
                    // on top of that, not a useful layout finding.
                    if implementation == target {
                        return violations;
                    }
                    let admin_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_ADMIN_SLOT);

                    let executor = ctx.executor.deref().borrow();
                    let proxy_code = executor.host.code.get(&target).cloned();
                    let impl_code = executor.host.code.get(&implementation).cloned();
                    drop(executor);

                    if let (Some(proxy_code), Some(impl_code)) = (proxy_code, impl_code) {
                        let as_bytecode = |locked: &std::sync::Arc<revm_interpreter::BytecodeLocked>| {
                            revm_primitives::Bytecode::new_raw(bytes::Bytes::copy_from_slice(locked.original_bytecode_slice()))
                        };
                        let proxy_slots = crate::evm::bytecode_analyzer::find_literal_sstore_slots(&as_bytecode(&proxy_code));
                        let impl_slots = crate::evm::bytecode_analyzer::find_literal_sstore_slots(&as_bytecode(&impl_code));
                        let overlap: Vec<EVMU256> = proxy_slots
                            .intersection(&impl_slots)
                            .filter(|s| **s != implementation_slot && **s != admin_slot)
                            .copied()
                            .collect();

                        if !overlap.is_empty() {
                            let bug_idx = sub_bug_idx(&target, 3);
                            EVMBugResult::new_simple(
                                "Proxy Storage Collision".to_string(),
                                bug_idx,
                                format!(
                                    "{target:?} (proxy) and its implementation {implementation:?} both directly write to storage slot(s) {overlap:?} via a literal SSTORE -- a static bytecode comparison, independent of whether either write path has actually been exercised yet. A top-level state variable in the implementation almost certainly aliases a variable the proxy itself uses (or a different implementation variable, across an upgrade) at this exact slot number -- writing one will silently corrupt the other.\n",
                                ),
                                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                            )
                            .push_to_output();
                            violations.push(bug_idx);
                        }
                    }
                }
            }
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::evm::{
        abi::{AEmpty, BoxedABI},
        host::FuzzHost,
        input::EVMInputTy,
        mutator::AccessPattern,
        scheduler::PowerABIScheduler,
        types::{generate_random_address, EVMQueueExecutor},
        vm::{EVMExecutor, PostExecutionCtx},
    };
    use crate::state::FuzzState;
    use crate::state_input::StagedVMState;

    /// Run the oracle on an `initialize()` call and report whether it
    /// committed `initialized_once` (its first observable write). On a
    /// post-execution (control-leak) state feedback.rs discards the output,
    /// so the commit must NOT happen -- otherwise the real, finished
    /// reinitialization call is permanently suppressed.
    fn commits_initialized_once(post_execution: bool) -> bool {
        let path = std::path::Path::new("work_dir");
        if !path.exists() {
            let _ = std::fs::create_dir(path);
        }
        let mut state: EVMFuzzState = FuzzState::new(0);
        let deployer = generate_random_address(&mut state);
        let executor: Rc<RefCell<EVMQueueExecutor>> = Rc::new(RefCell::new(EVMExecutor::new(
            FuzzHost::new(PowerABIScheduler::new(), "work_dir".to_string()),
            deployer,
        )));

        let target = generate_random_address(&mut state);
        let caller = generate_random_address(&mut state);

        let mut evm_state = EVMState::new();
        if post_execution {
            evm_state.post_execution.push(PostExecutionCtx {
                constraints: vec![],
                pes: vec![],
                must_step: false,
            });
        }
        state.get_execution_result_mut().new_state = StagedVMState::new_with_state(evm_state);

        let mut abi = BoxedABI::new(Box::new(AEmpty {}));
        abi.set_func(INITIALIZE_SELECTOR);
        let input = EVMInput {
            caller,
            contract: target,
            data: Some(abi),
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: bytes::Bytes::new(),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: std::collections::HashMap::new(),
        };

        let pre_state = input.get_state().clone();
        let oracle = ProxyIntegrityOracle::new();
        let mut ctx: EVMOracleCtx<'_> =
            EVMOracleCtx::new(&mut state, &pre_state, executor.clone(), &input);
        let _ = oracle.oracle(&mut ctx, 0);

        oracle.initialized_once.borrow().contains(&target)
    }

    #[test]
    fn post_execution_state_does_not_commit_bookkeeping() {
        assert!(
            !commits_initialized_once(true),
            "oracle committed initialized_once on an INTERMEDIATE (control-leak) \
             state -- the guard is missing or misplaced"
        );
    }

    #[test]
    fn finished_state_still_runs_the_oracle() {
        assert!(
            commits_initialized_once(false),
            "oracle bailed on a FINISHED execution -- the guard is over-broad"
        );
    }
}
