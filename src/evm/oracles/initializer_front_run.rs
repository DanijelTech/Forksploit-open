use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    ops::Deref,
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::INITIALIZER_FRONT_RUN_BUG_IDX,
        types::{convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_executor::GenericVM,
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const INITIALIZE_SELECTOR: [u8; 4] = [0x81, 0x29, 0xfc, 0x1c]; // initialize()
const OWNER_SELECTOR: [u8; 4] = [0x8d, 0xa5, 0xcb, 0x5b]; // owner()

fn sub_bug_idx(target: &EVMAddress, tag: u8) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    tag.hash(&mut hasher);
    (hasher.finish() << 8) + INITIALIZER_FRONT_RUN_BUG_IDX
}

/// Detects initializer front-running: the no-arg `initialize()` selector
/// (the near-universal OpenZeppelin `Initializable` entry point) succeeding
/// and granting ownership/admin to a caller that is NOT the fuzzer's
/// configured deployer, on a contract that had no owner/admin set
/// beforehand (freshly deployed, never initialized).
///
/// This is distinct from the two existing proxy checks:
/// - `AccessControlOracle` explicitly skips the "owner was unset" case, because
///   a *correctly* used initializer also looks like "owner went from zero to
///   someone" -- that oracle only cares about changes to an *already-set*
///   owner.
/// - `ProxyIntegrityOracle` only flags a *second* successful `initialize()`
///   call (reinitialization), not a first call won by the wrong party.
///
/// Comparing the caller against the fuzzer's own deployer address is what
/// makes this safe to run without false-positiving on every normal
/// deploy-then-initialize flow: if the deployer itself calls `initialize()`
/// first (the intended, correct sequence), nothing is flagged. Only a
/// *different* address winning that race is reported -- the real-world
/// Wormhole/Audius-class bug, where anyone can call `initialize()` on a
/// freshly deployed, not-yet-initialized implementation/proxy and take over
/// before the legitimate owner does.
pub struct InitializerFrontRunOracle;

impl Default for InitializerFrontRunOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl InitializerFrontRunOracle {
    pub fn new() -> Self {
        Self
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
    > for InitializerFrontRunOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let calldata = ctx.input.to_bytes();
        let selector: Option<[u8; 4]> = (calldata.len() >= 4).then(|| calldata[0..4].try_into().unwrap());
        if selector != Some(INITIALIZE_SELECTOR) {
            return vec![];
        }

        let target = ctx.input.get_contract();
        let caller = ctx.input.get_caller();
        let deployer = ctx.executor.deref().borrow().deployer;
        if caller == deployer {
            // The legitimate deployer calling its own initializer is the
            // intended, correct sequence -- nothing to flag.
            return vec![];
        }

        let mut violations = vec![];

        // --- Check 1: owner() claimed via initialize() by a non-deployer ---
        let probe_calls = [(target, Bytes::from(OWNER_SELECTOR.to_vec()))];
        let owner_pre_raw =
            ctx.executor
                .deref()
                .borrow_mut()
                .fast_static_call(&probe_calls, ctx.pre_state, ctx.fuzz_state);
        let owner_post_raw = ctx.call_post_batch(&probe_calls);

        let owner_pre = (owner_pre_raw[0].len() == 32)
            .then(|| EVMU256::try_from_be_slice(&owner_pre_raw[0]))
            .flatten()
            .map(convert_u256_to_h160);
        let owner_post = (owner_post_raw[0].len() == 32)
            .then(|| EVMU256::try_from_be_slice(&owner_post_raw[0]))
            .flatten()
            .map(convert_u256_to_h160);

        if owner_pre == Some(EVMAddress::default()) && owner_post == Some(caller) {
            let bug_idx = sub_bug_idx(&target, 0);
            EVMBugResult::new_simple(
                "Initializer Front-Running".to_string(),
                bug_idx,
                format!(
                    "initialize() on {:?} was called by {:?} (NOT the deployer {:?}) while owner() was still unset, and it set owner() to the caller -- anyone can race the deployer to claim ownership of a freshly deployed, not-yet-initialized contract.\n",
                    target, caller, deployer
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }

        // --- Check 2: EIP-1967 admin slot claimed via initialize() by a non-deployer
        // ---
        let admin_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_ADMIN_SLOT);
        let get_slot = |state: &EVMState, slot: &EVMU256| {
            state
                .state
                .get(&target)
                .and_then(|m| m.get(slot).copied())
                .unwrap_or(EVMU256::ZERO)
        };
        let admin_pre = get_slot(ctx.pre_state, &admin_slot);
        let admin_post = get_slot(&ctx.post_state, &admin_slot);
        let mut caller_bytes = [0u8; 32];
        caller_bytes[12..32].copy_from_slice(caller.as_slice());
        let caller_as_slot = EVMU256::from_be_bytes(caller_bytes);

        if admin_pre == EVMU256::ZERO && admin_post == caller_as_slot {
            let bug_idx = sub_bug_idx(&target, 1);
            EVMBugResult::new_simple(
                "Initializer Front-Running".to_string(),
                bug_idx,
                format!(
                    "initialize() on {:?} was called by {:?} (NOT the deployer {:?}) while the EIP-1967 admin slot was still unset, and it set that slot to the caller -- anyone can race the deployer to claim proxy admin of a freshly deployed, not-yet-initialized proxy.\n",
                    target, caller, deployer
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }

        violations
    }
}
