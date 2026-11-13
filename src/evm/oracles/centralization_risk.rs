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
        oracles::CENTRALIZATION_RISK_BUG_IDX,
        types::{convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const OWNER_SELECTOR: [u8; 4] = [0x8d, 0xa5, 0xcb, 0x5b]; // owner()

fn sub_bug_idx(target: &EVMAddress, selector: &[u8; 4]) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    selector.hash(&mut hasher);
    (hasher.finish() << 8) + CENTRALIZATION_RISK_BUG_IDX
}

/// Systematically maps a contract's "privileged surface": every distinct
/// function selector the fuzzer sees `owner()` successfully call is
/// re-probed with the exact same calldata from a non-privileged address
/// (the zero address, via a real -- not static -- call, so state-mutating
/// functions aren't rejected merely for being a mutation). If that probe
/// reverts while the real owner call succeeded, the function is genuinely
/// gated to the owner, and is reported once as part of the admin surface.
///
/// This directly answers the roadmap's "what can the owner role actually
/// do" question: instead of only surfacing a privileged function when the
/// fuzzer happens to also stumble into a profitable misuse of it (what
/// `AccessControlOracle`/`ArbitraryERC20TransferOracle` etc. already catch),
/// this builds a running catalogue of the admin surface as soon as each
/// owner-gated selector is tried even once -- whether or not calling it
/// looks "bad" by itself. These are reported as review items, not bugs:
/// a centralized owner is sometimes an accepted design, but it should be a
/// deliberate decision made before production, not a surprise.
///
/// Known limitation: the non-owner probe always uses zero `msg.value`, so a
/// payable owner-only function whose real call carried ETH is skipped
/// rather than risk a probe that reverts for the wrong reason (insufficient
/// value, not access control).
pub struct CentralizationRiskOracle {
    classified: RefCell<HashSet<(EVMAddress, [u8; 4])>>,
}

impl Default for CentralizationRiskOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl CentralizationRiskOracle {
    pub fn new() -> Self {
        Self {
            classified: RefCell::new(HashSet::new()),
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
    > for CentralizationRiskOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {

        // A control-leak (post-execution) state is an INTERMEDIATE state:
        // feedback.rs's OracleFeedback unconditionally discards any oracle()
        // result produced on it. Writing the one-shot "already reported"
        // bookkeeping below on such a state would permanently suppress the
        // real, finished execution that would surface this finding -- exactly
        // the bug the sibling oracles (self_referral, curve_virtual_price,
        // twap_manipulation, ...) already guard against. Defer instead.
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }
        let calldata = ctx.input.to_bytes();
        if calldata.len() < 4 {
            // No selector (plain ETH transfer / fallback) -- nothing to
            // catalogue as a named function on the admin surface.
            return vec![];
        }
        let selector: [u8; 4] = calldata[0..4].try_into().unwrap();
        let target = ctx.input.get_contract();
        let key = (target, selector);
        if self.classified.borrow().contains(&key) {
            return vec![];
        }

        // Only a non-payable call can be safely re-probed with zero value
        // without the probe reverting for the wrong reason.
        if ctx.input.get_txn_value().is_some_and(|v| v != EVMU256::ZERO) {
            return vec![];
        }

        let caller = ctx.input.get_caller();

        let owner_probe = [(target, Bytes::from(OWNER_SELECTOR.to_vec()))];
        let owner_raw = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&owner_probe, ctx.pre_state, ctx.fuzz_state);
        let owner = (owner_raw[0].len() == 32)
            .then(|| EVMU256::try_from_be_slice(&owner_raw[0]))
            .flatten()
            .map(convert_u256_to_h160);

        let owner = match owner {
            Some(o) if o != EVMAddress::default() => o,
            // No owner established yet -- nothing to compare the caller
            // against.
            _ => return vec![],
        };

        if caller != owner {
            // A non-owner successfully called this selector (oracle() only
            // runs on non-reverted executions), which already proves it is
            // NOT owner-gated. Nothing to report, and no further probing
            // needed for this selector.
            self.classified.borrow_mut().insert(key);
            return vec![];
        }

        // The real call just succeeded from the owner. Replay the exact
        // same calldata as a real (non-static) call from the zero address
        // against the pre-call state, so mutating logic executes normally
        // and only an actual access-control check can cause a revert.
        let probe = [(EVMAddress::default(), target, Bytes::from(calldata.to_vec()))];
        let (probe_results, _) = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_call(&probe, ctx.pre_state, ctx.fuzz_state);
        let (_, non_owner_succeeded) = &probe_results[0];

        self.classified.borrow_mut().insert(key);

        if *non_owner_succeeded {
            // Anyone could have called this -- not actually owner-gated.
            return vec![];
        }

        let bug_idx = sub_bug_idx(&target, &selector);
        EVMBugResult::new_simple(
            "Centralization Risk: Owner-Only Function".to_string(),
            bug_idx,
            format!(
                "{:?}'s function 0x{} succeeded when called by owner() ({:?}), but the identical call reverts for anyone else -- part of the privileged admin surface. Not a bug by itself: review whether this power (and anything else owner-gated on this contract) is appropriately scoped, time-locked, or multi-sig'd before production.\n",
                target, hex::encode(selector), owner
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
        )
        .push_to_output();

        vec![bug_idx]
    }
}
