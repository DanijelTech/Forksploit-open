use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashSet},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::TRANSIENT_GUARD_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    oracle::Oracle,
    state::HasExecutionResult,
};

fn sub_bug_idx(target: &EVMAddress) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    (hasher.finish() << 8) + TRANSIENT_GUARD_BUG_IDX
}

/// Detects an EIP-1153 transient-storage reentrancy guard that is RELEASED
/// (TSTORE 0) BEFORE an external CALL -- the guard's protection window
/// closes too early, so a reentrant callee can re-enter while the state is
/// still mid-update. This is the transient-storage analogue of the classic
/// "checks-effects-interactions violated" bug, and it is invisible to every
/// SSTORE-based oracle: `reentrancy.rs`/`stale_guard.rs` watch 0x54/0x55,
/// while modern V4-era guards use 0x5c/0x5d, which the host did not decode
/// at all before this oracle.
///
/// Real dataflow, not a proximity guess:
/// * `host.rs` 0x5c (TLOAD) records every transient slot read this call as a
///   candidate guard slot (`current_transient_loaded`).
/// * 0x5d (TSTORE) tracks lock/unlock transitions of those slots: a nonzero
///   write locks, a zero write to a previously-locked slot arms a pending
///   unlock (`current_transient_unlock`), and a re-lock cancels it.
/// * The CALL arm records a hit when an external CALL/STATICCALL executes
///   while a TLOAD'd guard slot is in the unlocked state
///   (`current_transient_unlock_calls`).
///
/// Review-tier: a contract can use transient storage for non-guard purposes
/// (e.g. a transient allowance), and an "unlock before call" is only
/// certainly a bug when the call target is untrusted. It points a human at
/// the exact unlock-then-call site, without claiming certainty.
pub struct TransientGuardOracle {
    reported: RefCell<HashSet<(EVMAddress, usize)>>,
}

impl Default for TransientGuardOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl TransientGuardOracle {
    pub fn new() -> Self {
        Self {
            reported: RefCell::new(HashSet::new()),
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
    > for TransientGuardOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        if ctx.post_state.transient_unlock_calls.is_empty() {
            return vec![];
        }

        // A control-leak leaves the call unfinished; its oracle() output is
        // discarded by the feedback layer, so recording "already reported"
        // here would swallow the finding (see oracles/forged_proof.rs).
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }

        let loaded = ctx.post_state.transient_loaded.clone();
        let hits: Vec<(EVMAddress, usize, EVMU256)> = ctx
            .post_state
            .transient_unlock_calls
            .iter()
            .filter(|(addr, _, slot)| loaded.contains(&(*addr, *slot)))
            .cloned()
            .collect();
        if hits.is_empty() {
            return vec![];
        }

        let mut res = vec![];
        for (addr, tstore_pc, slot) in hits {
            if !self.reported.borrow_mut().insert((addr, tstore_pc)) {
                continue;
            }
            let bug_idx = sub_bug_idx(&addr);
            EVMBugResult::new_simple(
                "Transient Guard Released Before External Call".to_string(),
                bug_idx,
                format!(
                    "{addr:?} released its EIP-1153 transient reentrancy guard (slot 0x{slot:064x}, TSTORE 0 at pc {tstore_pc}) BEFORE executing an external CALL -- a reentrant callee can re-enter while state is still mid-update, so the guard does not actually protect the function.\n"
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}
