use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use libafl_bolts::impl_serdeany;
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::READONLY_REENTRANCY_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ReadonlyReentrancyMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(ReadonlyReentrancyMetadata);

/// Reports every entry in `ctx.post_state.readonly_reentrancy_hits`
/// (populated by `host.rs`'s own `call()` -- needs the decoded
/// `CallInputs` and real return bytes, which only `call()` sees, not a
/// separate opcode-only middleware) that's genuinely NEW in this
/// transaction: a call that re-queried a (target, selector) already
/// seen once at control-leak depth 0 ("stable" state) earlier in the
/// SAME transaction, and got a DIFFERENT return value while a
/// control-leak is now pending (depth > 0) -- i.e. a view-shaped
/// function returning inconsistent, mid-transaction state to whoever
/// queries it during a reentrant callback window.
///
/// This is the read-only reentrancy class behind the real Curve
/// (January 2023) incidents and others: the classic `reentrancy.rs`
/// oracle only catches a SLOAD-before-write / SSTORE-after-reentry
/// pattern on the SAME contract's OWN state -- it has no signal for "an
/// EXTERNAL integrator read a stale/manipulated value via a plain,
/// state-preserving call and acted on it," because nothing was ever
/// written incorrectly on the queried contract itself.
///
/// Review-tier, not Confirmed: a value legitimately differing between
/// two calls during a reentrant window can also just mean "unrelated,
/// correct state changed in between" (e.g. a totally different deposit
/// landing), not necessarily an exploitable inconsistency -- worth a
/// human look at whether the specific value involved is
/// security-critical (a price, a share ratio, a health factor), not a
/// certain bug. Diffs against `ctx.pre_state` from the start (see
/// oracles/ecrecover.rs's 2026-11-02/03 doc comments for why that
/// matters -- built in here, not added later as a fix).
pub struct ReadonlyReentrancyOracle {}

impl Default for ReadonlyReentrancyOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadonlyReentrancyOracle {
    pub fn new() -> Self {
        Self {}
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
    > for ReadonlyReentrancyOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize)> = ctx
            .post_state
            .readonly_reentrancy_hits
            .iter()
            .filter(|e| !ctx.pre_state.readonly_reentrancy_hits.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<ReadonlyReentrancyMetadata>() {
            ctx.fuzz_state
                .metadata_map_mut()
                .insert(ReadonlyReentrancyMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx
                .fuzz_state
                .metadata_map_mut()
                .get_mut::<ReadonlyReentrancyMetadata>()
                .unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + READONLY_REENTRANCY_BUG_IDX;

            EVMBugResult::new_simple(
                "Read-Only Reentrancy".to_string(),
                bug_idx,
                format!(
                    "{addr:?} at pc {pc} re-queried a (target, selector) call during a pending reentrant \
                     callback window and got a DIFFERENT return value than the same call returned earlier \
                     in this same transaction, outside that window. A view-shaped function returning \
                     inconsistent, mid-transaction state to an external caller is exactly the shape behind \
                     real read-only reentrancy incidents (e.g. Curve, January 2023) -- worth checking whether \
                     the value involved (a price, share ratio, or similar) is security-critical elsewhere.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
