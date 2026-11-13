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
        oracles::UNCHECKED_CALL_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct UncheckedCallMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(UncheckedCallMetadata);

/// Reports every entry in `ctx.post_state.unchecked_call` (populated by
/// `UncheckedCallTracer`, see `middlewares/unchecked_call.rs`): a plain
/// `CALL`/`CALLCODE` that failed in a transaction that still completed
/// successfully overall -- i.e. nothing downstream reverted because of it.
/// **Heuristic, not proof**: this can also fire on code that deliberately
/// checks the result and handles a failure gracefully without reverting
/// (see the caveat in `middlewares/unchecked_call.rs`). Not included in
/// `high_confidence` for that reason.
pub struct UncheckedCallOracle {}

impl Default for UncheckedCallOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl UncheckedCallOracle {
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
    > for UncheckedCallOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // See ecrecover.rs's oracle() (2026-11-02) for the full writeup --
        // same bug, same fix, found a day later via a systematic re-check
        // of every EVMState field vm.rs unions forward across the WHOLE
        // corpus lineage: only entries absent from ctx.pre_state (the
        // state right before THIS transaction) are genuinely new here.
        let new_hits: Vec<(_, _)> = ctx
            .post_state
            .unchecked_call
            .iter()
            .filter(|e| !ctx.pre_state.unchecked_call.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<UncheckedCallMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(UncheckedCallMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<UncheckedCallMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + UNCHECKED_CALL_BUG_IDX;

            EVMBugResult::new_simple(
                "Unchecked Low-Level Call".to_string(),
                bug_idx,
                format!(
                    "{addr:?}'s low-level call at pc {pc} failed, yet the overall transaction still succeeded -- nothing downstream reverted because of it. Any native-value/state change that call was supposed to make silently never happened. (Heuristic: this can also fire on code that checks the result and deliberately continues without reverting.)\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
