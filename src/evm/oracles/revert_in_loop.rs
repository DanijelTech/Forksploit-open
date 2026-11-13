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
        oracles::REVERT_IN_LOOP_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct RevertInLoopMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(RevertInLoopMetadata);

/// Reports every entry in `ctx.post_state.revert_in_loop` (populated by
/// `host.rs`'s `call()`) that's genuinely NEW in this transaction: an
/// outgoing CALL site that FAILED and was executed 2+ times within the same
/// call -- the push-payment DoS shape (SWC-113). Re-executing the same call
/// pc proves it sits inside a loop, and a failure there proves a recipient
/// made the payout call fail; unlike a pc-range/backward-jump heuristic,
/// this cannot be fooled by the single backward JUMP solc emits as the
/// return edge of every internal helper.
///
/// `for (uint i; i < recipients.length; i++) recipients[i].transfer(x);`
/// reverts the whole loop if ANY recipient's transfer fails. A single
/// recipient that always reverts (a contract whose fallback reverts, a
/// blacklisted address, or a `.transfer()` that runs out of the 2300-gas
/// stipend -- see oracles/gas_stipend.rs) permanently blocks the
/// distribution for every other recipient. The robust pattern is a
/// pull-payment (each recipient withdraws) or a try/catch that skips the
/// failing recipient.
///
/// Review-tier: a short, fully-trusted, all-EOA recipient list makes this
/// safe, and the fuzzer can only observe a failure it actually caused, so
/// this is "look here", not "certain bug". Diffs against `ctx.pre_state`
/// from the start.
pub struct RevertInLoopOracle {}

impl Default for RevertInLoopOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl RevertInLoopOracle {
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
    > for RevertInLoopOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // A failing outgoing call site executed 2+ times in one call is
        // unambiguously inside a loop: the same call pc ran more than once,
        // and one of those runs failed. That is the push-payment DoS shape
        // -- a recipient made a payout call fail, and the caller's loop
        // re-executes that call for every other recipient.
        let hits: Vec<(EVMAddress, usize)> = ctx
            .post_state
            .revert_in_loop
            .iter()
            .filter(|e| !ctx.pre_state.revert_in_loop.contains(*e))
            .cloned()
            .collect();
        if hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<RevertInLoopMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(RevertInLoopMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<RevertInLoopMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + REVERT_IN_LOOP_BUG_IDX;

            EVMBugResult::new_simple(
                "Revert In Loop (DoS)".to_string(),
                bug_idx,
                format!(
                    "{addr:?} had an outgoing call at pc {pc} fail while iterating a loop (SWC-113). If the caller reverts on that failure (a bare `recipients[i].transfer(x)` with no try/catch), one recipient that always reverts permanently blocks the distribution for every other recipient -- a griefing / denial-of-service vector.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
