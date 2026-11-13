use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use libafl_bolts::impl_serdeany;
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::INTEGER_OVERFLOW_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct IntegerOverflowMetadata {
    // (address, pc) -> how many times already reported, capped to avoid
    // flooding the output every single time the same wraparound re-executes.
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(IntegerOverflowMetadata);

/// Reports every entry that ended up in `ctx.post_state.integer_overflow`
/// (populated by `IntegerOverflowTracer`, see `middlewares/overflow.rs`) for
/// a non-reverted transaction -- i.e. unchecked arithmetic wrapped around and
/// the contract kept running anyway instead of reverting.
pub struct IntegerOverflowOracle {}

impl Default for IntegerOverflowOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegerOverflowOracle {
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
    > for IntegerOverflowOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // See ecrecover.rs's oracle() for the full writeup -- same bug, same fix:
        // ctx.post_state.integer_overflow accumulates across the WHOLE corpus
        // lineage forever (vm.rs), so only entries absent from ctx.pre_state (the
        // state right before THIS transaction) are genuinely new here.
        let new_hits: Vec<(_, _, _)> = ctx
            .post_state
            .integer_overflow
            .iter()
            .filter(|e| !ctx.pre_state.integer_overflow.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<IntegerOverflowMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(IntegerOverflowMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc, op_name) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<IntegerOverflowMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + INTEGER_OVERFLOW_BUG_IDX;

            EVMBugResult::new_simple(
                "Integer Overflow".to_string(),
                bug_idx,
                format!(
                    "Unchecked {op_name} at {:?}:{} wrapped around without reverting -- likely missing overflow protection (pre-0.8 Solidity, raw bytecode, or an `unchecked` block).\n",
                    addr, pc
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}

