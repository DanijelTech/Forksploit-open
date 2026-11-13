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
        oracles::ARBITRARY_STORAGE_WRITE_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ArbitraryStorageWriteMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(ArbitraryStorageWriteMetadata);

/// Reports every entry in `ctx.post_state.arbitrary_storage_writes`
/// (populated by `ArbitraryStorageWriteTracer`, see
/// `middlewares/arbitrary_storage_write.rs`) that's genuinely NEW in this
/// transaction -- SWC-124, Write to Arbitrary Storage Location: an SSTORE
/// whose slot came straight from this transaction's own calldata,
/// unmodified by any KECCAK256 mapping/array-slot derivation.
///
/// Diffs against `ctx.pre_state` rather than iterating the full
/// accumulated set directly -- see oracles/ecrecover.rs's own doc comment
/// (2026-11-02/03) for why: `post_state.arbitrary_storage_writes` is
/// unioned forward across the WHOLE corpus lineage in vm.rs, so without
/// this diff a stale (addr, pc, slot) from an unrelated earlier
/// transaction in the same lineage would get reported again here. Built
/// with this fix from the start, not discovered as a separate bug later.
pub struct ArbitraryStorageWriteOracle {}

impl Default for ArbitraryStorageWriteOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ArbitraryStorageWriteOracle {
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
    > for ArbitraryStorageWriteOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize, EVMU256)> = ctx
            .post_state
            .arbitrary_storage_writes
            .iter()
            .filter(|e| !ctx.pre_state.arbitrary_storage_writes.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<ArbitraryStorageWriteMetadata>() {
            ctx.fuzz_state
                .metadata_map_mut()
                .insert(ArbitraryStorageWriteMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc, slot) in new_hits.iter() {
            let metadata = ctx
                .fuzz_state
                .metadata_map_mut()
                .get_mut::<ArbitraryStorageWriteMetadata>()
                .unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + ARBITRARY_STORAGE_WRITE_BUG_IDX;

            EVMBugResult::new_simple(
                "Arbitrary Storage Write".to_string(),
                bug_idx,
                format!(
                    "{addr:?} executed SSTORE at pc {pc} with slot {slot:?} -- a value that came \
                     straight from this transaction's own calldata, not from a KECCAK256 \
                     mapping/array-slot derivation. The storage slot being written looks \
                     attacker-chosen, which can overwrite ANY slot in this contract (owner, \
                     balances, implementation address, ...) depending on what value is passed.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
