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
        oracles::UNINITIALIZED_MEMORY_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct UninitializedMemoryMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(UninitializedMemoryMetadata);

/// Reports every entry in `ctx.post_state.uninitialized_memory_reads`
/// (populated by `UninitializedMemoryTracer`, see
/// `middlewares/uninitialized_memory.rs`): an `MLOAD` reading a 32-byte
/// memory word that was never written (via `MSTORE`/`MSTORE8`/`*COPY`, or
/// copied in from a sub-call's return data) within the current call frame.
///
/// This is a heuristic code-quality signal, NOT a guaranteed exploit: the
/// EVM deterministically zero-fills unwritten memory (there is no
/// "undefined behavior" the way there is in e.g. C), so the read itself is
/// always safe and predictable. What it *can* indicate is a logic bug --
/// code silently proceeding with a value (0) it never actually computed or
/// validated, because some expected initialization step was skipped.
/// Expect a higher false-positive rate here than most other detectors.
pub struct UninitializedMemoryOracle {}

impl Default for UninitializedMemoryOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl UninitializedMemoryOracle {
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
    > for UninitializedMemoryOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // See ecrecover.rs's oracle() (2026-11-02) for the full writeup --
        // same bug, same fix, found a day later via a systematic re-check
        // of every EVMState field vm.rs unions forward across the WHOLE
        // corpus lineage (`.chain(self.host.current_X...)`): only entries
        // absent from ctx.pre_state (the state right before THIS
        // transaction) are genuinely new here.
        let new_hits: Vec<(_, _)> = ctx
            .post_state
            .uninitialized_memory_reads
            .iter()
            .filter(|e| !ctx.pre_state.uninitialized_memory_reads.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<UninitializedMemoryMetadata>() {
            ctx.fuzz_state
                .metadata_map_mut()
                .insert(UninitializedMemoryMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<UninitializedMemoryMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + UNINITIALIZED_MEMORY_BUG_IDX;

            EVMBugResult::new_simple(
                "Uninitialized Memory Read".to_string(),
                bug_idx,
                format!(
                    "{addr:?} executed MLOAD at pc {pc} reading a memory word that was never written in the current call frame -- possibly relying on a value that was never actually computed (EVM memory reads as zero, so this is a logic-bug smell, not a crash).\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
