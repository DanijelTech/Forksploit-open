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
        oracles::STORAGE_COLLISION_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct StorageCollisionMetadata {
    pub known: HashMap<(EVMAddress, EVMU256), u8>,
}

impl_serdeany!(StorageCollisionMetadata);

/// Reports every entry in `ctx.post_state.storage_collisions` (populated by
/// `StorageCollisionTracer`, see `middlewares/storage_collision.rs`): a
/// storage slot that has been observed written both "natively" and from
/// inside a DELEGATECALL frame -- strong evidence that two logically
/// unrelated variables (the proxy's own, and the implementation's) share
/// the same physical slot.
pub struct StorageCollisionOracle {}

impl Default for StorageCollisionOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageCollisionOracle {
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
    > for StorageCollisionOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // See ecrecover.rs's oracle() for the full writeup -- same bug, same fix:
        // ctx.post_state.storage_collisions accumulates across the WHOLE corpus
        // lineage forever (vm.rs), so only entries absent from ctx.pre_state (the
        // state right before THIS transaction) are genuinely new here.
        let new_hits: Vec<(_, _)> = ctx
            .post_state
            .storage_collisions
            .iter()
            .filter(|e| !ctx.pre_state.storage_collisions.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<StorageCollisionMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(StorageCollisionMetadata::default());
        }

        let mut violations = vec![];
        for (addr, slot) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<StorageCollisionMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *slot)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            slot.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + STORAGE_COLLISION_BUG_IDX;

            EVMBugResult::new_simple(
                "Storage Collision".to_string(),
                bug_idx,
                format!(
                    "{addr:?}'s storage slot {slot:?} has been written both by the contract's own code and from inside a DELEGATECALL frame -- the proxy's and the implementation's storage layouts likely overlap at this slot, so writing one logical variable silently corrupts the other.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
