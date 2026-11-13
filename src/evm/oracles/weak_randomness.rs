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
        oracles::WEAK_RANDOMNESS_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct WeakRandomnessMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(WeakRandomnessMetadata);

/// Reports every entry in `ctx.post_state.weak_randomness_uses` (populated
/// by `host.rs`'s MOD/comparison opcode handling) that's genuinely NEW in
/// this transaction: a `MOD`/`AND`/comparison whose operand was a block
/// environment read (TIMESTAMP/NUMBER/PREVRANDAO/DIFFICULTY/GASLIMIT/
/// BASEFEE) -- SWC-120, "Weak sources of randomness from chain
/// attributes".
///
/// These values are all miner/validator-influenceable and, crucially,
/// *predictable* by anyone watching the pending transaction: `block.
/// timestamp % n`-style "lottery" or winner-selection logic is trivially
/// gamed (the classic "roll the dice with block.number" bug). An AND used
/// as a cheap modulo (`x & 0xff`) is included because it's the same
/// pattern with the same consequence.
///
/// Review-tier: block values are sometimes used for genuinely
/// time-lock/epoch semantics (legitimate) rather than randomness, and the
/// opcode-level linkage is proximity-based (the env value is latched by
/// the opcode immediately before the consumer), so this is a strong
/// hint, not a certain bug. Diffs against `ctx.pre_state` from the start.
pub struct WeakRandomnessOracle {}

impl Default for WeakRandomnessOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl WeakRandomnessOracle {
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
    > for WeakRandomnessOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize)> = ctx
            .post_state
            .weak_randomness_uses
            .iter()
            .filter(|e| !ctx.pre_state.weak_randomness_uses.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<WeakRandomnessMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(WeakRandomnessMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<WeakRandomnessMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + WEAK_RANDOMNESS_BUG_IDX;

            EVMBugResult::new_simple(
                "Weak Randomness".to_string(),
                bug_idx,
                format!(
                    "{addr:?} used a block-environment value (block.timestamp/number/prevrandao/gaslimit/basefee) as the operand of a modulo/bitmask/comparison at pc {pc} (SWC-120). Such values are predictable by whoever watches the pending transaction and influenceable by the block producer, so any winner/lottery/selection logic built on them can be gamed.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
