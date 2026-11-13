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
        oracles::ECRECOVER_ZERO_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct EcrecoverZeroMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(EcrecoverZeroMetadata);

/// Reports every entry in `ctx.post_state.ecrecover_zero` (populated by
/// `EcrecoverZeroTracer`, see `middlewares/ecrecover.rs`): a transaction
/// where `ecrecover()` recovered the zero address (invalid signature) and
/// the caller's call still succeeded instead of reverting.
pub struct EcrecoverZeroOracle {}

impl Default for EcrecoverZeroOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl EcrecoverZeroOracle {
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
    > for EcrecoverZeroOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // Only entries NEW in this exact transaction -- ctx.post_state.ecrecover_zero
        // is the WHOLE lineage's accumulation (vm.rs unions it forward across every
        // transaction forever, never clearing it), so iterating it directly re-fires
        // on every later, unrelated transaction built on top of a corpus branch that
        // EVER saw this once. Confirmed live 2026-11-02 on real ETC mainnet
        // (0x9f5304...'s plan C9f53_5): the minimized single-call replay
        // (`0x64dab283()`, a plain address getter -- verified via debug_traceCall,
        // zero CALL-family opcodes, max pc reached 1314) was reported as "called
        // ecrecover() at pc 1927" -- a pc that call can never reach -- purely because
        // SOME earlier, unrelated transaction in the same corpus lineage had already
        // tripped this oracle and the flag never got cleared. ctx.pre_state is the
        // state immediately before only THIS transaction (see oracle.rs's own doc:
        // "The VMState before the execution"), so diffing against it is exactly the
        // fix -- true multi-tx exploits still work: the step that ACTUALLY calls
        // ecrecover(0) still gets its (addr, pc) added to pre_state -> post_state
        // right then, which is still "new" at that step's own oracle() call.
        let new_hits: Vec<(_, _)> = ctx
            .post_state
            .ecrecover_zero
            .iter()
            .filter(|e| !ctx.pre_state.ecrecover_zero.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<EcrecoverZeroMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(EcrecoverZeroMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<EcrecoverZeroMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + ECRECOVER_ZERO_BUG_IDX;

            EVMBugResult::new_simple(
                "Unchecked ecrecover(0)".to_string(),
                bug_idx,
                format!(
                    "{addr:?} called ecrecover() at pc {pc} with an invalid signature (recovered the zero address), and the call succeeded anyway -- likely missing a `require(signer != address(0))` check, which is exploitable if the compared value was never initialized.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
