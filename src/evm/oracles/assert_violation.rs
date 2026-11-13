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
        oracles::ASSERT_VIOLATION_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct AssertViolationMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(AssertViolationMetadata);

/// Reports every entry in `ctx.post_state.assert_violations` (populated by
/// `host.rs`) that's genuinely NEW in this transaction: a failed `assert()`
/// was reached while the calling transaction carried non-empty calldata --
/// SWC-110, "Assert Violation". solc 0.8.x compiles `assert(x)` to a REVERT
/// carrying `Panic(0x01)` (selector 0x4e487b71), not the INVALID opcode;
/// host.rs recognises both the INVALID (0xfe) form and the Panic(0x01) form.
///
/// `assert()` is for internal invariants that can never fail if the code
/// is correct; it burns ALL remaining gas on failure. Using it for input
/// validation (something an attacker can trigger) both mislabels the
/// error and turns a cheap revert into a full gas drain -- a griefing
/// amplifier, and a signal the developer believed the condition
/// impossible when it isn't.
///
/// Review-tier: the failure could in principle come from a hand-written
/// assembly block rather than `assert`, and calldata being present doesn't
/// by itself prove the input is attacker-controlled (it may be a trusted
/// caller's own argument), so this flags a reachable assertion, not a
/// certain bug. Diffs against `ctx.pre_state` from the start.
pub struct AssertViolationOracle {}

impl Default for AssertViolationOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl AssertViolationOracle {
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
    > for AssertViolationOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize)> = ctx
            .post_state
            .assert_violations
            .iter()
            .filter(|e| !ctx.pre_state.assert_violations.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<AssertViolationMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(AssertViolationMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<AssertViolationMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + ASSERT_VIOLATION_BUG_IDX;

            EVMBugResult::new_simple(
                "Assert Violation".to_string(),
                bug_idx,
                format!(
                    "{addr:?} reached a failed `assert()` at pc {pc} (solc 0.8.x emits Panic(0x01)) on a transaction that carried calldata (SWC-110). `assert` is meant for impossible internal invariants -- if an externally-supplied input can reach it, the check is misused for validation and burns all gas on failure instead of reverting cheaply.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
