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
        oracles::PRECISION_LOSS_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct PrecisionLossMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(PrecisionLossMetadata);

/// Reports every entry in `ctx.post_state.precision_losses` (populated by
/// `host.rs`'s DIV/MUL opcode handling) that's genuinely NEW in this
/// transaction: a `MUL` whose operand is the result of the `DIV` seen a
/// few opcodes earlier -- i.e. `(a / b) * c` rather than `(a * c) / b`.
///
/// Solidity integer division truncates, so dividing before scaling loses
/// the remainder on every step; the correct ordering multiplies first.
/// This is the root of a large family of real DeFi bugs (wrong
/// share/interest/fee math, "rounding" that leaks value), and it is
/// bytecode-visible without any source.
///
/// Review-tier: the opcode linkage is proximity-based and legitimate
/// orderings do exist (e.g. an intentionally-floored intermediate that is
/// never scaled back up), so this flags "look here", not "certain bug".
/// Diffs against `ctx.pre_state` from the start.
pub struct PrecisionLossOracle {}

impl Default for PrecisionLossOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecisionLossOracle {
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
    > for PrecisionLossOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize)> = ctx
            .post_state
            .precision_losses
            .iter()
            .filter(|e| !ctx.pre_state.precision_losses.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<PrecisionLossMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(PrecisionLossMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<PrecisionLossMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + PRECISION_LOSS_BUG_IDX;

            EVMBugResult::new_simple(
                "Precision Loss".to_string(),
                bug_idx,
                format!(
                    "{addr:?} multiplied at pc {pc} by the result of an immediately-preceding division -- `(a / b) * c`. Integer division truncates, so scaling after dividing loses the remainder; the lossless ordering is `(a * c) / b`. Classic wrong share/interest/fee math (SWC-101 / rounding class).\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
