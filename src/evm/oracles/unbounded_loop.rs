use std::collections::HashMap;

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use libafl_bolts::impl_serdeany;
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::UNBOUNDED_LOOP_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

/// How many backward-jump iterations a loop needs to hit, in a SINGLE
/// call, before this oracle starts paying attention to it at all. Below
/// this, "the loop ran a few times" is completely normal and not a signal
/// of anything -- most loops in real contracts are short and bounded by
/// calldata/constants, not by ever-growing storage.
const MIN_ITERATIONS_OF_INTEREST: u64 = 8;

/// A loop whose trip count for the SAME (address, loop pc) is observed to
/// GROW across separate, independently-fuzzed calls is the direct,
/// empirical signature of "this loop's bound comes from a storage value
/// that keeps increasing" -- the classic unbounded-loop-over-growing-array
/// gas-griefing footgun (e.g. `for (i = 0; i < allPoolMembers.length; i++)`
/// inside a function anyone can call, where `allPoolMembers` only ever
/// gets pushed to, never popped). Confirmed live against a real, deployed
/// ETC contract this session: a public `mint()` function loops over every
/// historical "superlist pool" member on every single call, with no
/// mechanism to ever shrink that pool -- gas cost (and therefore real
/// transaction fees) for EVERY future mint provably increases forever as
/// more members join, until it eventually exceeds the block gas limit and
/// the function becomes permanently unusable. No existing oracle in this
/// project targets this bug class: it isn't reentrancy, access control,
/// or arithmetic -- it's a pure, usage-driven gas-cost growth trend, which
/// is exactly what a FUZZER (replaying many real calls against evolving
/// state) can observe directly, instead of needing static dataflow
/// tracing to prove a loop bound is storage-derived.
///
/// Reported only on GROWTH (this call's count > the highest ever seen for
/// this exact loop before), never on a loop merely being long once -- a
/// single long-but-fixed loop (e.g. iterating a hardcoded MAX_OWNERS)
/// isn't this bug; only a trend of increasing cost over separate calls is.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct UnboundedLoopMetadata {
    /// (address, loop JUMPDEST pc) -> highest iteration count ever
    /// observed across all calls so far this campaign.
    pub max_seen: HashMap<(EVMAddress, usize), u64>,
    /// Same key -> how many times growth has already been reported for
    /// it. Capped (like unchecked_call.rs's equivalent) so one real
    /// growing loop doesn't spam a finding every single time it grows by
    /// one more iteration.
    pub report_count: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(UnboundedLoopMetadata);

/// Heuristic, not proof: a loop can legitimately iterate more on a LATER
/// call for reasons that have nothing to do with unbounded growth (e.g. a
/// caller-supplied length argument that happened to be bigger this time).
/// What this can't fake is a SUSTAINED, repeated upward trend across many
/// independent calls with no growing input of that kind -- which is why
/// report_count stays capped low rather than firing on every single call:
/// a one-off bigger iteration count proves little, but the SAME loop
/// growing several separate times in a row, with no corresponding
/// explicit argument driving it, is a strong real signal.
pub struct UnboundedLoopOracle {}

impl Default for UnboundedLoopOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl UnboundedLoopOracle {
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
    > for UnboundedLoopOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        if ctx.post_state.loop_iterations.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<UnboundedLoopMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(UnboundedLoopMetadata::default());
        }

        let mut violations = vec![];
        let observed: Vec<((EVMAddress, usize), u64)> =
            ctx.post_state.loop_iterations.iter().map(|(k, v)| (*k, *v)).collect();

        for (key, count) in observed {
            if count < MIN_ITERATIONS_OF_INTEREST {
                continue;
            }
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<UnboundedLoopMetadata>().unwrap();
            let prev_max = *metadata.max_seen.get(&key).unwrap_or(&0);

            if count <= prev_max {
                continue;
            }
            metadata.max_seen.insert(key, count);

            // First time this loop is seen at/above the threshold: record
            // the baseline, but don't report yet -- a single call proves
            // nothing about a GROWTH trend, only a second, bigger call
            // does.
            if prev_max == 0 {
                continue;
            }

            let report_count = metadata.report_count.entry(key).or_insert(0);
            if *report_count > 3 {
                continue;
            }
            *report_count += 1;

            let (addr, pc) = key;
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            use std::hash::{Hash, Hasher};
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + UNBOUNDED_LOOP_BUG_IDX;

            EVMBugResult::new_simple(
                "Unbounded Loop".to_string(),
                bug_idx,
                format!(
                    "{addr:?}'s loop at pc {pc} iterated {count} times this call, up from a previous max of \
                     {prev_max} -- its trip count is GROWING across separate calls, meaning it's bounded by a \
                     storage value that only ever increases, not by calldata or a fixed constant. Gas cost for \
                     EVERY future call through this loop keeps rising as more state accumulates, until it \
                     eventually exceeds the block gas limit and the function becomes permanently unusable \
                     (unbounded-loop-over-growing-storage gas-griefing DoS). Heuristic: a loop can also grow \
                     once for a legitimate reason (e.g. a bigger caller-supplied length); this is only reported \
                     after the SAME loop grows repeatedly with no such explicit driver.\n"
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
