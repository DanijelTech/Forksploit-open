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
        oracles::STALE_GUARD_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    oracle::Oracle,
    state::HasExecutionResult,
};

/// How many SEPARATE successful calls need to pass through the SAME guard
/// (JUMPI fed by the SAME storage slot) with the slot's value COMPLETELY
/// UNCHANGED before this oracle pays attention. Most `require(storageVar
/// OP constant)`-style checks legitimately read a slot that stays the
/// same for a while (a short fuzz campaign may just never call whatever
/// setter would change it) -- a high threshold is the only real defense
/// against that, short of proving the slot is semantically "a counter"
/// (which would need source-level typing this project deliberately
/// doesn't rely on).
const MIN_STREAK_OF_INTEREST: u32 = 6;

/// Confirmed live this session on a real deployed ETC contract: a
/// `mint()` function gated on `require(numTokens < MAX_TOKENS)`, where
/// `numTokens`'s own increment (`numTokens++`) was commented out in the
/// internal mint path and only incremented once-per-call (not once-per-
/// token) elsewhere, behind an unrelated flag. The advertised 20,000-token
/// cap was therefore completely ineffective -- the guard read the SAME
/// value on every single call, no matter how many times `mint()`
/// succeeded. This oracle generalizes that SPECIFIC finding into a
/// bytecode-only, no-source-needed signal: a storage slot that is SLOAD'd
/// immediately (within a few instructions -- see `current_last_sload` in
/// `host.rs`) before a JUMPI, repeated across many successful calls with
/// its value never once changing, looks exactly like a cap/limit/counter
/// guard that structurally can never progress -- either because whatever
/// is supposed to increment it is dead/unreachable, or because the check
/// is comparing against the wrong thing entirely.
///
/// Heuristic, not proof (same caveat as `unbounded_loop.rs`): a storage
/// slot CAN legitimately be read by a guard and stay constant for a long
/// time by design (a rarely-touched admin flag, a one-time "initialized"
/// check, a fee percentage nobody changed this campaign). Reported as a
/// review item, in the same spirit as `centralization_risk.rs` --
/// "something to check", not an assertion that this specific guard is
/// broken.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct StaleGuardMetadata {
    /// (address, jumpi pc, slot) -> (last value seen, how many SEPARATE
    /// successful calls in a row saw that exact value, how many times
    /// already reported for this exact guard).
    pub streaks: HashMap<(EVMAddress, usize, EVMU256), (EVMU256, u32, u8)>,
}

impl_serdeany!(StaleGuardMetadata);

pub struct StaleGuardOracle {}

impl Default for StaleGuardOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl StaleGuardOracle {
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
    > for StaleGuardOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        if ctx.post_state.guard_reads.is_empty() {
            return vec![];
        }

        // See the identical check in oracles/self_referral.rs: a call that
        // leaked control is not yet finished, and feedback.rs's
        // OracleFeedback unconditionally discards any oracle() result from
        // it -- updating the streak/already-reported bookkeeping below for
        // such a call would let it consume the one-shot report without the
        // finding ever actually surfacing.
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<StaleGuardMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(StaleGuardMetadata::default());
        }

        let mut violations = vec![];
        let observed: Vec<(EVMAddress, usize, EVMU256, EVMU256)> =
            ctx.post_state.guard_reads.iter().cloned().collect();

        for (addr, jumpi_pc, slot, value) in observed {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<StaleGuardMetadata>().unwrap();
            let key = (addr, jumpi_pc, slot);
            let entry = metadata.streaks.entry(key).or_insert((value, 0, 0));

            if entry.0 == value {
                entry.1 += 1;
            } else {
                // The guard moved -- it's doing SOMETHING, reset the
                // streak instead of treating this as a fresh occurrence.
                entry.0 = value;
                entry.1 = 1;
            }

            if entry.1 < MIN_STREAK_OF_INTEREST || entry.2 > 0 {
                continue;
            }
            entry.2 += 1;
            let streak = entry.1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            jumpi_pc.hash(&mut hasher);
            slot.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + STALE_GUARD_BUG_IDX;

            EVMBugResult::new_simple(
                "Stale Guard Counter".to_string(),
                bug_idx,
                format!(
                    "{addr:?}'s guard check at pc {jumpi_pc} reads storage slot {slot:#x}, which held the exact \
                     same value ({value:#x}) across {streak} separate successful calls through this guard. If \
                     this slot is meant to be a counter or usage total that a `require(slot < LIMIT)`-style check \
                     enforces a cap against, a value that never moves despite repeated successful activity \
                     usually means the increment logic is missing, unreachable, or gated behind something \
                     unrelated -- making the advertised limit silently ineffective (confirmed in a real deployed \
                     contract this session: a token-mint cap whose counter's increment had been commented out). \
                     Review item, not a certain bug: a guard CAN legitimately read a slot that stays constant by \
                     design (an admin flag, a one-time init check) -- worth a manual look at what this slot is \
                     supposed to track and whether anything actually updates it.\n"
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
