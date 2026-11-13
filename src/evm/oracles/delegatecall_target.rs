use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use libafl_bolts::impl_serdeany;
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::DELEGATECALL_TARGET_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct DelegatecallTargetMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(DelegatecallTargetMetadata);

/// Reports every entry in `ctx.post_state.delegatecall_targets_seen`
/// (populated by `DelegatecallTargetTracer`, see
/// `middlewares/delegatecall_target.rs`) whose target address traces back
/// to attacker-influenced input, not a fixed implementation address.
/// Three provenance signals, strongest first: (1) the target was decoded
/// from THIS call's own calldata via CALLDATALOAD (real dataflow
/// tracking, host.rs's 0x35 case -- shared with oracles/self_referral.rs),
/// (2) the target was read back via RETURNDATACOPY from a PRIOR call's
/// return data within the same transaction (host.rs's 0x3e case) -- a
/// cross-contract value-flow path (e.g. a delegatecall target fetched
/// from an untrusted registry's `getImplementation()`) that a
/// calldata-only check can never see, (3) a weaker fallback: the target's
/// raw bytes merely appear somewhere in the calldata, which is only a
/// coincidental byte match, not confirmed provenance -- reported as a
/// separate, lower-confidence bug_type. Complementary to
/// `DelegatecallInjectionOracle`, which instead needs campaign-long
/// history to prove the target is "unbounded"; this catches it in a
/// single transaction.
pub struct DelegatecallTargetOracle {}

impl Default for DelegatecallTargetOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatecallTargetOracle {
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
    > for DelegatecallTargetOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // See ecrecover.rs's oracle() (2026-11-02) for the full writeup --
        // same bug, same fix, found a day later: unlike calldata_addresses/
        // returndata_addresses (reset to this transaction's own current_*
        // value every time, never chained -- see vm.rs, no fix needed for
        // those two), delegatecall_targets_seen IS unioned forward across
        // the WHOLE corpus lineage. Diff against ctx.pre_state so a stale
        // (caller, pc, target) from an unrelated earlier transaction in
        // the same lineage doesn't get reported again here.
        let new_hits: Vec<(_, _, _)> = ctx
            .post_state
            .delegatecall_targets_seen
            .iter()
            .filter(|e| !ctx.pre_state.delegatecall_targets_seen.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        // Found 2026-11-03: `ctx.input.to_bytes()` is NOT the original
        // transaction's calldata once a trace has been "turned into a
        // step" to resume a control-leak continuation -- `set_as_post_exec`
        // (src/evm/input.rs) overwrites `input.data` with a synthetic
        // placeholder representing the injected leak-callback return value,
        // discarding the real argument bytes entirely (confirmed live: 4
        // bytes instead of the real encoded call). Gating the WHOLE
        // function on `calldata.len() < 20` therefore blocked the
        // Confirmed-tier via_calldata_taint/via_returndata_taint checks
        // too, even though those rely only on the persistent
        // calldata_addresses/returndata_addresses state (see vm.rs's
        // execute_from_pc, same-day fix) and have nothing to do with
        // `calldata` at all. The length check now only gates the weaker
        // byte-coincidence fallback below, which genuinely can't mean
        // anything against a stepped segment's synthetic data.
        let calldata = ctx.input.to_bytes();

        if !ctx.fuzz_state.has_metadata::<DelegatecallTargetMetadata>() {
            ctx.fuzz_state
                .metadata_map_mut()
                .insert(DelegatecallTargetMetadata::default());
        }

        let mut violations = vec![];
        for (caller, pc, target) in new_hits.iter() {
            // Three provenance signals, strongest first. The first two are
            // real dataflow tracking (host.rs's 0x35 CALLDATALOAD / 0x3e
            // RETURNDATACOPY observation), confirming `target` is a value
            // that was ACTUALLY decoded that way -- not just a coincidental
            // byte match. `calldata_addresses`/`returndata_addresses` are
            // populated per-call in host.rs and exposed on EVMState (see
            // their own doc comments there).
            let via_calldata_taint = ctx.post_state.calldata_addresses.contains(target);
            let via_returndata_taint = ctx.post_state.returndata_addresses.contains(target);
            let target_bytes = target.as_slice();
            let via_byte_coincidence = !via_calldata_taint
                && !via_returndata_taint
                && calldata.len() >= 20
                && calldata.windows(20).any(|w| w == target_bytes);

            if !via_calldata_taint && !via_returndata_taint && !via_byte_coincidence {
                continue;
            }

            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<DelegatecallTargetMetadata>().unwrap();
            let count = metadata.known.entry((*caller, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            caller.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + DELEGATECALL_TARGET_BUG_IDX;

            // Byte-coincidence alone (no confirmed taint) is a weaker,
            // unconfirmed signal -- give it its own bug_type so
            // oracle.rs's confidence classification (which only
            // recognizes "Delegatecall Target From Calldata" as
            // Confirmed) correctly tags it Review instead.
            let (bug_type, provenance) = if via_calldata_taint {
                (
                    "Delegatecall Target From Calldata",
                    "was itself decoded from this transaction's own calldata (confirmed via CALLDATALOAD tracking, not a coincidental byte match)".to_string(),
                )
            } else if via_returndata_taint {
                (
                    "Delegatecall Target From Calldata",
                    "was read back from a PRIOR call's return data within this same transaction -- a cross-contract value-flow path that a calldata-only check can never see".to_string(),
                )
            } else {
                (
                    "Delegatecall Target From Calldata (Unconfirmed)",
                    "has address bytes that merely appear somewhere in this transaction's calldata -- a weaker, coincidental signal, not confirmed via real dataflow tracking".to_string(),
                )
            };

            EVMBugResult::new_simple(
                bug_type.to_string(),
                bug_idx,
                format!(
                    "{caller:?}'s DELEGATECALL at pc {pc} targeted {target:?}, which {provenance} -- the delegatecall target looks attacker-controlled, not a fixed implementation address.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
