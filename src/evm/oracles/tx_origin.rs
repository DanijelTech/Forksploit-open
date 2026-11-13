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
        oracles::TX_ORIGIN_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TxOriginMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(TxOriginMetadata);

/// Reports every entry in `ctx.post_state.tx_origin_checks` (populated by
/// `TxOriginTracer`, see `middlewares/tx_origin.rs`): a contract that read
/// `tx.origin` while being called through an intermediary (`msg.sender` !=
/// `tx.origin`) in a transaction that still completed successfully --
/// exactly the shape of the classic `tx.origin` phishing bypass (a victim
/// account is tricked into calling an attacker contract, which relays the
/// call into this one; any `tx.origin`-based check still passes since
/// `tx.origin` never changes down the call chain).
pub struct TxOriginOracle {}

impl Default for TxOriginOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl TxOriginOracle {
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
    > for TxOriginOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // See ecrecover.rs's oracle() (2026-11-02) for the full writeup --
        // same bug, same fix, found a day later via a systematic re-check
        // of every EVMState field vm.rs unions forward across the WHOLE
        // corpus lineage: only entries absent from ctx.pre_state (the
        // state right before THIS transaction) are genuinely new here.
        let new_hits: Vec<(_, _)> = ctx
            .post_state
            .tx_origin_checks
            .iter()
            .filter(|e| !ctx.pre_state.tx_origin_checks.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<TxOriginMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(TxOriginMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<TxOriginMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + TX_ORIGIN_BUG_IDX;

            EVMBugResult::new_simple(
                "Tx.Origin Phishing Bypass".to_string(),
                bug_idx,
                format!(
                    "{addr:?} read tx.origin at pc {pc} while being called through an intermediary (msg.sender != tx.origin), and the transaction still succeeded. Any tx.origin-based check here can be bypassed by tricking the real account into calling an attacker's contract, which then relays the call here -- tx.origin stays the same all the way down the call chain.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
