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
        oracles::GAS_STIPEND_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct GasStipendMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(GasStipendMetadata);

/// Reports every entry in `ctx.post_state.hardcoded_gas_stipends`
/// (populated by `host.rs`'s `call()`) that's genuinely NEW in this
/// transaction: an outgoing CALL made with a hardcoded, low gas limit
/// (<= 2300, the EIP-150 stipend solc forwards verbatim for
/// `.transfer()`/`.send()`) -- SWC-134, "Message call with hardcoded gas
/// amount".
///
/// This is the exact shape of a well-known, real, repeatable failure: a
/// recipient whose `receive()`/`fallback()` needs more than 2300 gas
/// (e.g. WETH9's own `transfer()`, which this project hit live) makes
/// every `.transfer()` to it revert -- and because solc's `.transfer()`
/// reverts the CALLER on failure, one such recipient bricks the whole
/// payout loop for everyone (see oracles/revert_in_loop.rs for the
/// companion DoS signal). Also broke when gas repricing (Istanbul's
/// EIP-1884) raised SLOAD's cost above the stipend.
///
/// Review-tier: 2300 is deliberately generous as an upper bound, so a
/// legitimate, intentional use of `.send()` (which returns a bool instead
/// of reverting) is a possible false positive -- but any hardcoded stipend
/// this low is worth a human look, and the WETH9 case is a proven real
/// bug. Diffs against `ctx.pre_state` from the start.
pub struct GasStipendOracle {}

impl Default for GasStipendOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl GasStipendOracle {
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
    > for GasStipendOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize, u64)> = ctx
            .post_state
            .hardcoded_gas_stipends
            .iter()
            .filter(|e| !ctx.pre_state.hardcoded_gas_stipends.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<GasStipendMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(GasStipendMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc, gas) in new_hits.iter() {
            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<GasStipendMetadata>().unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + GAS_STIPEND_BUG_IDX;

            EVMBugResult::new_simple(
                "Hardcoded Gas Stipend".to_string(),
                bug_idx,
                format!(
                    "{addr:?} made an outgoing call at pc {pc} with a hardcoded gas limit of {gas} (SWC-134). If the recipient's fallback/receive needs more than that, the call reverts -- and since a `.transfer()` reverts the caller on failure, one such recipient can brick this payout path for everyone (WETH9's own transfer() is a proven real-world case; Istanbul's EIP-1884 repricing broke others).\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
