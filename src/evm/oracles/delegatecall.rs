use std::collections::{hash_map::DefaultHasher, HashMap};

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use libafl_bolts::impl_serdeany;
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::DELEGATECALL_INJECTION_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct DelegatecallInjectionMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(DelegatecallInjectionMetadata);

/// Reports every entry in `ctx.post_state.delegatecall_injections`
/// (populated by `DelegatecallInjectionTracer`, see
/// `middlewares/delegatecall.rs`): a DELEGATECALL callsite that has been
/// observed targeting more than `DELEGATECALL_INJECTION_THRESHOLD` distinct
/// addresses over the campaign, i.e. the target is effectively
/// attacker-controlled rather than a fixed trusted implementation.
pub struct DelegatecallInjectionOracle {}

impl Default for DelegatecallInjectionOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatecallInjectionOracle {
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
    > for DelegatecallInjectionOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        // See ecrecover.rs's oracle() for the full writeup -- same bug, same fix:
        // ctx.post_state.delegatecall_injections accumulates across the WHOLE
        // corpus lineage forever (vm.rs), so only entries absent from
        // ctx.pre_state (the state right before THIS transaction) are new here.
        let new_hits: Vec<(_, _)> = ctx
            .post_state
            .delegatecall_injections
            .iter()
            .filter(|e| !ctx.pre_state.delegatecall_injections.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<DelegatecallInjectionMetadata>() {
            ctx.fuzz_state
                .metadata_map_mut()
                .insert(DelegatecallInjectionMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx
                .fuzz_state
                .metadata_map_mut()
                .get_mut::<DelegatecallInjectionMetadata>()
                .unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + DELEGATECALL_INJECTION_BUG_IDX;

            EVMBugResult::new_simple(
                "Delegatecall Injection".to_string(),
                bug_idx,
                format!(
                    "Contract {addr:?} performs a DELEGATECALL at pc {pc} whose target has varied across multiple distinct addresses during fuzzing -- the delegatecall target is effectively attacker-controlled, which can corrupt {addr:?}'s own storage/identity.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
