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
        oracles::ZERO_ADDRESS_SETTER_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ZeroAddressSetterMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(ZeroAddressSetterMetadata);

/// Reports every entry in `ctx.post_state.zero_address_setters` (populated
/// by `host.rs`'s own 0x55 SSTORE handling) that's genuinely NEW in this
/// transaction: an SSTORE that wrote exactly zero into a slot which
/// previously held a nonzero, address-shaped value (upper 96 bits clear),
/// at a pc the fuzzer does NOT already know writes a mapping/array slot.
///
/// That is the missing `require(newAddr != address(0))` guard on a direct
/// state-variable setter -- `owner = newOwner`, `admin = x`,
/// `implementation = impl` -- which permanently cements the privileged
/// role to the burn address. Review-tier: the shape is exactly right for
/// the bug, but a contract can legitimately zero an address on purpose
/// (deliberate renounce/disable), so this needs a human glance at whether
/// zeroing here is an intended terminal state or an unguarded input.
/// Diffs against `ctx.pre_state` from the start (same convention as
/// forced_eth_accounting.rs/ecrecover.rs) so a slot already zeroed in an
/// earlier transaction isn't re-reported.
pub struct ZeroAddressSetterOracle {}

impl Default for ZeroAddressSetterOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroAddressSetterOracle {
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
    > for ZeroAddressSetterOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize, EVMU256)> = ctx
            .post_state
            .zero_address_setters
            .iter()
            .filter(|e| !ctx.pre_state.zero_address_setters.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<ZeroAddressSetterMetadata>() {
            ctx.fuzz_state
                .metadata_map_mut()
                .insert(ZeroAddressSetterMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc, slot) in new_hits.iter() {
            let metadata = ctx
                .fuzz_state
                .metadata_map_mut()
                .get_mut::<ZeroAddressSetterMetadata>()
                .unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + ZERO_ADDRESS_SETTER_BUG_IDX;

            EVMBugResult::new_simple(
                "Zero Address Setter".to_string(),
                bug_idx,
                format!(
                    "{addr:?} wrote address(0) into storage slot {slot:?} at pc {pc}, overwriting a previously-set address value with no visible zero-check. If this slot holds an owner/admin/implementation role, the privileged address is now permanently the burn address -- a missing `require(newAddr != address(0))` guard (SWC-131, presence of unused variables / zero-address assignment).\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
