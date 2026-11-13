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
        oracles::FORCED_ETH_ACCOUNTING_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ForcedEthAccountingMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(ForcedEthAccountingMetadata);

/// Reports every entry in `ctx.post_state.forced_eth_accounting_checks`
/// (populated by `host.rs`'s own 0x47 SELFBALANCE / 0x31 BALANCE / 0x14
/// EQ handling) that's genuinely NEW in this transaction: an EQ
/// comparison using `address(this).balance`/`SELFBALANCE` as one of its
/// two operands -- SWC-132. Unlike `eth_backing.rs` (which checks
/// `sum(balances) > real balance`, an INSOLVENCY direction), this is the
/// OPPOSITE, DoS direction: an EXACT equality against the contract's own
/// real ETH holdings can be permanently broken by force-feeding it even
/// 1 extra wei via `SELFDESTRUCT` (targeting any address always succeeds
/// and bypasses every `receive()`/`payable` guard) or a `block.coinbase`
/// mining reward -- no legitimate transaction path can ever remove
/// unwanted ETH again, so the check fails forever once donated.
///
/// Review-tier, not Confirmed: an exact-equality check against the
/// contract's own balance is sometimes a deliberate, narrow invariant
/// assertion (e.g. a one-time setup/init check) rather than live,
/// attacker-reachable logic -- worth a human look at whether this
/// specific check is reachable AFTER deployment, not a certain DoS.
/// Diffs against `ctx.pre_state` from the start (see
/// oracles/ecrecover.rs's 2026-11-02/03 doc comments for why that
/// matters -- built in here, not added later as a fix).
pub struct ForcedEthAccountingOracle {}

impl Default for ForcedEthAccountingOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ForcedEthAccountingOracle {
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
    > for ForcedEthAccountingOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize)> = ctx
            .post_state
            .forced_eth_accounting_checks
            .iter()
            .filter(|e| !ctx.pre_state.forced_eth_accounting_checks.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<ForcedEthAccountingMetadata>() {
            ctx.fuzz_state
                .metadata_map_mut()
                .insert(ForcedEthAccountingMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx
                .fuzz_state
                .metadata_map_mut()
                .get_mut::<ForcedEthAccountingMetadata>()
                .unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + FORCED_ETH_ACCOUNTING_BUG_IDX;

            EVMBugResult::new_simple(
                "Forced Native Value Accounting".to_string(),
                bug_idx,
                format!(
                    "{addr:?} executed an EQ comparison at pc {pc} against its own real native-token balance \
                     (SELFBALANCE/BALANCE(address(this))) -- an exact-equality check that a SELFDESTRUCT \
                     donation of even 1 wei to this address can brick permanently, since no legitimate \
                     transaction can ever remove unwanted native value.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
