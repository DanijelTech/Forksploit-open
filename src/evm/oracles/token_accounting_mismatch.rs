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
        oracles::TOKEN_ACCOUNTING_MISMATCH_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::Oracle,
    state::HasExecutionResult,
};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TokenAccountingMismatchMetadata {
    pub known: HashMap<(EVMAddress, usize), u8>,
}

impl_serdeany!(TokenAccountingMismatchMetadata);

/// Reports every entry in `ctx.post_state.token_accounting_mismatches`
/// (populated by `host.rs`'s own call()/0x55-SSTORE handling -- this bug
/// class needed the real decoded `CallInputs`, which only the host's own
/// `call()` method sees, not a separate opcode-only middleware) that's
/// genuinely NEW in this transaction: a successful
/// `transferFrom(from, address(this), amount)` immediately followed by an
/// accounting SSTORE that adds the UNVERIFIED `amount` argument straight
/// to a prior balance, instead of the real, observed balanceOf() delta.
/// Fee-on-transfer tokens (deduct a cut) and rebasing tokens (balance
/// drifts independently of transfers) both break this assumption --
/// crediting MORE than was actually received, a real, repeated DeFi
/// accounting-drift bug class (not hypothetical: numerous real token
/// integrations have been drained this way).
///
/// Review-tier, not Confirmed: this is a heuristic proximity signal (same
/// slot, same call frame), not confirmed dataflow all the way from the
/// SLOAD to the SSTORE, and plenty of real tokens genuinely have no fee/
/// rebase at all, in which case this exact pattern is completely safe --
/// worth a human look at which specific token is involved, not a certain
/// bug. Diffs against `ctx.pre_state` from the start (see
/// oracles/ecrecover.rs's 2026-11-02/03 doc comments for why that
/// matters -- built in here, not added later as a fix).
pub struct TokenAccountingMismatchOracle {}

impl Default for TokenAccountingMismatchOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenAccountingMismatchOracle {
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
    > for TokenAccountingMismatchOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let new_hits: Vec<(EVMAddress, usize)> = ctx
            .post_state
            .token_accounting_mismatches
            .iter()
            .filter(|e| !ctx.pre_state.token_accounting_mismatches.contains(*e))
            .cloned()
            .collect();
        if new_hits.is_empty() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<TokenAccountingMismatchMetadata>() {
            ctx.fuzz_state
                .metadata_map_mut()
                .insert(TokenAccountingMismatchMetadata::default());
        }

        let mut violations = vec![];
        for (addr, pc) in new_hits.iter() {
            let metadata = ctx
                .fuzz_state
                .metadata_map_mut()
                .get_mut::<TokenAccountingMismatchMetadata>()
                .unwrap();
            let count = metadata.known.entry((*addr, *pc)).or_insert(0);
            if *count > 3 {
                continue;
            }
            *count += 1;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + TOKEN_ACCOUNTING_MISMATCH_BUG_IDX;

            EVMBugResult::new_simple(
                "Token Accounting Mismatch".to_string(),
                bug_idx,
                format!(
                    "{addr:?} executed SSTORE at pc {pc} crediting the raw `amount` argument of a prior \
                     successful transferFrom(from, address(this), amount) directly onto a storage balance, \
                     instead of the real, observed balanceOf() delta. A fee-on-transfer or rebasing token \
                     would make the credited amount larger than what was actually received, letting a \
                     depositor withdraw more than they put in.\n",
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
