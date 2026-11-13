use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashSet},
    hash::{Hash, Hasher},
    ops::Deref,
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::TWAP_MANIPULATION_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const GET_RESERVES_SELECTOR: [u8; 4] = [0x09, 0x02, 0xf1, 0xac]; // getReserves()

/// Detects the precondition for TWAP manipulation: a Uniswap-V2-shaped
/// pair's reserve ratio (spot price) moving by more than 2x in a SINGLE
/// transaction. This is exactly the primitive behind real flash-loan price
/// manipulation attacks (push the spot price far in one block, then have
/// some OTHER contract read that skewed price in the same block/tx before
/// anything can arbitrage it back).
///
/// This does not (and black-box, without tracing which other contract
/// reads this specific pair's price in the same block, cannot) prove a
/// downstream consumer was actually exploited -- it reports the precursor
/// condition, same honesty level as `PriceFeedStalenessOracle`. A pair
/// whose price swings this hard in one transaction is worth a human
/// checking "what else reads this pool's price, and over what window."
///
/// Fingerprints a target as a V2-shaped pair purely by whether
/// `getReserves()` answers with a plausible (uint112, uint112, uint32)
/// tuple -- no ABI/source needed, and deliberately independent of the
/// flashloan middleware's own (onchain-only) pair registration, so this
/// works in offchain fuzzing too.
pub struct TwapManipulationOracle {
    // Targets the Review-tier "Precondition" bug_type has already been
    // reported for -- stops that ONE report from spamming once it's
    // happened, but deliberately does NOT stop further oracle() calls
    // for the same target: a LATER call might still show the caller
    // actually profiting (see `confirmed` below), which is worth
    // reporting even after the weaker precondition already fired once.
    reported: RefCell<HashSet<EVMAddress>>,
    // Targets the Confirmed-tier "(Profit Confirmed)" bug_type has
    // already been reported for. Once this fires, there is nothing
    // stronger left to find for this target, so THIS one does stop
    // further oracle() work for it (same one-shot spirit as the
    // original `reported` set, just for the strongest signal).
    confirmed: RefCell<HashSet<EVMAddress>>,
}

impl Default for TwapManipulationOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl TwapManipulationOracle {
    pub fn new() -> Self {
        Self {
            reported: RefCell::new(HashSet::new()),
            confirmed: RefCell::new(HashSet::new()),
        }
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
    > for TwapManipulationOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let target = ctx.input.get_contract();
        if self.confirmed.borrow().contains(&target) {
            return vec![];
        }

        // Confirmed live 2026-11-01: a call that leaks control (e.g. this
        // one's own `.transfer()` to the caller triggers the caller's
        // fallback/receive(), a classic control-leak shape) is not yet a
        // finished transaction -- feedback.rs's OracleFeedback
        // unconditionally discards any oracle() result from such a call.
        // `ctx.post_state` also isn't guaranteed to reflect final
        // reserves yet. Reported here BEFORE this check existed:
        // the real profit-confirmed case (reserves swung >2x AND the
        // caller's ETH balance net increased) was reachable but never
        // actually surfaced, because the one-shot `reported`/`confirmed`
        // bookkeeping below would otherwise still need to run on a
        // discarded call, permanently suppressing the eventual finished
        // one. Defer entirely instead -- same fix as
        // oracles/self_referral.rs and oracles/stale_guard.rs.
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }

        let probe = [(target, Bytes::from(GET_RESERVES_SELECTOR.to_vec()))];
        let pre_raw = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&probe, ctx.pre_state, ctx.fuzz_state);
        if pre_raw[0].len() != 96 {
            // Not a (uint112, uint112, uint32) tuple -- not getReserves().
            return vec![];
        }
        let post_raw = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&probe, &ctx.post_state, ctx.fuzz_state);
        if post_raw[0].len() != 96 {
            return vec![];
        }

        // getReserves() returns (uint112 reserve0, uint112 reserve1, uint32
        // blockTimestampLast), each left-padded to 32 bytes -- read directly
        // from the ABI-encoded return data (independent of the packed
        // storage layout `reserve_parser` expects).
        let (r0_pre, r1_pre) = (
            EVMU256::try_from_be_slice(&pre_raw[0][0..32]).unwrap_or(EVMU256::ZERO),
            EVMU256::try_from_be_slice(&pre_raw[0][32..64]).unwrap_or(EVMU256::ZERO),
        );
        let (r0_post, r1_post) = (
            EVMU256::try_from_be_slice(&post_raw[0][0..32]).unwrap_or(EVMU256::ZERO),
            EVMU256::try_from_be_slice(&post_raw[0][32..64]).unwrap_or(EVMU256::ZERO),
        );
        if r0_pre == EVMU256::ZERO || r1_pre == EVMU256::ZERO || r0_post == EVMU256::ZERO || r1_post == EVMU256::ZERO {
            return vec![];
        }

        // price = r1/r0. Compare ratios via cross-multiplication (exact
        // integer math, no precision loss): price doubled if
        // r1_post * r0_pre > 2 * r1_pre * r0_post; halved if the reverse
        // with the factor of 2 on the other side. uint112 * uint112 fits
        // comfortably in 256 bits even after the extra factor of 2.
        let doubled = r1_post.saturating_mul(r0_pre) > r1_pre.saturating_mul(r0_post).saturating_mul(EVMU256::from(2));
        let halved = r1_pre.saturating_mul(r0_post) > r1_post.saturating_mul(r0_pre).saturating_mul(EVMU256::from(2));
        if !doubled && !halved {
            return vec![];
        }

        let mut hasher = DefaultHasher::new();
        target.hash(&mut hasher);
        let bug_idx = (hasher.finish() << 8) + TWAP_MANIPULATION_BUG_IDX;

        // Secondary confirmation: the precondition alone (price moved) is
        // not itself harm -- someone else has to read that skewed price
        // and benefit. The one beneficiary this can check black-box,
        // without tracing which other contract reads this pool, is the
        // CALLER who moved the price: if their own ETH balance net
        // increased as a result of this SAME transaction, that is real,
        // demonstrable profit directly tied to the manipulation, not an
        // inference about what might happen elsewhere. Reported as a
        // separate, Confirmed-tier bug_type (see oracle.rs's
        // classify_confidence and solution/mod.rs's
        // is_confirmed_exploitable_bug) -- the weaker, Review-tier
        // "Precondition" finding is unchanged for the common case where
        // no such profit is observed.
        let caller = ctx.input.get_caller();
        let caller_profited = match (ctx.pre_state.get_balance(&caller), ctx.post_state.balance.get(&caller)) {
            (Some(pre), Some(post)) => post > pre,
            _ => false,
        };

        let (bug_type, bug_info) = if caller_profited {
            self.confirmed.borrow_mut().insert(target);
            (
                "TWAP Manipulation (Profit Confirmed)".to_string(),
                format!(
                    "Pair {target:?}'s spot price moved by more than 2x in a single transaction (reserves {:?} -> {:?}), AND the caller {caller:?} who moved it walked away from this SAME transaction with a net native-token balance increase -- confirmed profit directly tied to the manipulation, not just the precondition for one.\n",
                    (r0_pre, r1_pre), (r0_post, r1_post)
                ),
            )
        } else {
            // Only the weaker signal this time -- don't spam it once
            // already reported for this target, but (unlike `confirmed`
            // above) keep letting future calls through: one of them
            // might still show the caller profiting later.
            if self.reported.borrow().contains(&target) {
                return vec![];
            }
            self.reported.borrow_mut().insert(target);
            (
                "TWAP Manipulation Precondition".to_string(),
                format!(
                    "Pair {target:?}'s spot price moved by more than 2x in a single transaction (reserves {:?} -> {:?}) -- the exact primitive flash-loan TWAP manipulation relies on. Check what else reads this pool's price (and over what averaging window) in the same block.\n",
                    (r0_pre, r1_pre), (r0_post, r1_post)
                ),
            )
        };

        EVMBugResult::new_simple(
            bug_type,
            bug_idx,
            bug_info,
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
        )
        .push_to_output();

        vec![bug_idx]
    }
}
