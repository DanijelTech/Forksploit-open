use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
    ops::Deref,
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::CURVE_VIRTUAL_PRICE_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const GET_VIRTUAL_PRICE_SELECTOR: [u8; 4] = [0xbb, 0x7b, 0x8b, 0x80]; // get_virtual_price()

/// Detects Curve-style StableSwap virtual-price manipulation: a scoped,
/// standalone equivalent of what `PairBalanceOracle` does for Uniswap V2
/// pairs, but for Curve pools and using a cleaner signal.
///
/// `get_virtual_price()` (LP-token value in terms of the underlying assets,
/// derived from the pool's StableSwap invariant `D`) is designed to be
/// monotonically non-decreasing for any sequence of legitimate operations:
/// swaps only ever add fees (price goes up), and proportional
/// add/remove-liquidity leaves it unchanged modulo rounding. A real
/// *decrease* has no legitimate cause -- it is exactly the signature of
/// several real Curve incidents (e.g. the 2023 read-only-reentrancy class of
/// bugs), where a mid-transaction state snapshot lets a caller extract value
/// disproportionate to the LP tokens they hold or burn.
///
/// This fingerprints a target as "Curve-shaped" purely by whether
/// `get_virtual_price()` answers with a plausible value -- no ABI/source
/// needed, same black-box philosophy as the rest of this project's oracles.
///
/// Scope note: unlike the existing Uniswap V2 pair support, this does NOT
/// hook into the flashloan/token-transformer pricing pipeline
/// (`src/evm/tokens/v2_transformer.rs` and friends) -- that would mean
/// teaching the flashloan harness to price and swap through an entirely
/// different (StableSwap) invariant, a much larger undertaking. This oracle
/// only detects the manipulation signal itself; it does not fund or drive a
/// flashloan-style attack through a Curve pool the way the V2 path can.
pub struct CurveVirtualPriceOracle {
    is_curve_pool: RefCell<HashMap<EVMAddress, bool>>,
    // Targets the Review-tier "Decrease" bug_type has already been
    // reported for -- stops that ONE report from spamming once it's
    // happened, but deliberately does NOT stop further oracle() calls
    // for the same target: a LATER call might still show the caller
    // actually profiting (see `confirmed` below), which is worth
    // reporting even after the weaker anomaly already fired once.
    reported: RefCell<HashSet<EVMAddress>>,
    // Targets the Confirmed-tier "(Profit Confirmed)" bug_type has
    // already been reported for. Once this fires, there is nothing
    // stronger left to find for this target.
    confirmed: RefCell<HashSet<EVMAddress>>,
}

impl Default for CurveVirtualPriceOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl CurveVirtualPriceOracle {
    pub fn new() -> Self {
        Self {
            is_curve_pool: RefCell::new(HashMap::new()),
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
    > for CurveVirtualPriceOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let target = ctx.input.get_contract();
        if self.confirmed.borrow().contains(&target) {
            return vec![];
        }

        // Confirmed live 2026-11-01: same fix as oracles/
        // twap_manipulation.rs -- a call that leaks control (e.g. an
        // outgoing `.transfer()` to the caller triggering their own
        // fallback/receive()) is not yet finished, and feedback.rs's
        // OracleFeedback unconditionally discards any oracle() result
        // from it. Updating the one-shot `reported`/`confirmed`
        // bookkeeping below on such a call would permanently suppress
        // the real, profit-confirmed finding without it ever actually
        // surfacing once the real (finished) call comes along.
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }

        let probe = [(target, Bytes::from(GET_VIRTUAL_PRICE_SELECTOR.to_vec()))];
        let pre_raw = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&probe, ctx.pre_state, ctx.fuzz_state);
        let pre_price = (pre_raw[0].len() == 32)
            .then(|| EVMU256::try_from_be_slice(&pre_raw[0]))
            .flatten();

        let already_known = self.is_curve_pool.borrow().get(&target).copied();
        let is_curve = match already_known {
            Some(known) => known,
            None => {
                let known = matches!(pre_price, Some(v) if v != EVMU256::ZERO);
                self.is_curve_pool.borrow_mut().insert(target, known);
                known
            }
        };
        if !is_curve {
            return vec![];
        }

        let post_raw = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&probe, &ctx.post_state, ctx.fuzz_state);
        let post_price = (post_raw[0].len() == 32)
            .then(|| EVMU256::try_from_be_slice(&post_raw[0]))
            .flatten();

        let (Some(pre_price), Some(post_price)) = (pre_price, post_price) else {
            return vec![];
        };

        if post_price >= pre_price {
            return vec![];
        }

        let mut hasher = DefaultHasher::new();
        target.hash(&mut hasher);
        let bug_idx = (hasher.finish() << 8) + CURVE_VIRTUAL_PRICE_BUG_IDX;

        // Secondary confirmation, same reasoning as
        // oracles/twap_manipulation.rs's own: a virtual-price decrease
        // alone proves LP value was lost, but not that THIS caller is the
        // one who profited from it (a read-only-reentrancy victim could
        // be a third party reading the price elsewhere). If the caller
        // who triggered the decrease also walked away from this SAME
        // transaction with a net ETH balance increase, that is
        // demonstrable profit directly tied to the decrease, not just the
        // underlying anomaly. Reported as a separate, Confirmed-tier
        // bug_type; the weaker Review-tier "Decrease" finding is
        // unchanged for the common case where no such profit is observed
        // (e.g. the loss is real but was extracted by a different
        // contract/caller this black-box check can't see).
        let caller = ctx.input.get_caller();
        let caller_profited = match (ctx.pre_state.get_balance(&caller), ctx.post_state.balance.get(&caller)) {
            (Some(pre), Some(post)) => post > pre,
            _ => false,
        };

        let (bug_type, bug_info) = if caller_profited {
            self.confirmed.borrow_mut().insert(target);
            (
                "Curve Virtual Price Decrease (Profit Confirmed)".to_string(),
                format!(
                    "Curve-style pool {target:?}'s get_virtual_price() decreased from {pre_price:?} to {post_price:?} as a result of this call, AND the caller {caller:?} who triggered it walked away from this SAME transaction with a net native-token balance increase -- confirmed profit directly tied to the decrease (e.g. read-only reentrancy), not just the underlying anomaly.\n",
                ),
            )
        } else {
            // Only the weaker signal this time -- don't spam it once
            // already reported for this target, but keep letting future
            // calls through: one of them might still show profit.
            if self.reported.borrow().contains(&target) {
                return vec![];
            }
            self.reported.borrow_mut().insert(target);
            (
                "Curve Virtual Price Decrease".to_string(),
                format!(
                    "Curve-style pool {target:?}'s get_virtual_price() decreased from {pre_price:?} to {post_price:?} as a result of this call -- LP-token value went down with no legitimate cause (swaps only add fees, proportional liquidity changes leave it unchanged). This is the signature of several real Curve incidents (e.g. read-only reentrancy): a caller extracted value disproportionate to any LP tokens held or burned.\n",
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
