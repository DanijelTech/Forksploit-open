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
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::UNBACKED_MINT_BUG_IDX,
        types::{convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd]; // totalSupply()
const OWNER_SELECTOR: [u8; 4] = [0x8d, 0xa5, 0xcb, 0x5b]; // owner()

fn sub_bug_idx(target: &EVMAddress) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    (hasher.finish() << 8) + UNBACKED_MINT_BUG_IDX
}

/// Detects an UNBACKED MINT on a native-backed supply token: `totalSupply()`
/// grows during a transaction that brought in no native value at all, while
/// the contract already holds native ETH that the existing supply is meant to
/// be a claim on. The new supply is therefore not backed by anything -- the
/// caller minted free claims on other holders' deposited ETH.
///
/// This is the bytecode-detectable core of the 2025-2026 "unbacked mint" /
/// "infinite mint" bucket (~$334M Liquid Network + ~$21M infinite-mint
/// incidents). It sits between two existing oracles without overlapping
/// either:
///
/// * `erc20.rs` reports "Fund Loss" -- native/token LEAVING the contract.
///   A mint is the opposite direction and never trips it.
/// * `eth_backing.rs` reports INSOLVENCY of the `balances(address)` bank
///   shape, and deliberately EXCLUDES ERC20-shaped contracts (it bails out
///   as soon as `totalSupply()` answers, see its own `not_applicable` path).
///   A token that exposes `totalSupply()` is exactly what it skips.
///
/// Review-tier, not Confirmed: a public `mint()` is sometimes intentional
/// (a faucet, a rebase controller, an inflationary token whose supply is not
/// meant to be native-backed at all), so the shape being right is not on its
/// own proof of a bug -- hence the deterministic extra gates below, and a
/// human glance at whether the token is *supposed* to be native-backed.
///
/// Detection gates, all deterministic:
/// 1. `totalSupply()` answers on both pre- and post-state (ERC20-shaped).
/// 2. post supply > pre supply (a mint happened in this transaction).
/// 3. the caller paid nothing (`txn_value == 0`).
/// 4. the contract's native balance did NOT increase (no native inflow that
///    could have backed the new supply -- e.g. a normal `deposit()`).
/// 5. the contract already held native ETH and already had non-zero supply
///    (there is an existing backed pool to dilute; excludes a fresh
///    contract's very first mint and pure ERC20/ERC20 LP tokens, which hold
///    no native ETH).
/// 6. the caller is not `owner()` when an `owner()` is readable (an admin
///    mint is usually legitimate).
pub struct UnbackedMintOracle {
    reported: RefCell<HashSet<(EVMAddress, EVMAddress)>>,
}

impl Default for UnbackedMintOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl UnbackedMintOracle {
    pub fn new() -> Self {
        Self {
            reported: RefCell::new(HashSet::new()),
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
    > for UnbackedMintOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {

        // A control-leak (post-execution) state is an INTERMEDIATE state:
        // feedback.rs's OracleFeedback unconditionally discards any oracle()
        // result produced on it. Writing the one-shot "already reported"
        // bookkeeping below on such a state would permanently suppress the
        // real, finished execution that would surface this finding -- exactly
        // the bug the sibling oracles (self_referral, curve_virtual_price,
        // twap_manipulation, ...) already guard against. Defer instead.
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }
        let target = ctx.input.get_contract();
        let caller = ctx.input.get_caller();
        if self.reported.borrow().contains(&(target, caller)) {
            return vec![];
        }

        let probe = [(target, Bytes::from(TOTAL_SUPPLY_SELECTOR.to_vec()))];
        let executor = ctx.executor.clone();
        let read = |state: &EVMState, fuzz_state: &mut EVMFuzzState| {
            let raw = executor.deref().borrow_mut().fast_static_call(&probe, state, fuzz_state);
            raw.first()
                .filter(|r| r.len() == 32)
                .and_then(|r| EVMU256::try_from_be_slice(r))
        };

        let Some(pre_supply) = read(ctx.pre_state, ctx.fuzz_state) else {
            return vec![];
        };
        let post_state = ctx.post_state.clone();
        let Some(post_supply) = read(&post_state, ctx.fuzz_state) else {
            return vec![];
        };
        if post_supply <= pre_supply {
            return vec![];
        }

        if ctx.input.get_txn_value().unwrap_or(EVMU256::ZERO) != EVMU256::ZERO {
            return vec![];
        }

        let pre_balance = ctx.pre_state.balance.get(&target).copied().unwrap_or(EVMU256::ZERO);
        let post_balance = ctx.post_state.balance.get(&target).copied().unwrap_or(EVMU256::ZERO);
        if post_balance > pre_balance {
            return vec![];
        }

        // Native-backed, pre-existing supply only -- see gates 5/6 above.
        if pre_balance == EVMU256::ZERO || pre_supply == EVMU256::ZERO {
            return vec![];
        }

        let owner_raw = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&[(target, Bytes::from(OWNER_SELECTOR.to_vec()))], ctx.pre_state, ctx.fuzz_state);
        if let Some(owner) = owner_raw
            .first()
            .filter(|r| r.len() == 32)
            .and_then(|r| EVMU256::try_from_be_slice(r))
            .map(convert_u256_to_h160)
        {
            if owner != EVMAddress::default() && owner == caller {
                return vec![];
            }
        }

        if !self.reported.borrow_mut().insert((target, caller)) {
            return vec![];
        }

        let minted = post_supply - pre_supply;
        let bug_idx = sub_bug_idx(&target);
        EVMBugResult::new_simple(
            "Unbacked Mint (Supply Growth Without Backing)".to_string(),
            bug_idx,
            format!(
                "{target:?}'s totalSupply() grew by {minted} in a transaction that paid no value and brought no native inflow, while the contract already held {pre_balance} wei of native balance backing a pre-existing supply of {pre_supply}. Caller {caller:?} received newly minted supply with no backing, diluting the native claim of existing holders (the 2025-2026 unbacked/infinite-mint class).\n"
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
        )
        .push_to_output();
        vec![bug_idx]
    }
}
