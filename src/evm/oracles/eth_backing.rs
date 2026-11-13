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
        oracles::ETH_BACKING_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const BALANCES_SELECTOR: [u8; 4] = [0x27, 0xe2, 0x35, 0xe3]; // balances(address)
const TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd]; // totalSupply()

/// Economic invariant check: for contracts using the extremely common
/// "mapping(address => uint256) balances" pattern (the textbook
/// bank/vault/pool shape -- not the ERC20 standard, which this
/// deliberately excludes via the `totalSupply()` fingerprint below, since
/// a real token's `balanceOf` isn't a claim on the contract's OWN ETH),
/// checks whether the sum of every caller's own recorded `balances(addr)`
/// ever exceeds the contract's real ETH holdings.
///
/// If it does, the contract has promised out more ETH than it actually
/// has: later withdrawers will find calls reverting for no visible reason
/// (classic insolvency/bank-run symptom), independent of any specific
/// known bug *type* -- this catches whatever COMBINATION of otherwise
/// individually-unremarkable operations broke the underlying economic
/// promise, which no single-bug-pattern oracle is positioned to catch.
///
/// Heuristic, not universal: it only recognizes the one specific
/// "balances(address)" selector name. A contract using a different
/// variable name for the same concept won't fingerprint, and is simply
/// not checked -- a false negative, never a false positive, which is the
/// right default for an informational economic-health check like this.
pub struct EthBackingOracle {
    known_callers: RefCell<HashMap<EVMAddress, HashSet<EVMAddress>>>,
    not_applicable: RefCell<HashSet<EVMAddress>>,
    reported: RefCell<HashSet<EVMAddress>>,
}

impl Default for EthBackingOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl EthBackingOracle {
    pub fn new() -> Self {
        Self {
            known_callers: RefCell::new(HashMap::new()),
            not_applicable: RefCell::new(HashSet::new()),
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
    > for EthBackingOracle
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
        if self.reported.borrow().contains(&target) || self.not_applicable.borrow().contains(&target) {
            return vec![];
        }

        let caller = ctx.input.get_caller();
        self.known_callers
            .borrow_mut()
            .entry(target)
            .or_default()
            .insert(caller);

        let real_balance = ctx.post_state.balance.get(&target).copied().unwrap_or(EVMU256::ZERO);
        if real_balance == EVMU256::ZERO {
            // Nothing at stake yet -- also cheaply avoids probing every
            // contract on every single transaction before any ETH has
            // ever landed in it.
            return vec![];
        }

        let total_supply_probe = [(target, Bytes::from(TOTAL_SUPPLY_SELECTOR.to_vec()))];
        let ts_raw =
            ctx.executor
                .deref()
                .borrow_mut()
                .fast_static_call(&total_supply_probe, &ctx.post_state, ctx.fuzz_state);
        if ts_raw[0].len() == 32 {
            // Looks ERC20-shaped -- balanceOf/balances here is a token
            // claim, not an ETH claim on this contract. Not applicable.
            self.not_applicable.borrow_mut().insert(target);
            return vec![];
        }

        let callers: Vec<EVMAddress> = self
            .known_callers
            .borrow()
            .get(&target)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let probes: Vec<(EVMAddress, Bytes)> = callers
            .iter()
            .map(|c| {
                let mut data = BALANCES_SELECTOR.to_vec();
                data.extend_from_slice(&[0u8; 12]);
                data.extend_from_slice(c.as_slice());
                (target, Bytes::from(data))
            })
            .collect();
        if probes.is_empty() {
            return vec![];
        }
        let raw = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&probes, &ctx.post_state, ctx.fuzz_state);

        let mut any_answered = false;
        let mut total_promised = EVMU256::ZERO;
        for r in &raw {
            if r.len() != 32 {
                continue;
            }
            any_answered = true;
            if let Some(v) = EVMU256::try_from_be_slice(r) {
                total_promised = total_promised.saturating_add(v);
            }
        }
        if !any_answered {
            // Doesn't implement balances(address) at all -- not this pattern.
            self.not_applicable.borrow_mut().insert(target);
            return vec![];
        }

        if total_promised <= real_balance {
            return vec![];
        }

        self.reported.borrow_mut().insert(target);

        let mut hasher = DefaultHasher::new();
        target.hash(&mut hasher);
        let bug_idx = (hasher.finish() << 8) + ETH_BACKING_BUG_IDX;

        EVMBugResult::new_simple(
            "Insolvent: Promised Native Value Exceeds Real Balance".to_string(),
            bug_idx,
            format!(
                "{:?}'s own recorded balances() for every caller observed so far sum to {:?}, more than the contract's real native-token balance of {:?} -- it has promised out more than it holds. Later withdrawals will start failing for honest users even though their recorded balance looks fine; this is a bank-run/insolvency condition, not tied to any single known bug type.\n",
                target, total_promised, real_balance
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
        )
        .push_to_output();

        vec![bug_idx]
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::evm::{
        host::FuzzHost,
        input::EVMInputTy,
        mutator::AccessPattern,
        scheduler::PowerABIScheduler,
        types::{generate_random_address, EVMQueueExecutor},
        vm::{EVMExecutor, PostExecutionCtx},
    };
    use crate::state::FuzzState;
    use crate::state_input::StagedVMState;

    /// Build an `EVMInput` and an executor, then run the oracle against a
    /// state whose post-execution marker is set (or not). The oracle's
    /// FIRST observable act is to record the caller in `known_callers`, so
    /// whether that set stays empty is a direct, causal probe of the guard.
    fn run_oracle_with_post_execution(post_execution: bool) -> bool {
        let path = std::path::Path::new("work_dir");
        if !path.exists() {
            let _ = std::fs::create_dir(path);
        }
        let mut state: EVMFuzzState = FuzzState::new(0);
        let deployer = generate_random_address(&mut state);
        let executor: Rc<RefCell<EVMQueueExecutor>> = Rc::new(RefCell::new(EVMExecutor::new(
            FuzzHost::new(PowerABIScheduler::new(), "work_dir".to_string()),
            deployer,
        )));

        let target = generate_random_address(&mut state);
        let caller = generate_random_address(&mut state);

        let mut evm_state = EVMState::new();
        if post_execution {
            evm_state.post_execution.push(PostExecutionCtx {
                constraints: vec![],
                pes: vec![],
                must_step: false,
            });
        }
        state.get_execution_result_mut().new_state = StagedVMState::new_with_state(evm_state);

        let input = EVMInput {
            caller,
            contract: target,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: bytes::Bytes::new(),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: std::collections::HashMap::new(),
        };

        let pre_state = input.get_state().clone();
        let oracle = EthBackingOracle::new();
        let mut ctx: EVMOracleCtx<'_> =
            EVMOracleCtx::new(&mut state, &pre_state, executor.clone(), &input);
        let _ = oracle.oracle(&mut ctx, 0);

        // `known_callers` is written by the oracle's very first statement
        // after the guard; non-empty means the guard did NOT fire.
        !oracle.known_callers.borrow().is_empty()
    }

    /// A control-leak (post-execution) state is INTERMEDIATE: feedback.rs
    /// discards its oracle() output, so the oracle must NOT commit its
    /// one-shot bookkeeping there -- otherwise the real, finished execution
    /// that would surface the finding is permanently suppressed. This test
    /// fails on the pre-guard code (which inserted the caller regardless).
    #[test]
    fn post_execution_state_does_not_commit_bookkeeping() {
        assert!(
            !run_oracle_with_post_execution(true),
            "oracle committed known_callers on an INTERMEDIATE (control-leak) state -- \
             the guard is missing or misplaced"
        );
    }

    /// The guard must not disable the oracle on a real, finished execution.
    #[test]
    fn finished_state_still_runs_the_oracle() {
        assert!(
            run_oracle_with_post_execution(false),
            "oracle bailed on a FINISHED execution -- the guard is over-broad"
        );
    }
}
