use std::{cell::RefCell, collections::HashSet, ops::Deref};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::PRICE_FEED_STALENESS_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

// latestRoundData() -- Chainlink AggregatorV3Interface
const LATEST_ROUND_DATA_SELECTOR: [u8; 4] = [0xfe, 0xaf, 0x96, 0x8c];

// Conservative: most real feeds update far more often than this, but some
// legitimately low-volatility feeds (e.g. stablecoin pairs) use a 24h
// heartbeat. 48h gives real production feeds headroom while still catching
// a feed nobody has looked at in two days -- a known real-world incident
// pattern (consumers that trust a feed without checking `updatedAt`).
const STALENESS_THRESHOLD_SECONDS: u64 = 48 * 60 * 60;

fn sub_bug_idx(target: &EVMAddress) -> u64 {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    (hasher.finish() << 8) + PRICE_FEED_STALENESS_BUG_IDX
}

/// Detects stale Chainlink-style price feeds purely by fingerprinting:
/// `latestRoundData()` answering with a plausible 5-word tuple is treated
/// as "this is a price feed," and its `updatedAt` is compared against the
/// current block timestamp. This does NOT (and black-box, without tracing
/// a consumer's internal calls, cannot) prove that some OTHER contract
/// blindly trusts this feed without its own staleness check -- it reports
/// the precondition: a feed in the fuzzed target set that hasn't updated
/// in a long time. That is itself worth a human's attention before
/// production, since several real incidents (e.g. Venus/Mango-class price
/// oracle manipulation) trace back to exactly this kind of blind trust in
/// a feed that had gone stale or was otherwise manipulable.
pub struct PriceFeedStalenessOracle {
    reported: RefCell<HashSet<EVMAddress>>,
}

impl Default for PriceFeedStalenessOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceFeedStalenessOracle {
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
    > for PriceFeedStalenessOracle
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
        if self.reported.borrow().contains(&target) {
            return vec![];
        }

        let probe = [(target, Bytes::from(LATEST_ROUND_DATA_SELECTOR.to_vec()))];
        let raw = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&probe, &ctx.post_state, ctx.fuzz_state);
        if raw[0].len() != 160 {
            // Not a 5-word (uint80, int256, uint256, uint256, uint80) tuple
            // -- not latestRoundData(), or not this shape.
            return vec![];
        }
        let data = &raw[0];

        let round_id = EVMU256::try_from_be_slice(&data[0..32]).unwrap_or(EVMU256::ZERO);
        let answer = EVMU256::try_from_be_slice(&data[32..64]).unwrap_or(EVMU256::ZERO);
        let Some(updated_at) = EVMU256::try_from_be_slice(&data[96..128]) else {
            return vec![];
        };
        // Weak but useful fingerprint guards: a real feed has a nonzero
        // round id and a nonzero answer (price feeds essentially never
        // legitimately report a zero price).
        if round_id == EVMU256::ZERO || answer == EVMU256::ZERO || updated_at == EVMU256::ZERO {
            return vec![];
        }

        let block_ts = ctx.input.get_vm_env().block.timestamp;
        if updated_at > block_ts {
            // Nonsensical (future timestamp) -- not a real feed reading.
            return vec![];
        }
        let staleness = block_ts - updated_at;
        if staleness <= EVMU256::from(STALENESS_THRESHOLD_SECONDS) {
            return vec![];
        }

        self.reported.borrow_mut().insert(target);
        let bug_idx = sub_bug_idx(&target);

        EVMBugResult::new_simple(
            "Price Feed Staleness".to_string(),
            bug_idx,
            format!(
                "{:?} answers latestRoundData() (Chainlink-style) with updatedAt={:?}, which is {:?}s old relative to the current block timestamp {:?} -- more than the {}h conservative threshold. If any consumer of this feed trusts it without its own staleness check, that is a real production risk (the same class of bug behind several real price-oracle-manipulation incidents).\n",
                target, updated_at, staleness, block_ts, STALENESS_THRESHOLD_SECONDS / 3600
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
        )
        .push_to_output();

        vec![bug_idx]
    }
}
