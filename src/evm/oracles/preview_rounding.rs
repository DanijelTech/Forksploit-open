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
        oracles::PREVIEW_ROUNDING_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

// deposit(uint256,address) / mint(uint256,address) /
// withdraw(uint256,address,address) / redeem(uint256,address,address) -- used
// purely to fingerprint "this looks like an ERC4626 vault", same selectors
// Erc4626ShareInflationOracle fingerprints on.
const DEPOSIT_SELECTOR: [u8; 4] = [0x6e, 0x55, 0x3f, 0x65];
const MINT_SELECTOR: [u8; 4] = [0x94, 0xbf, 0x80, 0x4d];
const WITHDRAW_SELECTOR: [u8; 4] = [0xb4, 0x60, 0xaf, 0x94];
const REDEEM_SELECTOR: [u8; 4] = [0xba, 0x08, 0x76, 0x52];

const PREVIEW_DEPOSIT_SELECTOR: [u8; 4] = [0xef, 0x8b, 0x30, 0xf7]; // previewDeposit(uint256)
const PREVIEW_REDEEM_SELECTOR: [u8; 4] = [0x4c, 0xda, 0xd5, 0x06]; // previewRedeem(uint256)

// A handful of magnitudes, covering small/medium/large relative to an
// 18-decimal asset, since a rounding-direction bug can manifest only at
// certain scales (e.g. only when the division remainder is large enough
// to matter, or only at very small amounts where a flat +1/-1 rounding
// choice dominates).
const TEST_AMOUNTS: [u64; 4] = [1, 1_000, 1_000_000, 1_000_000_000_000_000_000];

fn sub_bug_idx(target: &EVMAddress) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    (hasher.finish() << 8) + PREVIEW_ROUNDING_BUG_IDX
}

/// Detects an ERC4626 vault whose rounding direction favors the user
/// instead of the vault: per EIP-4626, `previewDeposit`/`previewRedeem`
/// MUST round in the vault's favor, specifically so that
/// `previewRedeem(previewDeposit(x)) <= x` always holds -- a user must
/// never be able to extract more assets than they put in via a pure
/// round trip. If that inequality is violated, repeating the round trip
/// is a guaranteed, risk-free profit for any caller, draining the vault
/// via a path `Erc4626ShareInflationOracle` doesn't check (that oracle
/// looks for assets entering via a side door, not a bad preview formula).
///
/// Pure view-function probing (previewDeposit/previewRedeem are `view` by
/// spec) against the vault's CURRENT state -- no transaction needed, no
/// side effects, checked opportunistically at several magnitudes as soon
/// as a vault is fingerprinted the same way `Erc4626ShareInflationOracle`
/// does (deposit/mint/withdraw/redeem selector seen).
pub struct PreviewRoundingOracle {
    known_vaults: RefCell<HashSet<EVMAddress>>,
    reported: RefCell<HashSet<EVMAddress>>,
}

impl Default for PreviewRoundingOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl PreviewRoundingOracle {
    pub fn new() -> Self {
        Self {
            known_vaults: RefCell::new(HashSet::new()),
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
    > for PreviewRoundingOracle
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
        let calldata = ctx.input.to_bytes();
        if calldata.len() >= 4 {
            let selector = &calldata[0..4];
            if selector == DEPOSIT_SELECTOR ||
                selector == MINT_SELECTOR ||
                selector == WITHDRAW_SELECTOR ||
                selector == REDEEM_SELECTOR
            {
                self.known_vaults.borrow_mut().insert(ctx.input.get_contract());
            }
        }

        let vaults: Vec<EVMAddress> = self.known_vaults.borrow().iter().cloned().collect();
        for vault in vaults {
            if self.reported.borrow().contains(&vault) {
                continue;
            }

            for amount in TEST_AMOUNTS {
                let mut deposit_call = PREVIEW_DEPOSIT_SELECTOR.to_vec();
                deposit_call.extend_from_slice(&EVMU256::from(amount).to_be_bytes::<32>());

                let probe = [(vault, Bytes::from(deposit_call))];
                let shares_raw =
                    ctx.executor
                        .deref()
                        .borrow_mut()
                        .fast_static_call(&probe, &ctx.post_state, ctx.fuzz_state);
                if shares_raw[0].len() != 32 {
                    continue;
                }
                let Some(shares) = EVMU256::try_from_be_slice(&shares_raw[0]) else {
                    continue;
                };
                if shares == EVMU256::ZERO {
                    continue;
                }

                let mut redeem_call = PREVIEW_REDEEM_SELECTOR.to_vec();
                redeem_call.extend_from_slice(&shares.to_be_bytes::<32>());
                let probe = [(vault, Bytes::from(redeem_call))];
                let assets_back_raw =
                    ctx.executor
                        .deref()
                        .borrow_mut()
                        .fast_static_call(&probe, &ctx.post_state, ctx.fuzz_state);
                if assets_back_raw[0].len() != 32 {
                    continue;
                }
                let Some(assets_back) = EVMU256::try_from_be_slice(&assets_back_raw[0]) else {
                    continue;
                };

                if assets_back <= EVMU256::from(amount) {
                    continue;
                }

                self.reported.borrow_mut().insert(vault);
                let bug_idx = sub_bug_idx(&vault);

                EVMBugResult::new_simple(
                    "ERC4626 Rounding Favors User".to_string(),
                    bug_idx,
                    format!(
                        "Vault {:?}: previewRedeem(previewDeposit({})) = {:?}, MORE than the {} deposited -- rounding favors the depositor instead of the vault (violates EIP-4626's requirement). Any caller can repeat this round trip for guaranteed, risk-free profit, draining the vault one round trip at a time.\n",
                        vault, amount, assets_back, amount
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                )
                .push_to_output();

                return vec![bug_idx];
            }
        }

        vec![]
    }
}
