use std::{cell::RefCell, collections::HashSet, ops::Deref};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::ERC4626_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_executor::GenericVM,
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

// Well-known ERC4626 selectors (https://eips.ethereum.org/EIPS/eip-4626)
const DEPOSIT_SELECTOR: [u8; 4] = [0x6e, 0x55, 0x3f, 0x65]; // deposit(uint256,address)
const MINT_SELECTOR: [u8; 4] = [0x94, 0xbf, 0x80, 0x4d]; // mint(uint256,address)
const WITHDRAW_SELECTOR: [u8; 4] = [0xb4, 0x60, 0xaf, 0x94]; // withdraw(uint256,address,address)
const REDEEM_SELECTOR: [u8; 4] = [0xba, 0x08, 0x76, 0x52]; // redeem(uint256,address,address)
const TOTAL_ASSETS_SELECTOR: [u8; 4] = [0x01, 0xe1, 0xd1, 0x14]; // totalAssets()
const TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd]; // totalSupply()

/// Price-per-share is scaled by this factor to keep precision in integer math.
const PPS_SCALE: u64 = 1_000_000_000;

/// Detects the classic ERC4626 "donation"/inflation attack: an attacker
/// manipulates a vault's share price by sending it assets through a path
/// other than `deposit`/`mint` (typically a plain ERC20 `transfer` straight
/// to the vault address), which dilutes every subsequent depositor without
/// ever touching the vault's own share-accounting.
///
/// This is detected generically, without any ABI/source knowledge: we track
/// addresses that are called with a `deposit`/`mint`/`withdraw`/`redeem`-
/// shaped selector as vault candidates, then on every subsequent executed
/// transaction (regardless of its target) we read each candidate's
/// `totalAssets()`/`totalSupply()` both before and after via static calls.
/// If total supply didn't change (no shares were minted/burned) but the
/// implied price-per-share jumped sharply, assets entered the vault through
/// a side door -- exactly the setup step of the inflation attack.
pub struct Erc4626ShareInflationOracle {
    known_vaults: RefCell<HashSet<EVMAddress>>,
}

impl Default for Erc4626ShareInflationOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Erc4626ShareInflationOracle {
    pub fn new() -> Self {
        Self {
            known_vaults: RefCell::new(HashSet::new()),
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
    > for Erc4626ShareInflationOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
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
        if vaults.is_empty() {
            return vec![];
        }

        let probe_calls: Vec<(EVMAddress, Bytes)> = vaults
            .iter()
            .flat_map(|v| {
                [
                    (*v, Bytes::from(TOTAL_ASSETS_SELECTOR.to_vec())),
                    (*v, Bytes::from(TOTAL_SUPPLY_SELECTOR.to_vec())),
                ]
            })
            .collect();

        let pre_results = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&probe_calls, ctx.pre_state, ctx.fuzz_state);
        let post_results = ctx.call_post_batch(&probe_calls);

        let mut violations = vec![];

        for (i, vault) in vaults.iter().enumerate() {
            let (ta_pre_raw, ts_pre_raw) = (&pre_results[i * 2], &pre_results[i * 2 + 1]);
            let (ta_post_raw, ts_post_raw) = (&post_results[i * 2], &post_results[i * 2 + 1]);

            if ta_pre_raw.len() != 32 || ts_pre_raw.len() != 32 || ta_post_raw.len() != 32 || ts_post_raw.len() != 32
            {
                // not actually an ERC4626-shaped contract, or the probe reverted
                continue;
            }

            let total_assets_pre = EVMU256::try_from_be_slice(ta_pre_raw).unwrap_or(EVMU256::ZERO);
            let total_supply_pre = EVMU256::try_from_be_slice(ts_pre_raw).unwrap_or(EVMU256::ZERO);
            let total_assets_post = EVMU256::try_from_be_slice(ta_post_raw).unwrap_or(EVMU256::ZERO);
            let total_supply_post = EVMU256::try_from_be_slice(ts_post_raw).unwrap_or(EVMU256::ZERO);

            // Only meaningful if the vault already has depositors to dilute, and
            // no shares were minted/burned this tx (ruling out a legitimate
            // deposit/withdrawal moving the price through the vault's own
            // accounting).
            if total_supply_pre == EVMU256::ZERO || total_supply_pre != total_supply_post {
                continue;
            }
            if total_assets_pre == EVMU256::ZERO {
                continue;
            }

            let pps_pre = match total_assets_pre.checked_mul(EVMU256::from(PPS_SCALE)) {
                Some(v) => v / total_supply_pre,
                None => continue,
            };
            // total_supply_post == total_supply_pre here, so reuse total_supply_pre as the divisor
            let pps_post = match total_assets_post.checked_mul(EVMU256::from(PPS_SCALE)) {
                Some(v) => v / total_supply_pre,
                None => continue,
            };

            if pps_pre == EVMU256::ZERO {
                continue;
            }

            // Flag if price-per-share jumped by more than 50% in a single
            // transaction that never touched the vault's share accounting.
            if pps_post > pps_pre && (pps_post - pps_pre) * EVMU256::from(2u64) > pps_pre {
                let caller = ctx.input.get_caller();
                EVMBugResult::new_simple(
                    "ERC4626 Share Inflation".to_string(),
                    ERC4626_BUG_IDX,
                    format!(
                        "Vault {:?} price-per-share jumped from {:?} to {:?} (x{} scale) in a single tx by {:?} without any deposit/mint/withdraw/redeem call on it -- likely a donation/inflation attack that dilutes future depositors.\n",
                        vault, pps_pre, pps_post, PPS_SCALE, caller
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                )
                .push_to_output();
                violations.push(ERC4626_BUG_IDX);
            }
        }

        violations
    }
}
