use super::types::EVMU512;

pub mod access_control;
pub mod arb_call;
pub mod arbitrary_storage_write;
pub mod arb_transfer;
pub mod assert_violation;
pub mod centralization_risk;
pub mod curve_virtual_price;
pub mod delegatecall;
pub mod delegatecall_target;
pub mod ecrecover;
pub mod eth_backing;
pub mod erc20;
pub mod erc4626;
pub mod forced_eth_accounting;
pub mod gas_stipend;
pub mod initializer_front_run;
pub mod invariant;
pub mod nft_transfer;
pub mod overflow;
pub mod precision_loss;
pub mod preview_rounding;
pub mod price_feed_staleness;
pub mod proxy_integrity;
pub mod unbacked_mint;
pub mod forged_proof;
pub mod transient_guard;
pub mod proxy_upgrade_hijack;
pub mod readonly_reentrancy;
pub mod reentrancy;
pub mod revert_in_loop;
pub mod self_referral;
pub mod selfdestruct;
pub mod stale_guard;
pub mod signature_malleability;
pub mod signature_replay;
pub mod state_comp;
pub mod storage_collision;
pub mod token_accounting_mismatch;
pub mod twap_manipulation;
pub mod typed_bug;
pub mod tx_origin;
pub mod unbounded_loop;
pub mod unchecked_call;
pub mod uninitialized_memory;
pub mod v2_pair;
pub mod weak_randomness;
pub mod zero_address_setter;

pub static ERC20_BUG_IDX: u64 = 0;
pub static V2_PAIR_BUG_IDX: u64 = 2;
pub static TYPED_BUG_BUG_IDX: u64 = 4;
pub static SELFDESTRUCT_BUG_IDX: u64 = 5;
pub static STATE_COMP_BUG_IDX: u64 = 7;
pub static ARB_CALL_BUG_IDX: u64 = 8;
pub static REENTRANCY_BUG_IDX: u64 = 9;
pub static INTEGER_OVERFLOW_BUG_IDX: u64 = 11;
pub static ERC4626_BUG_IDX: u64 = 12;
pub static ACCESS_CONTROL_BUG_IDX: u64 = 13;
pub static SIGNATURE_REPLAY_BUG_IDX: u64 = 14;
pub static NFT_TRANSFER_BUG_IDX: u64 = 15;
pub static PROXY_INTEGRITY_BUG_IDX: u64 = 16;
pub static ARB_TRANSFER_BUG_IDX: u64 = 17;
pub static DELEGATECALL_INJECTION_BUG_IDX: u64 = 18;
pub static ECRECOVER_ZERO_BUG_IDX: u64 = 19;
pub static STORAGE_COLLISION_BUG_IDX: u64 = 20;
pub static DELEGATECALL_TARGET_BUG_IDX: u64 = 21;
pub static UNINITIALIZED_MEMORY_BUG_IDX: u64 = 22;
pub static UNCHECKED_CALL_BUG_IDX: u64 = 23;
pub static TX_ORIGIN_BUG_IDX: u64 = 24;
pub static INITIALIZER_FRONT_RUN_BUG_IDX: u64 = 25;
pub static CENTRALIZATION_RISK_BUG_IDX: u64 = 26;
pub static SIGNATURE_MALLEABILITY_BUG_IDX: u64 = 27;
pub static CURVE_VIRTUAL_PRICE_BUG_IDX: u64 = 28;
pub static PRICE_FEED_STALENESS_BUG_IDX: u64 = 29;
pub static TWAP_MANIPULATION_BUG_IDX: u64 = 30;
pub static PREVIEW_ROUNDING_BUG_IDX: u64 = 31;
pub static ETH_BACKING_BUG_IDX: u64 = 32;
pub static UNBOUNDED_LOOP_BUG_IDX: u64 = 33;
pub static STALE_GUARD_BUG_IDX: u64 = 34;
pub static SELF_REFERRAL_BUG_IDX: u64 = 35;
pub static ARBITRARY_STORAGE_WRITE_BUG_IDX: u64 = 36;
pub static TOKEN_ACCOUNTING_MISMATCH_BUG_IDX: u64 = 37;
pub static FORCED_ETH_ACCOUNTING_BUG_IDX: u64 = 38;
pub static READONLY_REENTRANCY_BUG_IDX: u64 = 39;
pub static ZERO_ADDRESS_SETTER_BUG_IDX: u64 = 40;
pub static GAS_STIPEND_BUG_IDX: u64 = 41;
pub static WEAK_RANDOMNESS_BUG_IDX: u64 = 42;
pub static PRECISION_LOSS_BUG_IDX: u64 = 43;
pub static REVERT_IN_LOOP_BUG_IDX: u64 = 44;
pub static ASSERT_VIOLATION_BUG_IDX: u64 = 45;
pub static PROXY_UPGRADE_HIJACK_BUG_IDX: u64 = 46;
pub static UNBACKED_MINT_BUG_IDX: u64 = 47;
pub static FORGED_PROOF_BUG_IDX: u64 = 48;
pub static TRANSIENT_GUARD_BUG_IDX: u64 = 49;
pub static INVARIANT_BUG_IDX: u64 = 50;

/// Divide a U512 by another U512 and return a string with the decimal point at
/// the correct position For example, 1000 / 3 = 333.333, then a = 1000e6, b =
/// 3, fp = 6
pub fn u512_div_float(a: EVMU512, b: EVMU512, fp: usize) -> String {
    let mut res = format!("{}", a / b);
    if res.len() <= fp {
        res.insert_str(0, &"0".repeat(fp - res.len() + 1));
    }
    res.insert(res.len() - fp, '.');
    res
}

#[macro_export]
macro_rules! oracle_should_skip {
    ($ctx: expr, $key: expr) => {{
        let mut res = false;
        if let Some(meta) = $ctx.fuzz_state.metadata_map().get::<BugMetadata>() {
            res = meta.known_bugs.contains(&$key);
        }
        res
    }};
}
