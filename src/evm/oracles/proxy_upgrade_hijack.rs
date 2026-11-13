use std::{
    cell::RefCell,
    collections::{HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    ops::Deref,
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::PROXY_UPGRADE_HIJACK_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256, convert_u256_to_h160},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const OWNER_SELECTOR: [u8; 4] = [0x8d, 0xa5, 0xcb, 0x5b]; // owner()
const UPGRADE_TO_SELECTOR: [u8; 4] = [0x36, 0x59, 0xcf, 0xe6]; // upgradeTo(address)
const UPGRADE_TO_AND_CALL_SELECTOR: [u8; 4] = [0x4f, 0x1e, 0xf2, 0x86]; // upgradeToAndCall(address,bytes)
const CHANGE_ADMIN_SELECTOR: [u8; 4] = [0x8f, 0x28, 0x39, 0x70]; // changeAdmin(address)
const DIAMOND_CUT_SELECTOR: [u8; 4] = [0x1f, 0x93, 0x1c, 0x1c]; // diamondCut(FacetCut[],address,bytes)

// EIP-1967 slots come from the crate-canonical, keccak-verified constants
// (`crate::evm::EIP1967_*_SLOT`).

fn sub_bug_idx(target: &EVMAddress, tag: u8) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    tag.hash(&mut hasher);
    (hasher.finish() << 8) + PROXY_UPGRADE_HIJACK_BUG_IDX
}

/// Detects an UNPROTECTED proxy upgrade -- the class that made up the single
/// largest code-level loss bucket of 2025-2026 (proxy upgrade hijack, ~$366M):
/// USPD, Rari Capital Fuse, UPCX, Muref, and the Parity-family uninitialized
/// proxies all reduce to the same primitive, "an upgrade entry point was
/// reachable by a caller who held no authority over it".
///
/// This is the deliberate complement of the two existing proxy oracles:
///
/// * `access_control.rs` already flags "Unauthorized Proxy Upgrade", but ONLY
///   when the EIP-1967 **admin slot is non-zero** -- it needs that admin
///   address to compare the caller against. A UUPS proxy never sets the admin
///   slot at all (its authority is `onlyOwner` on the implementation), so the
///   entire UUPS family is invisible to it.
/// * `proxy_integrity.rs` deliberately SKIPS the upgrade selectors when looking
///   for storage collisions (`is_expected_slot_writer`), precisely so it
///   doesn't misreport an intentional upgrade as a layout bug.
///
/// Between the two, an unprotected `upgradeTo` on an admin-slot-less proxy
/// falls through both -- confirmed live 2026-11-05 on
/// `tests/evm/proxy_upgrade_hijack/`: the existing binary found only a
/// coincidental `Zero Address Setter` (because the fuzzer happened to call
/// `upgradeTo(address(0))`) and never the actual missing access control, so a
/// realistic malicious (non-zero) implementation address produced NO finding
/// and `confirmed_exploitable: false`.
///
/// Detection is deterministic and black-box: on a call whose selector is one
/// of the recognized upgrade entry points, the EIP-1967 implementation (or
/// admin) slot actually changed, the admin slot is zero/unset (the UUPS case,
/// which is exactly the part the other oracle can't reach), and a readable
/// `owner()` exists whose value differs from the caller. A non-zero owner
/// that did not make the call is proof the upgrade was not authorized by the
/// owner -- the same authority signal `access_control.rs` already treats as
/// Confirmed-tier for owner changes, applied here to the upgrade path.
pub struct ProxyUpgradeHijackOracle {
    reported: RefCell<HashSet<(EVMAddress, EVMAddress)>>,
}

impl Default for ProxyUpgradeHijackOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyUpgradeHijackOracle {
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
    > for ProxyUpgradeHijackOracle
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
        if calldata.len() < 4 {
            return vec![];
        }
        let selector: [u8; 4] = calldata[0..4].try_into().unwrap();
        let is_upgrade_selector = matches!(
            selector,
            UPGRADE_TO_SELECTOR | UPGRADE_TO_AND_CALL_SELECTOR | CHANGE_ADMIN_SELECTOR | DIAMOND_CUT_SELECTOR
        );
        if !is_upgrade_selector {
            return vec![];
        }

        let target = ctx.input.get_contract();
        let implementation_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_IMPLEMENTATION_SLOT);
        let admin_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_ADMIN_SLOT);

        let get_slot = |state: &EVMState, slot: &EVMU256| {
            state
                .state
                .get(&target)
                .and_then(|m| m.get(slot).copied())
                .unwrap_or(EVMU256::ZERO)
        };

        // Did an upgrade actually take effect in this transaction?
        let impl_changed =
            get_slot(ctx.pre_state, &implementation_slot) != get_slot(&ctx.post_state, &implementation_slot);
        let admin_changed = get_slot(ctx.pre_state, &admin_slot) != get_slot(&ctx.post_state, &admin_slot);
        if !impl_changed && !admin_changed {
            return vec![];
        }

        // Only the admin-slot-less (UUPS/beacon-style) case is ours. When the
        // admin slot IS set, `access_control.rs` owns this finding -- emitting
        // here too would just double-report the same bug under two names.
        let admin_pre = get_slot(ctx.pre_state, &admin_slot);
        if admin_pre != EVMU256::ZERO {
            return vec![];
        }

        // Authority source for the admin-less case: the owner() the
        // implementation exposes through the proxy. Read it from the
        // pre-state so we compare against the authority that held *before*
        // this call, not one the call itself may have rewritten.
        let caller = ctx.input.get_caller();
        if caller == EVMAddress::default() {
            return vec![];
        }
        let owner_raw = ctx.executor.deref().borrow_mut().fast_static_call(
            &[(target, Bytes::from(OWNER_SELECTOR.to_vec()))],
            ctx.pre_state,
            ctx.fuzz_state,
        );
        let owner = owner_raw
            .first()
            .filter(|r| r.len() == 32)
            .and_then(|r| EVMU256::try_from_be_slice(r))
            .map(convert_u256_to_h160);

        // No readable authority at all: cannot prove this upgrade was
        // unauthorized (a role-based `hasRole` guard would look identical from
        // the outside), so stay silent rather than guess. The oracle's whole
        // value is the deterministic owner-mismatch case below.
        let Some(owner) = owner else {
            return vec![];
        };
        if owner == EVMAddress::default() || caller == owner {
            return vec![];
        }

        let mut reported = self.reported.borrow_mut();
        if !reported.insert((target, caller)) {
            return vec![];
        }
        drop(reported);

        let selector_hex = hex::encode(selector);
        let which = if impl_changed { "implementation" } else { "admin" };
        let bug_idx = sub_bug_idx(&target, if impl_changed { 0 } else { 1 });
        EVMBugResult::new_simple(
            "Unprotected Proxy Upgrade (UUPS)".to_string(),
            bug_idx,
            format!(
                "{target:?}'s EIP-1967 {which} slot changed via upgrade selector 0x{selector_hex}, but the caller was {caller:?} (not owner() == {owner:?}) and no EIP-1967 admin slot is set. An admin-slot-less (UUPS-style) proxy whose upgrade entry point is reachable by a non-owner can be pointed at an attacker-controlled implementation, taking over every function the proxy delegates -- the primitive behind the 2025-2026 proxy-upgrade-hijack losses (USPD, Rari Fuse, UPCX). The upgrade function is missing its `onlyOwner`/`_authorizeUpgrade` guard.\n"
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
        )
        .push_to_output();
        vec![bug_idx]
    }
}
