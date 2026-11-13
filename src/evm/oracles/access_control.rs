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
        oracles::ACCESS_CONTROL_BUG_IDX,
        types::{convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_executor::GenericVM,
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const OWNER_SELECTOR: [u8; 4] = [0x8d, 0xa5, 0xcb, 0x5b]; // owner()
const PAUSED_SELECTOR: [u8; 4] = [0x5c, 0x97, 0x5a, 0xbb]; // paused()

// EIP-1967 storage slots come from the crate-canonical, keccak-verified
// constants (`crate::evm::EIP1967_*_SLOT`).

/// Detects unauthorized privilege-escalation paths in a black-box fashion:
/// a caller that isn't the current `owner()`/EIP-1967 admin manages to
/// change the owner, flip `paused()`, or swap a proxy's implementation slot.
///
/// Like the ERC4626 oracle, this needs no ABI/source knowledge: every
/// address ever called becomes a candidate, and on every executed
/// transaction we compare `owner()`/`paused()` (via static calls) and the
/// EIP-1967 implementation/admin storage slots (read directly) before and
/// after. A change made by anyone other than the pre-call owner/admin is
/// flagged.
pub struct AccessControlOracle {
    known_targets: RefCell<HashSet<EVMAddress>>,
}

impl Default for AccessControlOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessControlOracle {
    pub fn new() -> Self {
        Self {
            known_targets: RefCell::new(HashSet::new()),
        }
    }
}

fn sub_bug_idx(target: &EVMAddress, tag: u8) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    tag.hash(&mut hasher);
    (hasher.finish() << 8) + ACCESS_CONTROL_BUG_IDX
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
    > for AccessControlOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        self.known_targets.borrow_mut().insert(ctx.input.get_contract());

        let targets: Vec<EVMAddress> = self.known_targets.borrow().iter().cloned().collect();
        if targets.is_empty() {
            return vec![];
        }

        let probe_calls: Vec<(EVMAddress, Bytes)> = targets
            .iter()
            .flat_map(|t| {
                [
                    (*t, Bytes::from(OWNER_SELECTOR.to_vec())),
                    (*t, Bytes::from(PAUSED_SELECTOR.to_vec())),
                ]
            })
            .collect();

        let pre_results = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_static_call(&probe_calls, ctx.pre_state, ctx.fuzz_state);
        let post_results = ctx.call_post_batch(&probe_calls);

        let caller = ctx.input.get_caller();
        let implementation_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_IMPLEMENTATION_SLOT);
        let admin_slot = EVMU256::from_be_bytes(crate::evm::EIP1967_ADMIN_SLOT);
        let mut violations = vec![];

        for (i, target) in targets.iter().enumerate() {
            let owner_pre_raw = &pre_results[i * 2];
            let paused_pre_raw = &pre_results[i * 2 + 1];
            let owner_post_raw = &post_results[i * 2];
            let paused_post_raw = &post_results[i * 2 + 1];

            let owner_pre = (owner_pre_raw.len() == 32)
                .then(|| EVMU256::try_from_be_slice(owner_pre_raw))
                .flatten()
                .map(convert_u256_to_h160);
            let owner_post = (owner_post_raw.len() == 32)
                .then(|| EVMU256::try_from_be_slice(owner_post_raw))
                .flatten()
                .map(convert_u256_to_h160);

            // Treat an unset (zero) owner as "no access control to violate" --
            // many contracts intentionally allow anyone to claim ownership in
            // that state.
            if let (Some(o_pre), Some(o_post)) = (owner_pre, owner_post) {
                if o_pre != o_post && o_pre != EVMAddress::default() && caller != o_pre {
                    EVMBugResult::new_simple(
                        "Unauthorized Owner Change".to_string(),
                        sub_bug_idx(target, 0),
                        format!(
                            "Contract {:?}'s owner() changed from {:?} to {:?}, but the caller was {:?} (not the previous owner) -- likely a missing or bypassed access-control check.\n",
                            target, o_pre, o_post, caller
                        ),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    )
                    .push_to_output();
                    violations.push(sub_bug_idx(target, 0));
                }
            }

            if paused_pre_raw.len() == 32 && paused_post_raw.len() == 32 {
                let paused_pre = EVMU256::try_from_be_slice(paused_pre_raw).unwrap_or(EVMU256::ZERO);
                let paused_post = EVMU256::try_from_be_slice(paused_post_raw).unwrap_or(EVMU256::ZERO);
                if paused_pre != paused_post {
                    if let Some(o_pre) = owner_pre {
                        if o_pre != EVMAddress::default() && caller != o_pre {
                            EVMBugResult::new_simple(
                                "Unauthorized Pause Toggle".to_string(),
                                sub_bug_idx(target, 1),
                                format!(
                                    "Contract {:?}'s paused() flipped from {:?} to {:?}, but the caller was {:?} (not the owner {:?}) -- likely a missing or bypassed access-control check.\n",
                                    target, paused_pre, paused_post, caller, o_pre
                                ),
                                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                            )
                            .push_to_output();
                            violations.push(sub_bug_idx(target, 1));
                        }
                    }
                }
            }

            // EIP-1967 proxy implementation slot: read directly from storage,
            // no call needed. Only meaningful when an admin slot is actually
            // set (otherwise we have no authority to compare the caller against).
            let get_slot = |state: &EVMState, slot: &EVMU256| state.state.get(target).and_then(|m| m.get(slot).copied());

            let impl_pre = get_slot(ctx.pre_state, &implementation_slot);
            let impl_post = get_slot(&ctx.post_state, &implementation_slot);
            let admin_pre = get_slot(ctx.pre_state, &admin_slot);

            if let (Some(ip), Some(ipo), Some(ad)) = (impl_pre, impl_post, admin_pre) {
                if ip != ipo && ad != EVMU256::ZERO {
                    let admin_addr = convert_u256_to_h160(ad);
                    if caller != admin_addr {
                        EVMBugResult::new_simple(
                            "Unauthorized Proxy Upgrade".to_string(),
                            sub_bug_idx(target, 2),
                            format!(
                                "Proxy {:?}'s EIP-1967 implementation slot changed, but the caller was {:?} (not the admin {:?}) -- likely a missing or bypassed upgrade access-control check.\n",
                                target, caller, admin_addr
                            ),
                            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        )
                        .push_to_output();
                        violations.push(sub_bug_idx(target, 2));
                    }
                }
            }
        }

        violations
    }
}
