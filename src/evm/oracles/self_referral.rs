use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use libafl_bolts::impl_serdeany;
use revm_primitives::Bytecode;
use serde::{Deserialize, Serialize};

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::SELF_REFERRAL_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    oracle::Oracle,
    state::HasExecutionResult,
};

/// Confirmed live this session on a real deployed ETC contract:
/// `mint(to, referral)` paid a 10% fee to `referral` regardless of
/// whether `referral` passed the contract's own "is this a valid
/// referral" check -- that check only gated a separate counter, never
/// the payment itself. Net effect: anyone can pass their OWN address as
/// `referral` and collect the fee, whether or not they're a real
/// referrer. No existing oracle targets this shape (it isn't access
/// control, reentrancy, or arithmetic -- it's a validation check that
/// looks like it should gate a payment but structurally doesn't).
///
/// Generalized, bytecode-only signal, with NO assumption about which
/// JUMPI branch means "valid" vs "invalid" (that's solc-codegen-specific
/// and not reliably inferable from opcodes alone): `host.rs`'s 0x35/0x57
/// instrumentation records, for a JUMPI fed by an address-type calldata
/// argument, which branch was taken (`current_arg_guard_reads`), and
/// separately whether that SAME argument value received an outgoing
/// value-carrying CALL this call (`current_paid_calldata_addresses`).
/// Across MULTIPLE independently-fuzzed calls that naturally explore
/// BOTH branches of the same guard (different argument values landing on
/// each side -- exactly what a fuzzer does without being told to), if a
/// payment-to-that-argument is observed on BOTH the "jump" and the
/// "fall-through" outcome, the check demonstrably does NOT determine
/// whether the payment happens -- the validation and the payout are
/// independent, whatever the check's intent. This needs no semantic
/// understanding of the branch, just confirming empirically that both
/// outcomes still pay out.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct SelfReferralMetadata {
    /// (address, jumpi pc) -> (payment observed when branch jumped,
    /// payment observed when branch fell through, already reported).
    pub seen: HashMap<(EVMAddress, usize), (bool, bool, bool)>,
}

impl_serdeany!(SelfReferralMetadata);

pub struct SelfReferralOracle {}

impl Default for SelfReferralOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfReferralOracle {
    pub fn new() -> Self {
        Self {}
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
    > for SelfReferralOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        if ctx.post_state.arg_guard_reads.is_empty() || ctx.post_state.paid_calldata_addresses.is_empty() {
            return vec![];
        }

        // A call that leaked control (e.g. the payment CALL above landed on
        // an address the fuzzer still wants to explore reentrancy through)
        // is NOT yet a finished execution -- feedback.rs's OracleFeedback
        // unconditionally discards every oracle() result from such a call
        // (see its own `has_post_exec` check), so bookkeeping below MUST
        // NOT treat this as a real observation: doing so would let a
        // discarded call permanently flip `entry.2` (already-reported)
        // without the finding ever actually being reported, silently
        // blocking this guard forever. Defer to the eventual finished call
        // instead.
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }

        if !ctx.fuzz_state.has_metadata::<SelfReferralMetadata>() {
            ctx.fuzz_state.metadata_map_mut().insert(SelfReferralMetadata::default());
        }

        let paid = ctx.post_state.paid_calldata_addresses.clone();
        let observed: Vec<(EVMAddress, usize, EVMAddress, bool)> =
            ctx.post_state.arg_guard_reads.iter().cloned().collect();

        let mut violations = vec![];
        for (addr, jumpi_pc, arg_addr, jumped) in observed {
            if !paid.contains(&arg_addr) {
                continue;
            }

            let metadata = ctx.fuzz_state.metadata_map_mut().get_mut::<SelfReferralMetadata>().unwrap();
            let entry = metadata.seen.entry((addr, jumpi_pc)).or_insert((false, false, false));
            if jumped {
                entry.0 = true;
            } else {
                entry.1 = true;
            }
            if !(entry.0 && entry.1) || entry.2 {
                continue;
            }
            entry.2 = true;

            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            jumpi_pc.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + SELF_REFERRAL_BUG_IDX;

            EVMBugResult::new_simple(
                "Validation-Independent Payment".to_string(),
                bug_idx,
                format!(
                    "{addr:?}'s check at pc {jumpi_pc} tests an address-type argument, which ALSO received a \
                     value-carrying CALL in the same transaction -- and this was observed on BOTH outcomes of \
                     the check (jumped and fell through) across separately fuzzed calls. The check does not \
                     actually gate the payment: whatever this argument is supposed to validate (e.g. \"is this a \
                     real referral/beneficiary\"), the payout to it happens either way. Confirmed in a real \
                     deployed contract this session: a referral fee paid to the `referral` argument regardless \
                     of whether it passed the contract's own referral-validity check -- anyone can pass their \
                     own address and collect the fee.\n"
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            violations.push(bug_idx);
        }
        violations
    }
}
