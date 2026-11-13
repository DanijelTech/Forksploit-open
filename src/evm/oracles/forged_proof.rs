use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashSet},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::FORGED_PROOF_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    oracle::Oracle,
    state::HasExecutionResult,
};

fn sub_bug_idx(target: &EVMAddress) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    (hasher.finish() << 8) + FORGED_PROOF_BUG_IDX
}

/// Detects a FORGED cross-chain / Merkle PROOF: the transaction computed a
/// hash itself (SHA3) and compared it for equality against a
/// caller-supplied calldata word, ACCEPTED that comparison (the JUMPI
/// jumped), and never compared that same calldata word against the
/// contract's own authoritative storage value -- i.e. `require(keccak(...)
/// == root)` where `root` is the attacker's, instead of `root ==
/// trustedRoot` (the Nomad "trusted root = 0x0" / KelpDAO-LayerZero forged
/// message shape, ~$308M + ~$44M, and BNB Bridge).
///
/// This is a real dataflow signal, not a proximity guess:
/// * `host.rs` 0x20 (SHA3) computes the exact hash revm is about to and
///   latches it (`current_last_sha3`).
/// * 0x14 (EQ) checks whether one operand is that just-computed hash and
///   the other is a raw calldata word (a caller-supplied root), latching
///   the pair; it separately records any calldata word ever compared
///   against an SLOAD'd value (`current_calldata_sload_compared`) -- the
///   SAFE `root == trustedRoot` form.
/// * 0x57 (JUMPI) records the pair only if the branch was ACCEPTED
///   (`current_proof_accepted`), and the oracle suppresses any pair whose
///   root word was also SLOAD-compared (the contract did tie it to state).
///
/// Review-tier: not every `keccak(...) == calldata` is a bug (a proof
/// verifier that legitimately takes the root as a parameter, e.g. a
/// stateless verifier called only by an already-trusted relay, is
/// well-formed), so this points a human at exactly the right call, without
/// claiming certainty. It sits between two existing oracles without
/// overlapping either: `signature_replay.rs` covers REPLAY of a
/// previously-seen calldata (same bytes twice), and `unchecked_call.rs`
/// covers a failed sub-call whose result was ignored -- neither sees a
/// proof verified against an attacker-chosen root.
pub struct ForgedProofOracle {
    reported: RefCell<HashSet<(EVMAddress, usize)>>,
}

impl Default for ForgedProofOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ForgedProofOracle {
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
    > for ForgedProofOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        if ctx.post_state.proof_accepted.is_empty() {
            return vec![];
        }

        // A call that leaked control is not a finished execution; the
        // feedback layer discards its oracle() output, so committing
        // "already reported" here would silently swallow the finding (see
        // oracles/self_referral.rs's identical guard).
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }

        let safe = ctx.post_state.calldata_sload_compared.clone();
        let hits: Vec<(EVMAddress, usize, EVMU256)> = ctx
            .post_state
            .proof_accepted
            .iter()
            .filter(|(_, _, root)| !safe.contains(root))
            .cloned()
            .collect();
        if hits.is_empty() {
            return vec![];
        }

        let mut res = vec![];
        for (addr, eq_pc, root) in hits {
            if !self.reported.borrow_mut().insert((addr, eq_pc)) {
                continue;
            }
            let bug_idx = sub_bug_idx(&addr);
            EVMBugResult::new_simple(
                "Forged Proof (Caller-Supplied Root Accepted)".to_string(),
                bug_idx,
                format!(
                    "{addr:?} at pc {eq_pc} accepted a proof comparison between a hash it computed itself and the caller-supplied word 0x{root:064x}, without that word ever being checked against the contract's own stored root -- a forged (root, proof) pair is accepted, the Nomad/KelpDAO cross-chain message-spoofing shape.\n"
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}
