use std::{cell::RefCell, collections::HashSet, ops::Deref};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::SIGNATURE_MALLEABILITY_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

// permit(address,address,uint256,uint256,uint8,bytes32,bytes32) -- EIP-2612
const EIP2612_PERMIT_SELECTOR: [u8; 4] = [0xd5, 0x05, 0xac, 0xcf];
// permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32) --
// DAI-style
const DAI_PERMIT_SELECTOR: [u8; 4] = [0x8f, 0xcb, 0xaf, 0x0c];

// secp256k1 curve order n. For any valid ECDSA signature (r, s, v), (r, n -
// s, v') with v flipped between 27/28 is ALSO a valid signature for the
// exact same message and signer -- the well-known malleability property
// plain `ecrecover` does not reject (only a hardened recover like modern
// OpenZeppelin `ECDSA.recover`, which rejects high-s, protects against it).
const SECP256K1_N_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc,
    0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// For every (v, r, s)-encoding `permit()` layout, returns the byte offset
/// of `v`'s 32-byte word and `s`'s 32-byte word, plus the expected total
/// calldata length -- or `None` if the selector isn't one we understand.
fn vs_offsets(selector: [u8; 4]) -> Option<(usize, usize, usize)> {
    match selector {
        EIP2612_PERMIT_SELECTOR => Some((132, 196, 228)), // v, s, total len
        DAI_PERMIT_SELECTOR => Some((164, 228, 260)),
        _ => None,
    }
}

/// Detects signature malleability: given a `permit()` call that just
/// succeeded with signature (v, r, s), computes the mathematically
/// equivalent malleable signature (v', r, n - s) for the exact same
/// message/signer, and actually replays it (a real, non-static call) against
/// the state right after the original call. If that replay ALSO succeeds,
/// the contract's replay protection doesn't actually invalidate the
/// authorization -- it only ever saw one specific (v, r, s) encoding of it,
/// and a second, byte-different-but-cryptographically-equivalent encoding
/// slips through. `SignatureReplayOracle` only catches literally identical
/// calldata reused twice; this catches the case it structurally cannot.
///
/// This is a real, deterministic replay (not a heuristic): if it fires, the
/// malleable signature was *actually accepted* by the real contract logic.
pub struct SignatureMalleabilityOracle {
    probed: RefCell<HashSet<(EVMAddress, Vec<u8>)>>,
}

impl Default for SignatureMalleabilityOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureMalleabilityOracle {
    pub fn new() -> Self {
        Self {
            probed: RefCell::new(HashSet::new()),
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
    > for SignatureMalleabilityOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let calldata = ctx.input.to_bytes();

        // A control-leak (post-execution) state is an INTERMEDIATE state:
        // feedback.rs's OracleFeedback unconditionally discards any oracle()
        // result produced on it, yet the one-shot bookkeeping below would
        // still be committed -- permanently suppressing the real, finished
        // execution that surfaces this finding (the same bug the sibling
        // oracles already guard against). Defer instead.
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }
        if calldata.len() < 4 {
            return vec![];
        }
        let selector: [u8; 4] = calldata[0..4].try_into().unwrap();
        let Some((v_off, s_off, expected_len)) = vs_offsets(selector) else {
            return vec![];
        };
        if calldata.len() != expected_len {
            // Non-standard encoding of the same selector -- don't guess at
            // offsets that might not actually be v/r/s.
            return vec![];
        }

        let target = ctx.input.get_contract();
        let key = (target, calldata.clone());
        if self.probed.borrow().contains(&key) {
            return vec![];
        }
        self.probed.borrow_mut().insert(key);

        let v = calldata[v_off + 31];
        if v != 27 && v != 28 {
            // Unexpected v convention -- don't guess.
            return vec![];
        }
        let v_prime: u8 = if v == 27 { 28 } else { 27 };

        let Some(s) = EVMU256::try_from_be_slice(&calldata[s_off..s_off + 32]) else {
            return vec![];
        };
        let n = EVMU256::from_be_bytes(SECP256K1_N_BYTES);
        if s == EVMU256::ZERO || s >= n {
            // Not a value a real signing process would produce.
            return vec![];
        }
        let s_prime = n - s;

        let mut malleable = calldata.to_vec();
        malleable[v_off + 31] = v_prime;
        let s_prime_bytes: [u8; 32] = s_prime.to_be_bytes();
        malleable[s_off..s_off + 32].copy_from_slice(&s_prime_bytes);

        let caller = ctx.input.get_caller();
        let probe = [(caller, target, Bytes::from(malleable.clone()))];
        let (probe_results, _) = ctx
            .executor
            .deref()
            .borrow_mut()
            .fast_call(&probe, &ctx.post_state, ctx.fuzz_state);
        let (_, replay_succeeded) = &probe_results[0];

        if !*replay_succeeded {
            return vec![];
        }

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&(target, calldata.to_vec()), &mut hasher);
        let bug_idx = (std::hash::Hasher::finish(&hasher) << 8) + SIGNATURE_MALLEABILITY_BUG_IDX;

        EVMBugResult::new_simple(
            "Signature Malleability".to_string(),
            bug_idx,
            format!(
                "permit() on {:?} succeeded with signature (v={}, r, s); replaying the mathematically equivalent malleable signature (v={}, r, n-s) for the SAME message/signer also succeeded -- replay protection doesn't actually invalidate the underlying authorization, only the one specific byte encoding of it.\n",
                target, v, v_prime
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
        )
        .push_to_output();

        vec![bug_idx]
    }
}
