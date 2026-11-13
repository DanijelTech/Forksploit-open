use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashSet},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::SIGNATURE_REPLAY_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

// permit(address,address,uint256,uint256,uint8,bytes32,bytes32) -- EIP-2612
const EIP2612_PERMIT_SELECTOR: [u8; 4] = [0xd5, 0x05, 0xac, 0xcf];
// permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32) -- DAI-style
const DAI_PERMIT_SELECTOR: [u8; 4] = [0x8f, 0xcb, 0xaf, 0x0c];
// relayMessage(uint256,address,address,uint256,uint256,bytes) -- OP-stack's
// CrossDomainMessenger (shared by every OP-stack chain: Optimism, Base,
// Blast, ...). Verified live, not guessed: calling this exact selector
// against the real L1CrossDomainMessengerProxy
// (0x25ace71c97B33Cc4729CF772ae268934F7ab5fA1 on ETH mainnet) reverts
// with "CrossDomainMessenger: message cannot be replayed" -- its own
// source literally names this the replay guard this oracle is checking
// for a bypass of.
const OP_STACK_RELAY_MESSAGE_SELECTOR: [u8; 4] = [0xd7, 0x64, 0xad, 0x0b];
// executeTransaction(bytes32[],uint256,address,address,uint256,uint256,uint256,uint256,bytes)
// -- Arbitrum Nitro's Outbox, which finalizes an L2->L1 message. Verified
// live: calling this selector against the real Arbitrum One Outbox
// (0x0B9857ae2D4A3DBe74ffE1d7DF045bb7F96E4840 on ETH mainnet) reaches
// real replay-guard logic (a custom-error revert carrying structured
// data, not a generic "unknown selector" fallback revert) -- its own
// source tracks spent/replayed messages in a `spent` bitmap specifically
// to reject exactly this call being repeated.
const ARBITRUM_EXECUTE_TRANSACTION_SELECTOR: [u8; 4] = [0x08, 0x63, 0x5a, 0x95];

/// Detects replay-protection bypasses: a call to one of a small set of
/// known "this should only ever succeed once" functions -- EIP-2612/DAI-
/// style `permit()` (owner, spender, value, deadline, v, r, s -- i.e. the
/// signature itself, meant to be invalidated via a nonce after first use),
/// or a cross-domain bridge message finalizer (OP-stack's
/// `relayMessage()`, Arbitrum's `executeTransaction()`, both of which
/// track which messages were already relayed specifically to reject this)
/// -- whose calldata is byte-for-byte identical to a previous *successful*
/// call of the same function on the same contract. A correct
/// implementation must reject the second call outright, so succeeding
/// twice with identical calldata means replay protection is missing or
/// broken -- the same underlying bug shape whether it's a signature nonce
/// or a bridge message-relayed marker that failed to stick.
///
/// This needs no cryptography or ABI knowledge beyond the selector check
/// below: `oracle()` only runs after non-reverted execution, so simply
/// seeing the exact same calldata accepted twice is itself the bug
/// signal. The two bridge selectors are chain-agnostic bytecode matches
/// (no hardcoded address table, unlike aave_transformer.rs/
/// balancer_transformer.rs) -- they fire against whatever contract is
/// being fuzzed, on any chain, including a non-OP-stack/non-Arbitrum
/// contract that happens to implement the identical standard interface.
pub struct SignatureReplayOracle {
    seen_successful: RefCell<HashSet<(EVMAddress, Vec<u8>)>>,
}

impl Default for SignatureReplayOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureReplayOracle {
    pub fn new() -> Self {
        Self {
            seen_successful: RefCell::new(HashSet::new()),
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
    > for SignatureReplayOracle
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
        let selector = &calldata[0..4];
        let matched_fn = if selector == EIP2612_PERMIT_SELECTOR || selector == DAI_PERMIT_SELECTOR {
            "permit()"
        } else if selector == OP_STACK_RELAY_MESSAGE_SELECTOR {
            "relayMessage()"
        } else if selector == ARBITRUM_EXECUTE_TRANSACTION_SELECTOR {
            "executeTransaction()"
        } else {
            return vec![];
        };

        let target = ctx.input.get_contract();
        let key = (target, calldata.clone());

        if self.seen_successful.borrow().contains(&key) {
            let caller = ctx.input.get_caller();

            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + SIGNATURE_REPLAY_BUG_IDX;

            EVMBugResult::new_simple(
                "Signature Replay".to_string(),
                bug_idx,
                format!(
                    "{matched_fn} on {:?} succeeded again with byte-for-byte identical calldata (caller {:?}) -- the signature/nonce/relayed-message marker was not invalidated after first use, allowing replay.\n",
                    target, caller
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            return vec![bug_idx];
        }

        self.seen_successful.borrow_mut().insert(key);
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards every selector constant above against a single wrong byte
    /// silently making that function's replay check never fire -- each
    /// is recomputed here from the real function signature rather than
    /// trusted as a literal.
    #[test]
    fn test_selectors_match_real_function_signatures() {
        let cases: [(&str, [u8; 4]); 4] = [
            (
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                EIP2612_PERMIT_SELECTOR,
            ),
            (
                "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
                DAI_PERMIT_SELECTOR,
            ),
            (
                "relayMessage(uint256,address,address,uint256,uint256,bytes)",
                OP_STACK_RELAY_MESSAGE_SELECTOR,
            ),
            (
                "executeTransaction(bytes32[],uint256,address,address,uint256,uint256,uint256,uint256,bytes)",
                ARBITRUM_EXECUTE_TRANSACTION_SELECTOR,
            ),
        ];
        for (sig, expected) in cases {
            let hash = alloy_primitives::keccak256(sig.as_bytes());
            assert_eq!(&hash[0..4], &expected, "selector mismatch for {sig}");
        }
    }
}
