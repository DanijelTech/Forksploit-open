use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    ops::Deref,
};

use bytes::Bytes;
use revm_primitives::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        oracle::EVMBugResult,
        oracles::ARB_TRANSFER_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_executor::GenericVM,
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

const TRANSFER_FROM_SELECTOR: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom(address,address,uint256)
const ALLOWANCE_SELECTOR: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e]; // allowance(address,address)
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)

fn sub_bug_idx(target: &EVMAddress, from: &EVMAddress) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    from.hash(&mut hasher);
    (hasher.finish() << 8) + ARB_TRANSFER_BUG_IDX
}

/// Detects an ERC20 `transferFrom(from, to, amount)` call that succeeded
/// despite the caller being neither `from` nor holding sufficient allowance
/// from `from` -- i.e. the token's own allowance check is missing or
/// bypassed, letting anyone drain anyone else's approved balance.
///
/// `transferFrom(address,address,uint256)` has the identical selector as
/// ERC721's, so this only fires once the target also answers
/// `allowance(from, caller)` with a valid 32-byte result -- that's what
/// disambiguates an ERC20 token from an NFT contract (see
/// `nft_transfer.rs`, which instead probes `ownerOf`).
///
/// This only catches a broken allowance check on the token itself. It does
/// NOT catch the "router already holds broad approval and forwards an
/// attacker-supplied `from` without checking msg.sender == from" bug class,
/// since that needs tracking the *immediate* caller of a nested
/// `transferFrom` (whichever contract issued the CALL opcode), not the
/// top-level transaction sender -- that would require host-level
/// instrumentation similar to the existing `current_arbitrary_calls`
/// unbounded-target tracking in `host.rs`, which is a separate, larger
/// piece of work.
pub struct ArbitraryERC20TransferOracle {}

impl Default for ArbitraryERC20TransferOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ArbitraryERC20TransferOracle {
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
    > for ArbitraryERC20TransferOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let calldata = ctx.input.to_bytes();
        if calldata.len() < 100 {
            return vec![];
        }
        if &calldata[0..4] != TRANSFER_FROM_SELECTOR {
            return vec![];
        }

        let target = ctx.input.get_contract();
        let caller = ctx.input.get_caller();

        let from = match EVMU256::try_from_be_slice(&calldata[4..36]) {
            Some(v) => crate::evm::types::convert_u256_to_h160(v),
            None => return vec![],
        };
        let amount = match EVMU256::try_from_be_slice(&calldata[68..100]) {
            Some(v) => v,
            None => return vec![],
        };

        if caller == from {
            // moving your own tokens is never "arbitrary"
            return vec![];
        }
        if from == EVMAddress::default() || amount == EVMU256::ZERO {
            // nothing real to steal from the zero address / a no-op transfer
            return vec![];
        }

        let allowance_calldata: Bytes = [&ALLOWANCE_SELECTOR[..], &[0u8; 12][..], from.as_slice(), &[0u8; 12][..], caller.as_slice()]
            .concat()
            .into();
        let balance_calldata: Bytes = [&BALANCE_OF_SELECTOR[..], &[0u8; 12][..], from.as_slice()].concat().into();

        let results = ctx.executor.deref().borrow_mut().fast_static_call(
            &[(target, allowance_calldata), (target, balance_calldata)],
            ctx.pre_state,
            ctx.fuzz_state,
        );

        let allowance_raw = &results[0];
        let balance_raw = &results[1];
        if allowance_raw.len() != 32 || balance_raw.len() != 32 {
            // doesn't answer allowance/balanceOf -- not ERC20-shaped (most
            // likely the ERC721 transferFrom case, see nft_transfer.rs)
            return vec![];
        }
        let allowance_pre = EVMU256::try_from_be_slice(allowance_raw).unwrap_or(EVMU256::ZERO);
        let balance_pre = EVMU256::try_from_be_slice(balance_raw).unwrap_or(EVMU256::ZERO);

        if balance_pre == EVMU256::ZERO {
            // `from` never held any real balance -- nothing meaningful to steal
            return vec![];
        }
        if allowance_pre >= amount {
            // the token's own allowance accounting covers this transfer
            return vec![];
        }

        let bug_idx = sub_bug_idx(&target, &from);
        EVMBugResult::new_simple(
            "Unauthorized ERC20 Transfer".to_string(),
            bug_idx,
            format!(
                "transferFrom({:?}, ..., {:?}) on {:?} succeeded despite {:?} only having an allowance of {:?} from {:?} -- the token's allowance check is missing or bypassed.\n",
                from, amount, target, caller, allowance_pre, from
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
        )
        .push_to_output();
        vec![bug_idx]
    }
}
