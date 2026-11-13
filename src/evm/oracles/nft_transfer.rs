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
        oracles::NFT_TRANSFER_BUG_IDX,
        types::{convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_executor::GenericVM,
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

// ERC721
const OWNER_OF_SELECTOR: [u8; 4] = [0x63, 0x52, 0x21, 0x1e]; // ownerOf(uint256)
const GET_APPROVED_SELECTOR: [u8; 4] = [0x08, 0x18, 0x12, 0xfc]; // getApproved(uint256)
const IS_APPROVED_FOR_ALL_SELECTOR: [u8; 4] = [0xe9, 0x85, 0xe9, 0xc5]; // isApprovedForAll(address,address)
const TRANSFER_FROM_SELECTOR: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom(address,address,uint256) -- shared w/ ERC20
const SAFE_TRANSFER_FROM_3_SELECTOR: [u8; 4] = [0x42, 0x84, 0x2e, 0x0e]; // safeTransferFrom(address,address,uint256)
const SAFE_TRANSFER_FROM_4_SELECTOR: [u8; 4] = [0xb8, 0x8d, 0x4f, 0xde]; // safeTransferFrom(address,address,uint256,bytes)

// ERC1155
const BALANCE_OF_1155_SELECTOR: [u8; 4] = [0x00, 0xfd, 0xd5, 0x8e]; // balanceOf(address,uint256)
const SAFE_TRANSFER_FROM_1155_SELECTOR: [u8; 4] = [0xf2, 0x42, 0x43, 0x2a]; // safeTransferFrom(address,address,uint256,uint256,bytes)
const SAFE_BATCH_TRANSFER_FROM_1155_SELECTOR: [u8; 4] = [0x2e, 0xb2, 0xc2, 0xd6]; // safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)

/// Decodes the first element of the dynamic `uint256[] ids` array from a
/// `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)` call,
/// given the standard ABI dynamic-array encoding (an offset at calldata[68..100],
/// relative to the start of the parameter block at byte 4, pointing at a
/// 32-byte length word followed by that many 32-byte elements).
fn decode_first_batch_id(calldata: &[u8]) -> Option<EVMU256> {
    let ids_offset = EVMU256::try_from_be_slice(&calldata[68..100])?;
    let ids_offset: usize = ids_offset.try_into().ok()?;
    let ids_start = 4usize.checked_add(ids_offset)?;
    let len_end = ids_start.checked_add(32)?;
    let len = EVMU256::try_from_be_slice(calldata.get(ids_start..len_end)?)?;
    if len == EVMU256::ZERO {
        return None;
    }
    let first_elem_end = len_end.checked_add(32)?;
    EVMU256::try_from_be_slice(calldata.get(len_end..first_elem_end)?)
}

fn sub_bug_idx(target: &EVMAddress, from: &EVMAddress, token_id: &EVMU256) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    from.hash(&mut hasher);
    token_id.hash(&mut hasher);
    (hasher.finish() << 8) + NFT_TRANSFER_BUG_IDX
}

/// Detects a `transferFrom`/`safeTransferFrom` call on an ERC721/ERC1155
/// token that succeeded even though the caller was neither the token's
/// owner (ERC721) / holder (ERC1155), nor an approved operator -- i.e. a
/// missing or bypassed `_isApprovedOrOwner`-style check.
///
/// Black-box: `transferFrom(address,address,uint256)` has the exact same
/// selector as ERC20's `transferFrom`, so this only fires when the target
/// also answers `ownerOf(tokenId)` (ERC721) or `balanceOf(from, id)`
/// (ERC1155) for the specific token involved -- that's what disambiguates
/// an NFT contract from a plain ERC20 one.
pub struct NftTransferOracle {}

impl Default for NftTransferOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl NftTransferOracle {
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
    > for NftTransferOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        let calldata = ctx.input.to_bytes();
        if calldata.len() < 4 {
            return vec![];
        }
        let selector = &calldata[0..4];
        let target = ctx.input.get_contract();
        let caller = ctx.input.get_caller();

        let is_erc721 = selector == TRANSFER_FROM_SELECTOR ||
            selector == SAFE_TRANSFER_FROM_3_SELECTOR ||
            selector == SAFE_TRANSFER_FROM_4_SELECTOR;
        let is_erc1155 = selector == SAFE_TRANSFER_FROM_1155_SELECTOR;
        let is_erc1155_batch = selector == SAFE_BATCH_TRANSFER_FROM_1155_SELECTOR;

        if !is_erc721 && !is_erc1155 && !is_erc1155_batch {
            return vec![];
        }
        // All shapes start with (address from, address to, ...)
        if calldata.len() < 100 {
            return vec![];
        }
        let from = match EVMU256::try_from_be_slice(&calldata[4..36]) {
            Some(v) => convert_u256_to_h160(v),
            None => return vec![],
        };
        let token_id = if is_erc1155_batch {
            match decode_first_batch_id(&calldata) {
                Some(v) => v,
                None => return vec![], // empty batch or malformed encoding
            }
        } else {
            match EVMU256::try_from_be_slice(&calldata[68..100]) {
                Some(v) => v,
                None => return vec![],
            }
        };

        if is_erc721 {
            let probe_calls: Vec<(EVMAddress, Bytes)> = vec![
                (target, [&OWNER_OF_SELECTOR[..], &token_id.to_be_bytes::<32>()].concat().into()),
                (target, [&GET_APPROVED_SELECTOR[..], &token_id.to_be_bytes::<32>()].concat().into()),
                (
                    target,
                    [
                        &IS_APPROVED_FOR_ALL_SELECTOR[..],
                        &[0u8; 12][..],
                        from.as_slice(),
                        &[0u8; 12][..],
                        caller.as_slice(),
                    ]
                    .concat()
                    .into(),
                ),
            ];
            let results = ctx
                .executor
                .deref()
                .borrow_mut()
                .fast_static_call(&probe_calls, ctx.pre_state, ctx.fuzz_state);

            let owner_raw = &results[0];
            if owner_raw.len() != 32 {
                // doesn't answer ownerOf() -- not an ERC721-shaped contract
                return vec![];
            }
            let owner_pre = convert_u256_to_h160(EVMU256::try_from_be_slice(owner_raw).unwrap_or(EVMU256::ZERO));
            if owner_pre == EVMAddress::default() {
                // token id was never minted -- nothing real to steal
                return vec![];
            }

            let approved = (results[1].len() == 32)
                .then(|| EVMU256::try_from_be_slice(&results[1]))
                .flatten()
                .map(convert_u256_to_h160);
            let is_operator = (results[2].len() == 32)
                .then(|| EVMU256::try_from_be_slice(&results[2]))
                .flatten()
                .map(|v| v != EVMU256::ZERO)
                .unwrap_or(false);

            let is_authorized = caller == owner_pre || approved == Some(caller) || is_operator;

            if !is_authorized {
                let bug_idx = sub_bug_idx(&target, &from, &token_id);
                EVMBugResult::new_simple(
                    "Unauthorized NFT Transfer".to_string(),
                    bug_idx,
                    format!(
                        "ERC721 token {:?} on {:?} (owner {:?}) was transferred away from {:?} by {:?}, who was neither the owner, the approved address, nor an approved operator -- missing or bypassed access-control check.\n",
                        token_id, target, owner_pre, from, caller
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                )
                .push_to_output();
                return vec![bug_idx];
            }
        } else if is_erc1155 || is_erc1155_batch {
            if from == EVMAddress::default() {
                // zero address can't be a real token holder
                return vec![];
            }
            let probe_calls: Vec<(EVMAddress, Bytes)> = vec![
                (
                    target,
                    [&BALANCE_OF_1155_SELECTOR[..], &[0u8; 12][..], from.as_slice(), &token_id.to_be_bytes::<32>()]
                        .concat()
                        .into(),
                ),
                (
                    target,
                    [
                        &IS_APPROVED_FOR_ALL_SELECTOR[..],
                        &[0u8; 12][..],
                        from.as_slice(),
                        &[0u8; 12][..],
                        caller.as_slice(),
                    ]
                    .concat()
                    .into(),
                ),
            ];
            let results = ctx
                .executor
                .deref()
                .borrow_mut()
                .fast_static_call(&probe_calls, ctx.pre_state, ctx.fuzz_state);

            let balance_raw = &results[0];
            if balance_raw.len() != 32 {
                // doesn't answer balanceOf(address,uint256) -- not ERC1155-shaped
                return vec![];
            }
            let balance_pre = EVMU256::try_from_be_slice(balance_raw).unwrap_or(EVMU256::ZERO);
            if balance_pre == EVMU256::ZERO {
                // `from` never held this token id; nothing meaningful to authorize
                return vec![];
            }
            let is_operator = (results[1].len() == 32)
                .then(|| EVMU256::try_from_be_slice(&results[1]))
                .flatten()
                .map(|v| v != EVMU256::ZERO)
                .unwrap_or(false);

            let is_authorized = caller == from || is_operator;

            if !is_authorized {
                let bug_idx = sub_bug_idx(&target, &from, &token_id);
                let batch_note = if is_erc1155_batch { " (batch transfer, first id shown)" } else { "" };
                EVMBugResult::new_simple(
                    "Unauthorized ERC1155 Transfer".to_string(),
                    bug_idx,
                    format!(
                        "ERC1155 token id {:?} on {:?} was transferred away from holder {:?} by {:?}, who was neither the holder nor an approved operator -- missing or bypassed access-control check{}.\n",
                        token_id, target, from, caller, batch_note
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
