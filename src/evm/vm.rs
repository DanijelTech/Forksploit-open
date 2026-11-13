use core::ops::Range;
use std::{
    any::Any,
    cell::RefCell,
    cmp::min,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fmt::Debug,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use bytes::Bytes;
/// EVM executor implementation
use itertools::Itertools;
use libafl::schedulers::Scheduler;
use revm_interpreter::{
    BytecodeLocked,
    CallContext,
    CallScheme,
    Contract,
    Gas,
    InstructionResult,
    InstructionResult::ControlLeak,
    Interpreter,
    Memory,
    Stack,
};
use revm_primitives::Bytecode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{debug, error};

use super::{input::EVMInput, middlewares::reentrancy::ReentrancyData, types::EVMFuzzState};
use crate::{evm::tokens::SwapData, generic_vm::vm_state};
#[allow(unused_imports)]
use crate::{
    evm::{
        bytecode_analyzer,
        host::{FuzzHost, CMP_MAP, COVERAGE_NOT_CHANGED, JMP_MAP, READ_MAP, STATE_CHANGE, WRITE_MAP},
        input::{ConciseEVMInput, EVMInputT, EVMInputTy},
        middlewares::middleware::Middleware,
        onchain::flashloan::FlashloanData,
        types::{float_scale_to_u512, EVMAddress, EVMU256, EVMU512},
        vm::Constraint::{NoLiquidation, Value},
    },
    generic_vm::{
        vm_executor::{ExecutionResult, GenericVM, MAP_SIZE},
        vm_state::VMStateT,
    },
    input::{ConciseSerde, VMInputT},
    invoke_middlewares,
    state::{HasCaller, HasCurrentInputIdx, HasItyState},
    state_input::StagedVMState,
};

pub const MEM_LIMIT: u64 = 500 * 1024;
/// How many nested control-leak continuations (`PostExecutionCtx`) one
/// transaction may accumulate before it is abandoned as reverted. Widened
/// from 10: the deepest real exploit shapes this tool targets -- a flashloan
/// whose callback re-enters a vault, which re-enters a token, which
/// re-enters an oracle (L7-L10-style chains) -- routinely need more than 10
/// distinct leak boundaries to be explored at all. Hitting this cap does
/// not just stop extending the chain: `execute` returns `reverted: true`,
/// so the WHOLE input is discarded as if it had failed, which is exactly the
/// "compound exploit never gets explored" symptom. Higher is search depth,
/// bounded by memory in practice.
const MAX_POST_EXECUTION: usize = 64;

/// Get the token context from the flashloan middleware,
/// which contains uniswap pairs of that token
#[macro_export]
macro_rules! get_token_ctx {
    ($flashloan_mid: expr, $token: expr) => {
        $flashloan_mid
            .flashloan_oracle
            .deref()
            .borrow()
            .known_tokens
            .get(&$token)
            .expect(format!("unknown token : {:?}", $token).as_str())
    };
}

/// Determine whether a call is successful
#[macro_export]
macro_rules! is_call_success {
    ($ret: expr) => {
        $ret == revm_interpreter::InstructionResult::Return ||
            $ret == revm_interpreter::InstructionResult::Stop ||
            $ret == revm_interpreter::InstructionResult::ControlLeak ||
            $ret == revm_interpreter::InstructionResult::SelfDestruct
    };
}

/// A post execution constraint
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Constraint {
    Caller(EVMAddress),
    Contract(EVMAddress),
    Value(EVMU256),
    NoLiquidation,
    MustStepNow,
}

/// A post execution context
/// When control is leaked, we dump the current execution context. This context
/// includes all information needed to continue subsequent execution (e.g.,
/// stack, pc, memory, etc.) Post execution context is attached to VM state if
/// control is leaked.
///
/// When EVM input has `step` set to true, then we continue execution from the
/// post execution context available. If `step` is false, then we conduct
/// reentrancy (i.e., don't need to continue execution from the post execution
/// context but we execute the input directly
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SinglePostExecution {
    /// All continuation info
    /// Instruction pointer.
    pub program_counter: usize,
    /// Return is main control flag, it tell us if we should continue
    /// interpreter or break from it
    pub instruction_result: InstructionResult,
    /// Memory.
    pub memory: Memory,
    /// Stack.
    pub stack: Stack,
    /// Return value.
    pub return_range: Range<usize>,
    /// Is interpreter call static.
    pub is_static: bool,
    /// Contract information and invoking data
    pub input: Bytes,
    /// Bytecode contains contract code, size of original code, analysis with
    /// gas block and jump table. Note that current code is extended with
    /// push padding and STOP at end.
    pub code_address: EVMAddress,
    /// Contract address
    pub address: EVMAddress,
    /// Caller of the EVM.
    pub caller: EVMAddress,
    /// Value send to contract.
    pub value: EVMU256,

    /// Post execution related information
    /// Output Length
    pub output_len: usize,
    /// Output Offset
    pub output_offset: usize,
}

impl Hash for SinglePostExecution {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.program_counter.hash(state);
        self.memory.data.hash(state);
        self.stack.data.hash(state);
        self.return_range.hash(state);
        self.is_static.hash(state);
        self.input.hash(state);
        self.code_address.hash(state);
        self.address.hash(state);
        self.caller.hash(state);
        self.value.hash(state);
        self.output_len.hash(state);
        self.output_offset.hash(state);
    }
}

impl SinglePostExecution {
    /// Convert the post execution context to revm [`CallContext`]
    fn get_call_ctx(&self) -> CallContext {
        CallContext {
            address: self.address,
            caller: self.caller,
            apparent_value: self.value,
            code_address: self.code_address,
            scheme: CallScheme::Call,
        }
    }

    fn get_interpreter(&self, bytecode: Arc<BytecodeLocked>) -> Interpreter {
        let contract = Contract::new_with_context_analyzed(self.input.clone(), bytecode, &self.get_call_ctx());

        let mut stack = Stack::new();
        for v in &self.stack.data {
            let _ = stack.push(*v);
        }

        Interpreter {
            instruction_pointer: unsafe { contract.bytecode.as_ptr().add(self.program_counter) },
            instruction_result: self.instruction_result,
            gas: Gas::new(0),
            memory: self.memory.clone(),
            stack,
            return_data_buffer: Bytes::new(),
            return_range: self.return_range.clone(),
            is_static: self.is_static,
            contract,
            memory_limit: MEM_LIMIT,
        }
    }

    pub fn from_interp(interp: &Interpreter, (out_offset, out_len): (usize, usize)) -> Self {
        Self {
            program_counter: interp.program_counter(),
            instruction_result: interp.instruction_result,
            memory: interp.memory.clone(),
            stack: interp.stack.clone(),
            return_range: interp.return_range.clone(),
            is_static: interp.is_static,
            input: interp.contract.input.clone(),
            code_address: interp.contract.code_address,
            address: interp.contract.address,
            caller: interp.contract.caller,
            value: interp.contract.value,
            output_len: out_len,
            output_offset: out_offset,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostExecutionCtx {
    pub constraints: Vec<Constraint>,
    pub pes: Vec<SinglePostExecution>,

    pub must_step: bool,
}

impl Hash for PostExecutionCtx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for pe in &self.pes {
            pe.hash(state);
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct EVMState {
    /// State of the EVM, which is mapping of EVMU256 slot to EVMU256 value for
    /// each contract
    pub state: HashMap<EVMAddress, HashMap<EVMU256, EVMU256>>,

    /// Balance of addresses
    pub balance: HashMap<EVMAddress, EVMU256>,

    /// Post execution context
    /// If control leak happens, we add the post execution context to the VM
    /// state, which contains all information needed to continue execution.
    ///
    /// There can be more than one [`PostExecutionCtx`] when the control is
    /// leaked again on the incomplete state (i.e., double+ reentrancy)
    pub post_execution: Vec<PostExecutionCtx>,

    /// Flashloan information
    /// (e.g., how much flashloan is taken, and how much tokens are liquidated)
    #[serde(skip)]
    pub flashloan_data: FlashloanData,

    /// Is bug() call in Solidity hit?
    #[serde(skip)]
    pub bug_hit: bool,
    /// selftdestruct() call in Solidity hit?
    #[serde(skip)]
    pub self_destruct: HashSet<(EVMAddress, usize)>,
    /// bug type call in solidity type
    #[serde(skip)]
    pub typed_bug: HashSet<(String, (EVMAddress, usize))>,
    #[serde(skip)]
    pub arbitrary_calls: HashSet<(EVMAddress, EVMAddress, usize)>,
    // integer overflow in sol
    #[serde(skip)]
    pub integer_overflow: HashSet<(EVMAddress, usize, &'static str)>,
    // delegatecall injection (attacker-controlled delegatecall target)
    #[serde(skip)]
    pub delegatecall_injections: HashSet<(EVMAddress, usize)>,
    // ecrecover() returned the zero address but the caller's tx still succeeded
    #[serde(skip)]
    pub ecrecover_zero: HashSet<(EVMAddress, usize)>,
    // slots written both natively and from inside a DELEGATECALL frame
    #[serde(skip)]
    pub storage_collisions: HashSet<(EVMAddress, EVMU256)>,
    // DELEGATECALL targets whose address appeared in the calling tx's own calldata
    #[serde(skip)]
    pub delegatecall_targets_seen: HashSet<(EVMAddress, usize, EVMAddress)>,
    // MLOADs reading a memory word never written in the current call frame
    #[serde(skip)]
    pub uninitialized_memory_reads: HashSet<(EVMAddress, usize)>,
    // plain CALL/CALLCODE that failed and whose return value was discarded
    // (POPped) without any check, in a transaction that still succeeded overall
    #[serde(skip)]
    pub unchecked_call: HashSet<(EVMAddress, usize)>,
    // ORIGIN read while msg.sender != tx.origin, in a transaction that
    // still succeeded overall (tx.origin phishing bypass)
    #[serde(skip)]
    pub tx_origin_checks: HashSet<(EVMAddress, usize)>,
    // (address, pc, slot) for every SSTORE whose slot came straight from
    // calldata (see oracles/arbitrary_storage_write.rs)
    #[serde(skip)]
    pub arbitrary_storage_writes: HashSet<(EVMAddress, usize, EVMU256)>,
    // (address, pc, slot) for every SSTORE that zeroed a nonzero,
    // address-shaped slot without a prior zero-check (see
    // oracles/zero_address_setter.rs)
    #[serde(skip)]
    pub zero_address_setters: HashSet<(EVMAddress, usize, EVMU256)>,
    // (address, pc, gas_limit) for every outgoing CALL made with a
    // hardcoded low gas stipend (see oracles/gas_stipend.rs)
    #[serde(skip)]
    pub hardcoded_gas_stipends: HashSet<(EVMAddress, usize, u64)>,
    // (address, pc) for every MOD/AND/comparison consuming a block
    // environment read (see oracles/weak_randomness.rs)
    #[serde(skip)]
    pub weak_randomness_uses: HashSet<(EVMAddress, usize)>,
    // (address, pc) for every (a/b)*c precision-loss ordering (see
    // oracles/precision_loss.rs)
    #[serde(skip)]
    pub precision_losses: HashSet<(EVMAddress, usize)>,
    // (address, pc) for every failed outgoing CALL made while a loop was
    // active in the same call (see oracles/revert_in_loop.rs)
    #[serde(skip)]
    pub revert_in_loop: HashSet<(EVMAddress, usize)>,
    // (address, pc) for every outgoing CALL site that FAILED at least once
    // (see oracles/revert_in_loop.rs)
    #[serde(skip)]
    pub failed_call_sites: HashSet<(EVMAddress, usize)>,
    // (address, pc) for every reachable INVALID reached with non-empty
    // calldata (see oracles/assert_violation.rs)
    #[serde(skip)]
    pub assert_violations: HashSet<(EVMAddress, usize)>,
    // (address, pc) for every SSTORE that credited an unverified
    // transferFrom amount instead of a real balanceOf() delta (see
    // oracles/token_accounting_mismatch.rs)
    #[serde(skip)]
    pub token_accounting_mismatches: HashSet<(EVMAddress, usize)>,
    // (address, pc) for every EQ that compared against this contract's
    // own real ETH balance (see oracles/forced_eth_accounting.rs)
    #[serde(skip)]
    pub forced_eth_accounting_checks: HashSet<(EVMAddress, usize)>,
    // (address, pc) for every call that re-queried an already-baselined
    // (target, selector) and got a different value while a control-leak
    // was pending (see oracles/readonly_reentrancy.rs)
    #[serde(skip)]
    pub readonly_reentrancy_hits: HashSet<(EVMAddress, usize)>,
    // (address, loop JUMPDEST pc) -> how many times that loop iterated in
    // THIS call (see oracles/unbounded_loop.rs)
    #[serde(skip)]
    pub loop_iterations: HashMap<(EVMAddress, usize), u64>,
    // (address, jumpi pc, slot, value) for every JUMPI this call whose
    // condition looks SLOAD-derived (see oracles/stale_guard.rs)
    #[serde(skip)]
    pub guard_reads: Vec<(EVMAddress, usize, EVMU256, EVMU256)>,
    // (address, jumpi pc, arg address, branch taken) for every JUMPI this
    // call whose condition looks derived from an address-type calldata
    // argument (see oracles/self_referral.rs)
    #[serde(skip)]
    pub arg_guard_reads: Vec<(EVMAddress, usize, EVMAddress, bool)>,
    // address-type calldata arguments that also received a value-carrying
    // CALL this same call (see oracles/self_referral.rs)
    #[serde(skip)]
    pub paid_calldata_addresses: HashSet<EVMAddress>,
    // every address-shaped 32-byte word copied via RETURNDATACOPY this
    // call (see oracles/delegatecall_target.rs's cross-contract
    // value-flow check)
    #[serde(skip)]
    pub returndata_addresses: HashSet<EVMAddress>,
    // (address, eq pc, root word) for every JUMPI this call that ACCEPTED a
    // condition comparing a freshly computed SHA3 hash against a
    // caller-supplied calldata word -- the forged-proof shape (see
    // oracles/forged_proof.rs).
    #[serde(skip)]
    pub proof_accepted: Vec<(EVMAddress, usize, EVMU256)>,
    // calldata words that were compared against an SLOAD'd value this call
    // (i.e. checked against authoritative state, the SAFE shape) -- used to
    // exclude a proof-accepted hit on that same word (see
    // oracles/forged_proof.rs).
    #[serde(skip)]
    pub calldata_sload_compared: HashSet<EVMU256>,
    // (address, tstore pc, slot) for every external CALL this call executed
    // while an EIP-1153 transient guard slot was unlocked -- the guard was
    // released before the external call (see oracles/transient_guard.rs).
    #[serde(skip)]
    pub transient_unlock_calls: Vec<(EVMAddress, usize, EVMU256)>,
    // transient slots TLOAD'd this call -- candidate guard slots (see
    // oracles/transient_guard.rs).
    #[serde(skip)]
    pub transient_loaded: HashSet<(EVMAddress, EVMU256)>,
    // every address-shaped value loaded via CALLDATALOAD this call (see
    // oracles/delegatecall_target.rs's precise calldata-provenance
    // check, and oracles/self_referral.rs which already consumes the
    // same underlying host field for its own purpose)
    #[serde(skip)]
    pub calldata_addresses: HashSet<EVMAddress>,
    #[serde(skip)]
    pub reentrancy_metadata: ReentrancyData,
    #[serde(skip)]
    pub swap_data: SwapData,
}

pub trait EVMStateT {
    fn get_constraints(&self) -> Vec<Constraint>;
}

impl EVMStateT for EVMState {
    fn get_constraints(&self) -> Vec<Constraint> {
        match self.post_execution.last() {
            Some(i) => i.constraints.clone(),
            None => vec![],
        }
    }
}

impl VMStateT for EVMState {
    /// Calculate the hash of the VM state
    fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        for i in self.post_execution.iter() {
            i.hash(&mut s);
        }
        for i in self.state.iter().sorted_by_key(|k| k.0) {
            i.0 .0.hash(&mut s);
            for j in i.1.iter() {
                j.0.hash(&mut s);
                j.1.hash(&mut s);
            }
        }
        s.finish()
    }

    /// Check whether current state has post execution context
    /// This can also used to check whether a state is intermediate state (i.e.,
    /// not yet finished execution)
    fn has_post_execution(&self) -> bool {
        !self.post_execution.is_empty()
    }

    /// Get length needed for return data length of the call that leads to
    /// control leak
    fn get_post_execution_needed_len(&self) -> usize {
        self.post_execution.last().unwrap().pes.first().unwrap().output_len
    }

    /// Get the PC of last post execution context
    fn get_post_execution_pc(&self) -> usize {
        match self.post_execution.last() {
            Some(i) => i.pes.first().unwrap().program_counter,
            None => 0,
        }
    }

    /// Get amount of post execution context
    fn get_post_execution_len(&self) -> usize {
        self.post_execution.len()
    }

    /// Get flashloan information
    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String {
        format!(
            "earned: {:?}, owed: {:?}",
            self.flashloan_data.earned, self.flashloan_data.owed
        )
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        self.state.iter().all(|(k, v)| {
            other
                .state
                .get(k)
                .map_or(false, |v2| v.iter().all(|(k, v)| v2.get(k).map_or(false, |v2| v == v2)))
        })
    }

    fn get_swap_data(&self) -> HashMap<String, vm_state::SwapInfo> {
        self.swap_data.to_generic()
    }
}

impl EVMState {
    /// Create a new EVM state, containing empty state, no post execution
    /// context
    pub(crate) fn new() -> Self {
        Default::default()
    }

    /// Get all storage slots of a specific contract
    pub fn get(&self, address: &EVMAddress) -> Option<&HashMap<EVMU256, EVMU256>> {
        self.state.get(address)
    }

    /// Get all storage slots of a specific contract (mutable)
    pub fn get_mut(&mut self, address: &EVMAddress) -> Option<&mut HashMap<EVMU256, EVMU256>> {
        self.state.get_mut(address)
    }

    /// Insert all storage slots of a specific contract
    pub fn insert(&mut self, address: EVMAddress, storage: HashMap<EVMU256, EVMU256>) {
        self.state.insert(address, storage);
    }

    /// Get balance of a specific address
    pub fn get_balance(&self, address: &EVMAddress) -> Option<&EVMU256> {
        self.balance.get(address)
    }

    /// Set balance of a specific address
    pub fn set_balance(&mut self, address: EVMAddress, balance: EVMU256) {
        self.balance.insert(address, balance);
    }

    /// Loads a storage slot from an address.
    pub fn sload(&self, address: EVMAddress, slot: EVMU256) -> Option<EVMU256> {
        self.state.get(&address).and_then(|slots| slots.get(&slot).cloned())
    }

    /// Stores a value to an address' storage slot.
    pub fn sstore(&mut self, address: EVMAddress, slot: EVMU256, value: EVMU256) {
        self.state.entry(address).or_default().insert(slot, value);
    }
}

/// Is current EVM execution fast call
pub static IS_FAST_CALL: AtomicBool = AtomicBool::new(false);

/// Is current EVM execution fast call (static)
/// - Fast call is a call that does not change the state of the contract
pub static IS_FAST_CALL_STATIC: AtomicBool = AtomicBool::new(false);

/// EVM executor, wrapper of revm
#[derive(Debug, Clone)]
pub struct EVMExecutor<VS, CI, SC>
where
    VS: VMStateT,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    /// Host providing the blockchain environment (e.g., writing/reading
    /// storage), needed by revm
    pub host: FuzzHost<SC>,
    /// [Depreciated] Deployer address
    pub deployer: EVMAddress,
    /// Known arbitrary (caller,pc)
    pub _known_arbitrary: HashSet<(EVMAddress, usize)>,
    phandom: PhantomData<(EVMInput, VS, CI)>,
}

pub fn is_reverted_or_control_leak(ret: &InstructionResult) -> bool {
    !matches!(
        *ret,
        InstructionResult::Return | InstructionResult::Stop | InstructionResult::SelfDestruct
    )
}

/// Encode the control-leak boundary (the host's full-width `call_count`)
/// into `ExecutionResult::additional_info`.
///
/// This is the wire format shared with `decode_call_leak` below: 4 bytes,
/// little-endian, so the whole `u32` survives. It used to be written as
/// `call_count as u8`, which truncated the boundary mod 256 -- a trace whose
/// leak happened after call 255 recorded a wrong `call_leak`, and since that
/// value is replayed straight back into `CALL_UNTIL`
/// (`cov_stage.rs`/`minimizer.rs`), such a finding no longer reproduced at
/// the same call.
pub(crate) fn encode_call_leak(call_count: u32) -> Vec<u8> {
    call_count.to_le_bytes().to_vec()
}

/// Decode `additional_info` back into the `call_leak` boundary.
///
/// `None` (the field is set only when the run ended in a control leak) means
/// `u32::MAX` -- CALL_UNTIL's neutral default, "ran to completion, no call
/// intercepted". A short buffer (e.g. the historical 1-byte encoding) is
/// still read as a little-endian value, so old serialized states keep
/// decoding to their original meaning instead of being rejected.
pub(crate) fn decode_call_leak(info: Option<&[u8]>) -> u32 {
    match info {
        None => u32::MAX,
        Some(bytes) => {
            let mut buf = [0u8; 4];
            let n = bytes.len().min(4);
            buf[..n].copy_from_slice(&bytes[..n]);
            u32::from_le_bytes(buf)
        }
    }
}

/// Execution result that may have control leaked
/// Contains raw information of revm output and execution
#[derive(Clone, Debug)]
pub struct IntermediateExecutionResult {
    /// Output of the execution
    pub output: Bytes,
    /// The new state after execution
    pub new_state: EVMState,
    /// Program counter after execution
    pub pc: usize,
    /// Return value after execution
    pub ret: InstructionResult,
    /// Stack after execution
    pub stack: Vec<EVMU256>,
    /// Memory after execution
    pub memory: Vec<u8>,
}

macro_rules! init_host {
    ($host:expr) => {
        $host.current_self_destructs = vec![];
        $host.current_arbitrary_calls = vec![];
        // Found live 2026-11-02 (real ETC mainnet, target 0x9f5304...): these
        // four were the ONLY current_* HashSets NOT reset per transaction here
        // (current_arbitrary_calls above always was) -- so they kept
        // accumulating across the WHOLE fuzzing process, not just one
        // transaction. vm.rs's own EVMState.X = pre_state.X.chain(current_X)
        // pattern then meant ANY transaction, in ANY unrelated corpus branch,
        // would see a NON-EMPTY current_ecrecover_zero/etc. the moment ANY
        // other branch had EVER tripped the condition once -- a diff against
        // pre_state (this session's first fix, in the oracles themselves)
        // wasn't sufficient on its own, because current_X itself was already
        // process-wide-dirty by the time a fresh, unrelated lineage's pre_state
        // was computed. Confirmed independently via debug_traceCall both ways:
        // a call the oracle described as "called ecrecover() at pc 2214" never
        // executed past pc 2050 on real chain state.
        $host.current_integer_overflow = HashSet::new();
        $host.current_delegatecall_injections = HashSet::new();
        $host.current_ecrecover_zero = HashSet::new();
        $host.current_storage_collisions = HashSet::new();
        // Found 2026-11-03 via a systematic re-check of EVERY EVMState
        // field unioned forward in this file (grep for ".chain(self.host.
        // current_" below) -- these four had the exact same never-reset
        // bug as the four above, just missed by yesterday's narrower
        // grep (which only searched for those four field names
        // specifically, not a full audit of the chain(...) call sites).
        $host.current_uninitialized_memory_reads = HashSet::new();
        $host.current_unchecked_call = HashSet::new();
        $host.current_tx_origin_checks = HashSet::new();
        $host.current_delegatecall_targets_seen = HashSet::new();
        $host.current_loop_iterations = HashMap::new();
        $host.current_last_sload = None;
        $host.current_guard_reads = vec![];
        $host.current_last_calldata_compare = None;
        $host.current_calldata_addresses = HashSet::new();
        $host.current_calldata_words = HashSet::new();
        $host.current_arbitrary_storage_writes = HashSet::new();
        $host.current_pending_token_transfer_in = None;
        $host.current_token_accounting_mismatches = HashSet::new();
        $host.current_last_self_balance_read = None;
        $host.current_forced_eth_accounting_checks = HashSet::new();
        $host.current_readonly_reentrancy_hits = HashSet::new();
        $host.current_zero_address_setters = HashSet::new();
        $host.current_hardcoded_gas_stipends = HashSet::new();
        $host.current_last_env_read = None;
        $host.current_weak_randomness_uses = HashSet::new();
        $host.current_precision_losses = HashSet::new();
        $host.current_last_div = None;
        $host.current_revert_in_loop = HashSet::new();
        $host.current_call_site_counts = HashMap::new();
        $host.current_call_fail_counts = HashMap::new();
        $host.current_assert_violations = HashSet::new();
        $host.current_arg_guard_reads = vec![];
        $host.current_paid_calldata_addresses = HashSet::new();
        $host.current_returndata_addresses = HashSet::new();
        $host.current_last_sha3 = None;
        $host.current_calldata_sload_compared = HashSet::new();
        $host.current_proof_accepted = vec![];
        $host.current_last_proof_compare = None;
        $host.current_transient_loaded = HashSet::new();
        $host.current_transient_locked = HashSet::new();
        $host.current_transient_unlock = None;
        $host.current_transient_unlock_calls = vec![];
        $host.call_count = 0;
        $host.jumpi_trace = 37;
        $host.current_typed_bug = vec![];
        $host.randomness = vec![9];
        $host.transient_storage = HashMap::new();
        // Uncomment the next line if middleware is needed.
        // $host.add_middlewares(middleware.clone());
    };
}

macro_rules! execute_call_single {
    ($ctx:expr, $host:expr, $state:expr, $address: expr, $by: expr) => {{
        match $host.code.get($address) {
            // Oracles and producers probe arbitrary addresses (e.g. a
            // function argument that was never actually deployed); treat
            // "no code loaded" the same as a failed call instead of
            // panicking the whole campaign.
            None => (Vec::new(), false),
            Some(code) => {
                let code = code.clone();
                let call = Contract::new_with_context_analyzed($by.clone(), code, &$ctx);
                let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT);
                let ret = $host.run_inspect(&mut interp, $state);
                (interp.return_value().to_vec(), is_call_success!(ret))
            }
        }
    }};
}

impl<VS, CI, SC> EVMExecutor<VS, CI, SC>
where
    VS: Default + VMStateT + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    pub fn fast_call_(
        &mut self,
        address: EVMAddress,
        data: Bytes,
        vm_state: &mut EVMState,
        state: &mut EVMFuzzState,
        value: EVMU256,
        from: EVMAddress,
    ) -> (Bytes, InstructionResult) {
        IS_FAST_CALL.store(true, Ordering::Relaxed);
        // debug!("fast call: {:?} {:?} with {}", address, hex::encode(data.to_vec()),
        // value);
        let call = Contract::new_with_context_analyzed(
            data,
            self.host
                .code
                .get(&address)
                .unwrap_or_else(|| panic!("no code {:?}", address))
                .clone(),
            &CallContext {
                address,
                caller: from,
                code_address: address,
                apparent_value: value,
                scheme: CallScheme::Call,
            },
        );
        self.host.evmstate = vm_state.clone();
        let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT);
        let ret = self.host.run_inspect(&mut interp, state);
        *vm_state = self.host.evmstate.clone();
        IS_FAST_CALL.store(false, Ordering::Relaxed);
        (interp.return_value(), ret)
    }

    /// Create a new EVM executor given a host and deployer address
    pub fn new(fuzz_host: FuzzHost<SC>, deployer: EVMAddress) -> Self {
        Self {
            host: fuzz_host,
            deployer,
            _known_arbitrary: Default::default(),
            phandom: PhantomData,
        }
    }

    /// Execute from a specific program counter and context
    ///
    /// `call_ctx` is the context of the call (e.g., caller address, callee
    /// address, etc.) `vm_state` is the VM state to execute on
    /// `data` is the input (function hash + serialized ABI args)
    /// `input` is the additional input information (e.g., access pattern, etc.)
    ///     If post execution context exists, then this is the return buffer of
    /// the call that leads     to control leak. This is like we are fuzzing
    /// the subsequent execution wrt the return     buffer of the control
    /// leak call. `post_exec` is the post execution context to use, if any
    ///     If `post_exec` is `None`, then the execution is from the beginning,
    /// otherwise it is from     the post execution context.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_from_pc(
        &mut self,
        call_ctx: &CallContext,
        vm_state: &EVMState,
        data: Bytes,
        input: &EVMInput,
        post_exec: Option<SinglePostExecution>,
        state: &mut EVMFuzzState,
        cleanup: bool,
    ) -> IntermediateExecutionResult {
        // Initial setups
        if cleanup {
            self.host.coverage_changed = false;
            self.host.bug_hit = false;
            self.host.current_typed_bug = vec![];
            self.host.jumpi_trace = 37;
            self.host.current_self_destructs = vec![];
            self.host.current_arbitrary_calls = vec![];
            // See init_host!'s own comment -- these four were never reset here
            // either, so they accumulated across the whole fuzzing process.
            self.host.current_integer_overflow = HashSet::new();
            self.host.current_delegatecall_injections = HashSet::new();
            self.host.current_ecrecover_zero = HashSet::new();
            self.host.current_storage_collisions = HashSet::new();
            // Found 2026-11-03 -- see init_host!'s own updated comment.
            self.host.current_uninitialized_memory_reads = HashSet::new();
            self.host.current_unchecked_call = HashSet::new();
            self.host.current_tx_origin_checks = HashSet::new();
            self.host.current_delegatecall_targets_seen = HashSet::new();
            self.host.current_loop_iterations = HashMap::new();
            self.host.current_last_sload = None;
            self.host.current_guard_reads = vec![];
            self.host.current_last_calldata_compare = None;
            self.host.current_calldata_words = HashSet::new();
            self.host.current_arbitrary_storage_writes = HashSet::new();
            self.host.current_pending_token_transfer_in = None;
            self.host.current_token_accounting_mismatches = HashSet::new();
            self.host.current_last_self_balance_read = None;
            self.host.current_forced_eth_accounting_checks = HashSet::new();
            self.host.current_readonly_reentrancy_hits = HashSet::new();
            self.host.current_zero_address_setters = HashSet::new();
            self.host.current_hardcoded_gas_stipends = HashSet::new();
            self.host.current_last_env_read = None;
            self.host.current_weak_randomness_uses = HashSet::new();
            self.host.current_precision_losses = HashSet::new();
            self.host.current_last_div = None;
            self.host.current_revert_in_loop = HashSet::new();
            self.host.current_call_site_counts = HashMap::new();
            self.host.current_call_fail_counts = HashMap::new();
            self.host.current_assert_violations = HashSet::new();
            self.host.current_arg_guard_reads = vec![];
            self.host.transient_storage = HashMap::new();
            // Found 2026-11-03, same root cause class as view_call_baseline
            // (see readonly_reentrancy.rs): delegatecall_target.rs's
            // cross-call provenance check needs calldata_addresses/
            // returndata_addresses/paid_calldata_addresses to survive a
            // control-leak boundary when a RETURNDATACOPY-decoded address
            // is recorded BEFORE the leaking call, and the actual
            // DELEGATECALL using it only happens in the resumed
            // continuation. Wiping to empty here (as every other current_*
            // field correctly does) would lose that taint. Unlike
            // view_call_baseline, making these persistent-forever on the
            // host would be unsafe here: raw address VALUES recur far more
            // often across unrelated transactions than a narrowly-keyed
            // baseline does, which would let stale, unrelated addresses
            // falsely "confirm" a Confirmed-tier delegatecall target. The
            // precise, safe fix: `post_exec.is_some()` means this call IS a
            // resumption of this exact lineage's own pending continuation
            // (never true for a genuinely fresh top-level transaction, see
            // execute_abi's `None` vs `Some(pe)` call sites below) -- so
            // seed from `vm_state`'s own already-correct field (computed
            // and stored on this exact corpus entry right before the leak)
            // instead of either wiping it or making it eternal.
            if post_exec.is_some() {
                self.host.current_calldata_addresses = vm_state.calldata_addresses.clone();
                self.host.current_returndata_addresses = vm_state.returndata_addresses.clone();
                self.host.current_paid_calldata_addresses = vm_state.paid_calldata_addresses.clone();
            } else {
                self.host.current_calldata_addresses = HashSet::new();
                self.host.current_returndata_addresses = HashSet::new();
                self.host.current_paid_calldata_addresses = HashSet::new();
            }
            // Initially, there is no state change
            STATE_CHANGE.store(false, Ordering::Relaxed);
        }

        self.host.evmstate = vm_state.clone();
        self.host.env = input.get_vm_env().clone();
        self.host.env.tx.caller = if input.get_origin().is_zero() {
            input.get_caller()
        } else {
            input.get_origin() // vm.prank; concolic
        };
        self.host.access_pattern = input.get_access_pattern().clone();
        self.host.call_count = 0;
        self.host.randomness = input.get_randomness();
        let mut repeats = input.get_repeat();

        // Get the bytecode
        let bytecode = match self.host.code.get(&call_ctx.code_address) {
            Some(i) => i.clone(),
            None => {
                debug!("no code @ {:?}, did you forget to deploy?", call_ctx.code_address);
                return IntermediateExecutionResult {
                    output: Bytes::new(),
                    new_state: EVMState::new(),
                    pc: 0,
                    ret: InstructionResult::Revert,
                    stack: Default::default(),
                    memory: Default::default(),
                };
            }
        };

        // Create the interpreter
        let mut interp = if let Some(ref post_exec_ctx) = post_exec {
            // If there is a post execution context, then we need to create the interpreter
            // from the post execution context
            repeats = 1;
            // setup the pc, memory, and stack as the post execution context
            let mut interp = post_exec_ctx.get_interpreter(bytecode);
            // set return buffer as the input
            // we remove the first 4 bytes because the first 4 bytes is the function hash
            // (00000000 here)
            interp.return_data_buffer = data.slice(4..);
            let target_len = min(post_exec_ctx.output_len, interp.return_data_buffer.len());
            interp
                .memory
                .set(post_exec_ctx.output_offset, &interp.return_data_buffer[..target_len]);
            interp
        } else {
            // if there is no post execution context, then we create the interpreter from
            // the beginning
            let call = Contract::new_with_context_analyzed(data, bytecode, call_ctx);
            Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT)
        };

        // Execute the contract for `repeats` times or until revert
        let mut r = InstructionResult::Stop;
        for _v in 0..repeats - 1 {
            // debug!("repeat: {:?}", v);
            r = self.host.run_inspect(&mut interp, state);
            interp.stack.data.clear();
            interp.memory.data.clear();
            interp.instruction_pointer = interp.contract.bytecode.as_ptr();
            if !is_call_success!(r) {
                interp.return_range = 0..0;
                break;
            }
        }
        if is_call_success!(r) {
            r = self.host.run_inspect(&mut interp, state);
        }

        // Build the result
        let mut result = IntermediateExecutionResult {
            output: interp.return_value(),
            new_state: self.host.evmstate.clone(),
            pc: interp.program_counter(),
            ret: r,
            stack: interp.stack.data().clone(),
            memory: interp.memory.data().clone(),
        };

        // [todo] remove this
        if self.host.coverage_changed {
            COVERAGE_NOT_CHANGED.store(0, Ordering::Relaxed);
        } else {
            COVERAGE_NOT_CHANGED.fetch_add(1, Ordering::Relaxed);
        }

        // hack to record txn value
        if let Some(ref m) = self.host.flashloan_middleware {
            m.deref()
                .borrow_mut()
                .analyze_call(input, &mut result.new_state.flashloan_data)
        }

        result
    }

    /// Execute a transaction, wrapper of [`EVMExecutor::execute_from_pc`]
    fn execute_abi(
        &mut self,
        input: &EVMInput,
        state: &mut EVMFuzzState,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        // Get necessary info from input
        let mut vm_state = { input.get_state().as_any().downcast_ref::<EVMState>().unwrap().clone() };

        // check balance
        #[cfg(feature = "real_balance")]
        {
            let tx_value = input.get_txn_value().unwrap_or_default();
            if tx_value > EVMU256::ZERO {
                let caller_balance = *vm_state.get_balance(&input.get_caller()).unwrap_or(&EVMU256::ZERO);
                let contract_balance = *vm_state.get_balance(&input.get_contract()).unwrap_or(&EVMU256::ZERO);
                if !state.has_caller(&input.get_caller()) {
                    if caller_balance < tx_value {
                        return ExecutionResult {
                            output: vec![],
                            reverted: true,
                            new_state: StagedVMState::new_uninitialized(),
                            additional_info: None,
                        };
                    }
                    vm_state.set_balance(input.get_caller(), caller_balance - tx_value);
                }

                vm_state.set_balance(input.get_contract(), contract_balance + tx_value);
            }
        }

        let r;
        let mut is_step = input.is_step();
        let mut data = Bytes::from(input.to_bytes());
        // use direct data (mostly used for debugging) if there is no data
        if data.is_empty() {
            data = Bytes::from(input.get_direct_data());
        }

        let mut cleanup = true;

        loop {
            unsafe {
                invoke_middlewares!(
                    &mut self.host,
                    None,
                    state,
                    before_execute,
                    is_step,
                    &mut data,
                    &mut vm_state
                );
            }
            // Execute the transaction
            let exec_res = if is_step {
                let post_exec = vm_state.post_execution.pop().unwrap().clone();
                let mut local_res = None;
                for mut pe in post_exec.pes {
                    // we need push the output of CALL instruction
                    let _ = pe.stack.push(EVMU256::from(1));
                    let res =
                        self.execute_from_pc(&pe.get_call_ctx(), &vm_state, data, input, Some(pe), state, cleanup);
                    data = Bytes::from([vec![0; 4], res.output.to_vec()].concat());
                    local_res = Some(res);
                    if is_reverted_or_control_leak(&local_res.as_ref().unwrap().ret) {
                        break;
                    }
                    cleanup = false;
                }
                local_res.unwrap()
            } else {
                let caller = input.get_caller();
                let value = input.get_txn_value().unwrap_or(EVMU256::ZERO);
                let contract_address = input.get_contract();
                self.execute_from_pc(
                    &CallContext {
                        address: contract_address,
                        caller,
                        code_address: contract_address,
                        apparent_value: value,
                        scheme: CallScheme::Call,
                    },
                    &vm_state,
                    data,
                    input,
                    None,
                    state,
                    cleanup,
                )
            };
            let need_step = !exec_res.new_state.post_execution.is_empty() &&
                exec_res.new_state.post_execution.last().unwrap().must_step;
            if (exec_res.ret == InstructionResult::Return || exec_res.ret == InstructionResult::Stop) && need_step {
                is_step = true;
                data = Bytes::from([vec![0; 4], exec_res.output.to_vec()].concat());
                // we dont need to clean up bug info and state info
                cleanup = false;
            } else {
                r = Some(exec_res);
                break;
            }
        }
        let mut r = r.unwrap();
        match r.ret {
            ControlLeak |
            InstructionResult::ArbitraryExternalCallAddressBounded(_, _, _) |
            InstructionResult::AddressUnboundedStaticCall => {
                if r.new_state.post_execution.len() + 1 > MAX_POST_EXECUTION {
                    return ExecutionResult {
                        output: r.output.to_vec(),
                        reverted: true,
                        new_state: StagedVMState::new_uninitialized(),
                        additional_info: None,
                    };
                }
                let leak_ctx = self.host.leak_ctx.clone();
                r.new_state.post_execution.push(PostExecutionCtx {
                    pes: leak_ctx,
                    must_step: match r.ret {
                        ControlLeak => false,
                        InstructionResult::ArbitraryExternalCallAddressBounded(_, _, _) => true,
                        InstructionResult::AddressUnboundedStaticCall => false,
                        _ => unreachable!(),
                    },

                    constraints: match r.ret {
                        ControlLeak => vec![],
                        InstructionResult::AddressUnboundedStaticCall => {
                            vec![Constraint::MustStepNow]
                        }
                        InstructionResult::ArbitraryExternalCallAddressBounded(caller, target, value) => {
                            vec![
                                Constraint::Caller(caller),
                                Constraint::Contract(target),
                                Value(value),
                                NoLiquidation,
                            ]
                        }
                        _ => unreachable!(),
                    },
                });
            }
            _ => {}
        }

        r.new_state.typed_bug = HashSet::from_iter(
            vm_state
                .typed_bug
                .iter()
                .cloned()
                .chain(self.host.current_typed_bug.iter().cloned()),
        );
        r.new_state.self_destruct = HashSet::from_iter(
            vm_state
                .self_destruct
                .iter()
                .cloned()
                .chain(self.host.current_self_destructs.iter().cloned()),
        );
        r.new_state.arbitrary_calls = HashSet::from_iter(
            vm_state
                .arbitrary_calls
                .iter()
                .cloned()
                .chain(self.host.current_arbitrary_calls.iter().cloned()),
        );

        r.new_state.integer_overflow = HashSet::from_iter(
            vm_state
                .integer_overflow
                .iter()
                .cloned()
                .chain(self.host.current_integer_overflow.iter().cloned()),
        );

        r.new_state.delegatecall_injections = HashSet::from_iter(
            vm_state
                .delegatecall_injections
                .iter()
                .cloned()
                .chain(self.host.current_delegatecall_injections.iter().cloned()),
        );

        r.new_state.ecrecover_zero = HashSet::from_iter(
            vm_state
                .ecrecover_zero
                .iter()
                .cloned()
                .chain(self.host.current_ecrecover_zero.iter().cloned()),
        );

        r.new_state.storage_collisions = HashSet::from_iter(
            vm_state
                .storage_collisions
                .iter()
                .cloned()
                .chain(self.host.current_storage_collisions.iter().cloned()),
        );

        r.new_state.delegatecall_targets_seen = HashSet::from_iter(
            vm_state
                .delegatecall_targets_seen
                .iter()
                .cloned()
                .chain(self.host.current_delegatecall_targets_seen.iter().cloned()),
        );

        r.new_state.uninitialized_memory_reads = HashSet::from_iter(
            vm_state
                .uninitialized_memory_reads
                .iter()
                .cloned()
                .chain(self.host.current_uninitialized_memory_reads.iter().cloned()),
        );

        r.new_state.unchecked_call = HashSet::from_iter(
            vm_state
                .unchecked_call
                .iter()
                .cloned()
                .chain(self.host.current_unchecked_call.iter().cloned()),
        );

        // Deliberately NOT merged with vm_state's leftover value like the
        // HashSets above -- this is a per-call measurement (how many
        // times did THIS call's loops iterate), not an "ever seen"
        // accumulation, so vm_state's old counts from a PRIOR call would
        // just be stale noise here. The oracle does its own, separate
        // across-calls max-tracking (see oracles/unbounded_loop.rs).
        r.new_state.loop_iterations = self.host.current_loop_iterations.clone();

        // Same reasoning as loop_iterations just above -- per-call
        // observations, not an accumulating set, so no merge with
        // vm_state's leftover value (see oracles/stale_guard.rs and
        // oracles/self_referral.rs, which each do their own cross-call
        // bookkeeping in fuzz_state metadata).
        r.new_state.guard_reads = self.host.current_guard_reads.clone();
        r.new_state.arg_guard_reads = self.host.current_arg_guard_reads.clone();
        r.new_state.paid_calldata_addresses = self.host.current_paid_calldata_addresses.clone();
        r.new_state.returndata_addresses = self.host.current_returndata_addresses.clone();
        r.new_state.proof_accepted = self.host.current_proof_accepted.clone();
        r.new_state.calldata_sload_compared = self.host.current_calldata_sload_compared.clone();
        r.new_state.transient_unlock_calls = self.host.current_transient_unlock_calls.clone();
        r.new_state.transient_loaded = self.host.current_transient_loaded.clone();
        r.new_state.calldata_addresses = self.host.current_calldata_addresses.clone();

        r.new_state.tx_origin_checks = HashSet::from_iter(
            vm_state
                .tx_origin_checks
                .iter()
                .cloned()
                .chain(self.host.current_tx_origin_checks.iter().cloned()),
        );

        r.new_state.arbitrary_storage_writes = HashSet::from_iter(
            vm_state
                .arbitrary_storage_writes
                .iter()
                .cloned()
                .chain(self.host.current_arbitrary_storage_writes.iter().cloned()),
        );

        r.new_state.token_accounting_mismatches = HashSet::from_iter(
            vm_state
                .token_accounting_mismatches
                .iter()
                .cloned()
                .chain(self.host.current_token_accounting_mismatches.iter().cloned()),
        );

        r.new_state.forced_eth_accounting_checks = HashSet::from_iter(
            vm_state
                .forced_eth_accounting_checks
                .iter()
                .cloned()
                .chain(self.host.current_forced_eth_accounting_checks.iter().cloned()),
        );

        r.new_state.readonly_reentrancy_hits = HashSet::from_iter(
            vm_state
                .readonly_reentrancy_hits
                .iter()
                .cloned()
                .chain(self.host.current_readonly_reentrancy_hits.iter().cloned()),
        );

        r.new_state.zero_address_setters = HashSet::from_iter(
            vm_state
                .zero_address_setters
                .iter()
                .cloned()
                .chain(self.host.current_zero_address_setters.iter().cloned()),
        );

        r.new_state.hardcoded_gas_stipends = HashSet::from_iter(
            vm_state
                .hardcoded_gas_stipends
                .iter()
                .cloned()
                .chain(self.host.current_hardcoded_gas_stipends.iter().cloned()),
        );

        r.new_state.weak_randomness_uses = HashSet::from_iter(
            vm_state
                .weak_randomness_uses
                .iter()
                .cloned()
                .chain(self.host.current_weak_randomness_uses.iter().cloned()),
        );

        r.new_state.precision_losses = HashSet::from_iter(
            vm_state
                .precision_losses
                .iter()
                .cloned()
                .chain(self.host.current_precision_losses.iter().cloned()),
        );

        r.new_state.revert_in_loop = HashSet::from_iter(
            vm_state
                .revert_in_loop
                .iter()
                .cloned()
                .chain(self.host.current_revert_in_loop.iter().cloned()),
        );

        r.new_state.failed_call_sites = HashSet::from_iter(
            vm_state
                .failed_call_sites
                .iter()
                .cloned()
                .chain(self.host.current_failed_call_sites.iter().cloned()),
        );

        r.new_state.assert_violations = HashSet::from_iter(
            vm_state
                .assert_violations
                .iter()
                .cloned()
                .chain(self.host.current_assert_violations.iter().cloned()),
        );

        {
            ExecutionResult {
                output: r.output.to_vec(),
                reverted: !matches!(
                    r.ret,
                    InstructionResult::Return |
                        InstructionResult::Stop |
                        InstructionResult::ControlLeak |
                        InstructionResult::SelfDestruct |
                        InstructionResult::AddressUnboundedStaticCall |
                        InstructionResult::ArbitraryExternalCallAddressBounded(_, _, _)
                ),
                new_state: StagedVMState::new_with_state(
                    VMStateT::as_any(&r.new_state).downcast_ref::<VS>().unwrap().clone(),
                ),
                additional_info: if r.ret == ControlLeak {
                    Some(encode_call_leak(self.host.call_count))
                } else {
                    None
                },
            }
        }
    }

    pub fn reexecute_with_middleware(
        &mut self,
        input: &EVMInput,
        state: &mut EVMFuzzState,
        middleware: Rc<RefCell<dyn Middleware<SC>>>,
    ) {
        self.host.add_middlewares(middleware.clone());
        self.execute(input, state);
        self.host.remove_middlewares(middleware);
    }

    fn _fast_call_inner(
        &mut self,
        data: &[(EVMAddress, EVMAddress, Bytes, EVMU256)],
        vm_state: &EVMState,
        state: &mut EVMFuzzState,
    ) -> (Vec<(Vec<u8>, bool)>, EVMState) {
        self.host.evmstate = vm_state.clone();

        init_host!(self.host);
        let res = data
            .iter()
            .map(|(caller, address, by, value)| {
                let ctx = CallContext {
                    address: *address,
                    caller: *caller,
                    code_address: *address,
                    apparent_value: *value,
                    scheme: CallScheme::Call,
                };
                execute_call_single!(ctx, self.host, state, address, by)
            })
            .collect::<Vec<(Vec<u8>, bool)>>();
        (res, self.host.evmstate.clone())
    }

    fn _fast_call_inner_no_value(
        &mut self,
        data: &[(EVMAddress, EVMAddress, Bytes)],
        vm_state: &EVMState,
        state: &mut EVMFuzzState,
    ) -> (Vec<(Vec<u8>, bool)>, EVMState) {
        self.host.evmstate = vm_state.clone();

        init_host!(self.host);
        let res = data
            .iter()
            .map(|(caller, address, by)| {
                let ctx = CallContext {
                    address: *address,
                    caller: *caller,
                    code_address: *address,
                    apparent_value: Default::default(),
                    scheme: CallScheme::Call,
                };
                execute_call_single!(ctx, self.host, state, address, by)
            })
            .collect::<Vec<(Vec<u8>, bool)>>();
        (res, self.host.evmstate.clone())
    }
}

pub static IN_DEPLOY: AtomicBool = AtomicBool::new(false);
pub static SETCODE_ONLY: AtomicBool = AtomicBool::new(false);

impl<VS, CI, SC> GenericVM<VS, Bytecode, Bytes, EVMAddress, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, CI>
    for EVMExecutor<VS, CI, SC>
where
    VS: VMStateT + Default + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    /// Deploy a contract
    fn deploy(
        &mut self,
        code: Bytecode,
        constructor_args: Option<Bytes>,
        deployed_address: EVMAddress,
        state: &mut EVMFuzzState,
    ) -> Option<EVMAddress> {
        debug!("deployer = 0x{} ", hex::encode(self.deployer));
        let deployer = Contract::new(
            constructor_args.unwrap_or_default(),
            code,
            deployed_address,
            deployed_address,
            self.deployer,
            EVMU256::from(0),
        );
        // disable middleware for deployment
        IN_DEPLOY.store(true, Ordering::Relaxed);
        let mut interp = Interpreter::new_with_memory_limit(deployer, 1e10 as u64, false, MEM_LIMIT);
        let mut dummy_state = EVMFuzzState::default();
        let r = self.host.run_inspect(&mut interp, &mut dummy_state);
        IN_DEPLOY.store(false, Ordering::Relaxed);
        if r != InstructionResult::Return {
            error!("deploy failed: {:?}", r);
            return None;
        }
        // debug!(
        //     "deployer = 0x{} contract = {:?}",
        //     hex::encode(self.deployer),
        //     hex::encode(interp.return_value())
        // );
        let mut contract_code = Bytecode::new_raw(interp.return_value());
        bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
        unsafe {
            invoke_middlewares!(
                &mut self.host,
                Some(&mut interp),
                state,
                on_insert,
                &mut contract_code,
                deployed_address
            );
        }
        self.host.set_code(deployed_address, contract_code, state);
        Some(deployed_address)
    }

    /// Execute an input (can be transaction or borrow)
    fn execute(
        &mut self,
        input: &EVMInput,
        state: &mut EVMFuzzState,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        use super::host::clear_branch_status;
        clear_branch_status();
        match input.get_input_type() {
            // buy (borrow because we have infinite ETH) tokens with ETH using uniswap
            EVMInputTy::Borrow => {
                let token = input.get_contract();
                let token_ctx = {
                    let flashloan_mid = self.host.flashloan_middleware.as_ref().unwrap().deref().borrow();
                    let flashloan_oracle = flashloan_mid.flashloan_oracle.deref().borrow();
                    flashloan_oracle
                        .known_tokens
                        .get(&token)
                        .unwrap_or_else(|| panic!("unknown token : {:?}", token))
                        .clone()
                };
                self.host.evmstate = {
                    VMStateT::as_any(input.get_state())
                        .downcast_ref::<EVMState>().unwrap()
                        .clone()
                };
                match token_ctx.buy(
                    input.get_txn_value().unwrap(),
                    input.get_caller(),
                    state,
                    self,
                    input.get_randomness().as_slice(),
                ) {
                    Some(()) => {
                        ExecutionResult {
                            output: vec![],
                            reverted: false,
                            new_state: StagedVMState::new_with_state(
                                VMStateT::as_any(&self.host.evmstate.clone())
                                    .downcast_ref::<VS>().unwrap()
                                    .clone(),
                            ),
                            additional_info: None,
                        }
                    },
                    None => {
                        ExecutionResult {
                            // we don't have enough liquidity to buy the token
                            output: vec![],
                            reverted: true,
                            new_state: StagedVMState::new_with_state({
                                VMStateT::as_any(input.get_state())
                                    .downcast_ref::<VS>().unwrap()
                                    .clone()
                            }),
                            additional_info: None,
                        }
                    }
                }
            }
            EVMInputTy::Liquidate => {
                unreachable!("liquidate should be handled by middleware");
            }
            EVMInputTy::ABI => self.execute_abi(input, state),
            EVMInputTy::ArbitraryCallBoundedAddr => self.execute_abi(input, state),
        }
    }

    /// Execute a static call
    fn fast_static_call(
        &mut self,
        data: &[(EVMAddress, Bytes)],
        vm_state: &VS,
        state: &mut EVMFuzzState,
    ) -> Vec<Vec<u8>> {
        IS_FAST_CALL_STATIC.store(true, Ordering::Relaxed);
        self.host.evmstate = vm_state.as_any().downcast_ref::<EVMState>().unwrap().clone();
        self.host.transient_storage = HashMap::new();
        self.host.current_self_destructs = vec![];
        self.host.current_arbitrary_calls = vec![];
        // See init_host!'s own comment -- these four were never reset here
        // either, so they accumulated across the whole fuzzing process.
        self.host.current_integer_overflow = HashSet::new();
        self.host.current_delegatecall_injections = HashSet::new();
        self.host.current_ecrecover_zero = HashSet::new();
        self.host.current_storage_collisions = HashSet::new();
        // Found 2026-11-03 -- see init_host!'s own updated comment.
        self.host.current_uninitialized_memory_reads = HashSet::new();
        self.host.current_unchecked_call = HashSet::new();
        self.host.current_tx_origin_checks = HashSet::new();
        self.host.current_delegatecall_targets_seen = HashSet::new();
        self.host.current_loop_iterations = HashMap::new();
        self.host.current_last_sload = None;
        self.host.current_guard_reads = vec![];
        self.host.current_last_calldata_compare = None;
        self.host.current_calldata_addresses = HashSet::new();
        self.host.current_calldata_words = HashSet::new();
        self.host.current_arbitrary_storage_writes = HashSet::new();
        self.host.current_pending_token_transfer_in = None;
        self.host.current_token_accounting_mismatches = HashSet::new();
        self.host.current_last_self_balance_read = None;
        self.host.current_forced_eth_accounting_checks = HashSet::new();
        self.host.current_readonly_reentrancy_hits = HashSet::new();
        self.host.current_zero_address_setters = HashSet::new();
        self.host.current_hardcoded_gas_stipends = HashSet::new();
        self.host.current_last_env_read = None;
        self.host.current_weak_randomness_uses = HashSet::new();
        self.host.current_precision_losses = HashSet::new();
        self.host.current_last_div = None;
        self.host.current_revert_in_loop = HashSet::new();
        self.host.current_call_site_counts = HashMap::new();
        self.host.current_call_fail_counts = HashMap::new();
        self.host.current_assert_violations = HashSet::new();
        self.host.current_arg_guard_reads = vec![];
        self.host.current_paid_calldata_addresses = HashSet::new();
        self.host.current_returndata_addresses = HashSet::new();
        self.host.current_last_sha3 = None;
        self.host.current_calldata_sload_compared = HashSet::new();
        self.host.current_proof_accepted = vec![];
        self.host.current_last_proof_compare = None;
        self.host.current_transient_loaded = HashSet::new();
        self.host.current_transient_locked = HashSet::new();
        self.host.current_transient_unlock = None;
        self.host.current_transient_unlock_calls = vec![];
        self.host.call_count = 0;
        self.host.jumpi_trace = 37;
        self.host.current_typed_bug = vec![];
        self.host.randomness = vec![9];

        let res = data
            .iter()
            .map(|(address, by)| {
                let ctx = CallContext {
                    address: *address,
                    caller: Default::default(),
                    code_address: *address,
                    apparent_value: Default::default(),
                    scheme: CallScheme::StaticCall,
                };
                let code = match self.host.code.get(address) {
                    Some(code) => code.clone(),
                    None => {
                        // Oracles probe arbitrary addresses (e.g. a function
                        // argument that was never actually deployed); treat
                        // "no code loaded" the same as a failed static call
                        // instead of panicking the whole campaign.
                        return vec![];
                    }
                };
                let call = Contract::new_with_context_analyzed(by.clone(), code.clone(), &ctx);
                let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT);
                let ret = self.host.run_inspect(&mut interp, state);
                if is_call_success!(ret) {
                    interp.return_value().to_vec()
                } else {
                    vec![]
                }
            })
            .collect::<Vec<Vec<u8>>>();

        IS_FAST_CALL_STATIC.store(false, Ordering::Relaxed);
        res
    }

    /// Execute a static call
    fn fast_call(
        &mut self,
        data: &[(EVMAddress, EVMAddress, Bytes)],
        vm_state: &VS,
        state: &mut EVMFuzzState,
    ) -> (Vec<(Vec<u8>, bool)>, VS) {
        {
            // IS_FAST_CALL = true;
            self.host.evmstate = vm_state.as_any().downcast_ref::<EVMState>().unwrap().clone();
        }
        init_host!(self.host);

        // self.host.add_middlewares(middleware.clone());

        let res = data
            .iter()
            .map(|(caller, address, by)| {
                let ctx = CallContext {
                    address: *address,
                    caller: *caller,
                    code_address: *address,
                    apparent_value: Default::default(),
                    scheme: CallScheme::Call,
                };
                let res = execute_call_single!(ctx, self.host, state, address, by);
                if let Some((_, _, r)) = self.host.check_assert_result() {
                    return (r.to_vec(), false);
                }
                res
            })
            .collect::<Vec<(Vec<u8>, bool)>>();

        (res, {
            self.host.evmstate.as_any().downcast_ref::<VS>().unwrap().clone()
        })
    }

    fn get_jmp(&self) -> &'static mut [u8; MAP_SIZE] {
        unsafe { JMP_MAP.get_mut() }
    }

    fn get_read(&self) -> &'static mut [bool; MAP_SIZE] {
        unsafe { READ_MAP.get_mut() }
    }

    fn get_write(&self) -> &'static mut [u8; MAP_SIZE] {
        unsafe { WRITE_MAP.get_mut() }
    }

    fn get_cmp(&self) -> &'static mut [EVMU256; MAP_SIZE] {
        unsafe { CMP_MAP.get_mut() }
    }

    fn state_changed(&self) -> bool {
        STATE_CHANGE.load(Ordering::Relaxed)
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap, path::Path, rc::Rc};

    use bytes::Bytes;
    use libafl::prelude::StdScheduler;
    use libafl_bolts::tuples::tuple_list;
    use revm_primitives::Bytecode;
    use tracing::debug;

    use crate::{
        evm::{
            host::{FuzzHost, JMP_MAP},
            input::{ConciseEVMInput, EVMInput, EVMInputTy},
            mutator::AccessPattern,
            types::{generate_random_address, EVMFuzzState, EVMU256},
            vm::{EVMExecutor, EVMState},
        },
        generic_vm::vm_executor::{GenericVM, MAP_SIZE},
        state::FuzzState,
        state_input::StagedVMState,
    };

    #[test]
    fn test_fuzz_executor() {
        let mut state: EVMFuzzState = FuzzState::new(0);
        let path = Path::new("work_dir");
        if !path.exists() {
            std::fs::create_dir(path).unwrap();
        }
        let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> = EVMExecutor::new(
            FuzzHost::new(StdScheduler::new(), "work_dir".to_string()),
            generate_random_address(&mut state),
        );
        tuple_list!();
        let _vm_state = EVMState::new();

        /*
        contract main {
            function process(uint8 a) public {
                require(a < 2, "2");
            }
        }
        */
        let deployment_bytecode = hex::decode("608060405234801561001057600080fd5b506102ad806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806390b6e33314610030575b600080fd5b61004a60048036038101906100459190610123565b610060565b60405161005791906101e9565b60405180910390f35b606060028260ff16106100a8576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161009f90610257565b60405180910390fd5b6040518060400160405280600f81526020017f48656c6c6f20436f6e74726163747300000000000000000000000000000000008152509050919050565b600080fd5b600060ff82169050919050565b610100816100ea565b811461010b57600080fd5b50565b60008135905061011d816100f7565b92915050565b600060208284031215610139576101386100e5565b5b60006101478482850161010e565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60005b8381101561018a57808201518184015260208101905061016f565b83811115610199576000848401525b50505050565b6000601f19601f8301169050919050565b60006101bb82610150565b6101c5818561015b565b93506101d581856020860161016c565b6101de8161019f565b840191505092915050565b6000602082019050818103600083015261020381846101b0565b905092915050565b7f3200000000000000000000000000000000000000000000000000000000000000600082015250565b600061024160018361015b565b915061024c8261020b565b602082019050919050565b6000602082019050818103600083015261027081610234565b905091905056fea264697066735822122025c2570c6b62c0201c750ff809bdc45aad0eae99133699dec80912878b9cc33064736f6c634300080f0033").unwrap();

        let deployment_loc = evm_executor
            .deploy(
                Bytecode::new_raw(Bytes::from(deployment_bytecode)),
                None,
                generate_random_address(&mut state),
                &mut FuzzState::new(0),
            )
            .unwrap();

        debug!("deployed to address: {:?}", deployment_loc);

        let function_hash = hex::decode("90b6e333").unwrap();

        let input_0 = EVMInput {
            caller: generate_random_address(&mut state),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                ]
                .concat(),
            ),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
        };

        let mut state = FuzzState::new(0);

        // process(0)
        let execution_result_0 = evm_executor.execute(&input_0, &mut state);
        let mut know_map: Vec<u8> = vec![0; MAP_SIZE];

        for i in 0..MAP_SIZE {
            let jmp_map = unsafe { JMP_MAP.get_mut() };
            know_map[i] = jmp_map[i];
            jmp_map[i] = 0;
        }
        assert!(!execution_result_0.reverted);

        // process(5)

        let input_5 = EVMInput {
            caller: generate_random_address(&mut state),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap(),
                ]
                .concat(),
            ),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
        };

        let execution_result_5 = evm_executor.execute(&input_5, &mut state);

        // checking cmp map about coverage
        let mut cov_changed = false;
        for i in 0..MAP_SIZE {
            let jmp_map = unsafe { JMP_MAP.get_mut() };
            let hit = jmp_map[i];
            if hit != know_map[i] && hit != 0 {
                debug!("jmp_map[{}] = known: {}; new: {}", i, know_map[i], hit);
                jmp_map[i] = 0;
                cov_changed = true;
            }
        }
        assert!(cov_changed);
        assert!(execution_result_5.reverted);
    }

    /// A4 regression: the control-leak boundary must survive the
    /// `ExecutionResult::additional_info` round trip at full `u32` width. It
    /// used to be written as `call_count as u8` (mod 256) and read back as
    /// `info[0] as u32`, so a leak recorded after call 255/256/... collapsed
    /// to the wrong boundary -- and since that value is replayed straight back
    /// into `CALL_UNTIL`, the trace no longer re-leaked at the same call.
    #[test]
    fn control_leak_boundary_survives_full_width_round_trip() {
        use super::{decode_call_leak, encode_call_leak};
        for n in [0u32, 1, 2, 255, 256, 257, 300, 65535, 65536, u32::MAX - 1] {
            let encoded = encode_call_leak(n);
            assert_eq!(encoded.len(), 4, "the boundary must be stored at full u32 width");
            assert_eq!(
                decode_call_leak(Some(&encoded)),
                n,
                "call_leak {n} must survive the encode/decode round trip"
            );
        }
        // No leak => CALL_UNTIL's neutral default.
        assert_eq!(decode_call_leak(None), u32::MAX);
        // A legacy 1-byte buffer still decodes to its original meaning, so
        // states serialized before this fix keep working.
        assert_eq!(decode_call_leak(Some(&[5])), 5);
    }
}
