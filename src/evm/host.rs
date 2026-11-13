use core::panic;
use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    io::Write,
    ops::Deref,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc,
        RwLock,
    },
};

#[cfg(feature = "print_logs")]
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_sol_types::SolValue;
use bytes::Bytes;
use itertools::Itertools;
use lazy_static::lazy_static;
use libafl::prelude::{HasMetadata, Scheduler};
use revm::precompile::{Precompile, Precompiles};
use revm_interpreter::{
    analysis::to_analysed,
    BytecodeLocked,
    CallContext,
    CallInputs,
    CallScheme,
    Contract,
    CreateInputs,
    Gas,
    Host,
    InstructionResult,
    InstructionResult::{Continue, ControlLeak, Revert},
    Interpreter,
    SelfDestructResult,
};
use revm_primitives::{
    keccak256,
    BerlinSpec,
    Bytecode,
    ByzantiumSpec,
    CancunSpec,
    Env,
    FrontierSpec,
    HomesteadSpec,
    IstanbulSpec,
    LatestSpec,
    LondonSpec,
    MergeSpec,
    PetersburgSpec,
    ShanghaiSpec,
    SpecId,
    SpuriousDragonSpec,
    TangerineSpec,
    B256,
};
use tracing::debug;

use super::{
    // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved
    // middlewares::cheatcode::{
    //     ExpectedCallData,
    //     ExpectedCallTracker,
    //     ExpectedCallType,
    //     ExpectedEmit,
    //     ExpectedRevert,
    //     Prank,
    //     ERROR_PREFIX,
    //     REVERT_PREFIX,
    // },
    types::EVMFuzzState,
    vm::{IS_FAST_CALL, MEM_LIMIT, SETCODE_ONLY},
};
use crate::{
    evm::{
        abi::{get_abi_type_boxed, register_abi_instance},
        contract_utils::extract_sig_from_contract,
        corpus_initializer::ABIMap,
        input::{EVMInput, EVMInputTy},
        middlewares::middleware::{add_corpus, CallMiddlewareReturn, Middleware, MiddlewareType},
        mutator::AccessPattern,
        onchain::{
            abi_decompiler::fetch_abi_evmole,
            flashloan::{register_borrow_txn, Flashloan},
        },
        types::{as_u64, checksum, convert_u256_to_h160, generate_random_address, is_zero, EVMAddress, EVMU256},
        vm::{is_reverted_or_control_leak, EVMState, SinglePostExecution, IN_DEPLOY, IS_FAST_CALL_STATIC},
    },
    generic_vm::vm_executor::MAP_SIZE,
    handle_contract_insertion,
    invoke_middlewares,
    state::{HasCaller, HasHashToAddress},
    state_input::StagedVMState,
    sync_utils::RacyCell,
};

pub static JMP_MAP: RacyCell<[u8; MAP_SIZE]> = RacyCell::new([0; MAP_SIZE]);

// dataflow
pub static READ_MAP: RacyCell<[bool; MAP_SIZE]> = RacyCell::new([false; MAP_SIZE]);
pub static WRITE_MAP: RacyCell<[u8; MAP_SIZE]> = RacyCell::new([0; MAP_SIZE]);

// cmp
pub static CMP_MAP: RacyCell<[EVMU256; MAP_SIZE]> = RacyCell::new([EVMU256::MAX; MAP_SIZE]);

pub static ABI_MAX_SIZE: RacyCell<[usize; MAP_SIZE]> = RacyCell::new([0; MAP_SIZE]);
pub static STATE_CHANGE: AtomicBool = AtomicBool::new(false);

pub const RW_SKIPPER_PERCT_IDX: usize = 100;
pub const RW_SKIPPER_AMT: usize = MAP_SIZE - RW_SKIPPER_PERCT_IDX;

// How mant iterations the coverage is the same
pub static COVERAGE_NOT_CHANGED: AtomicU32 = AtomicU32::new(0);
pub static RET_SIZE: AtomicUsize = AtomicUsize::new(0);
pub static RET_OFFSET: AtomicUsize = AtomicUsize::new(0);

pub static PANIC_ON_BUG: AtomicBool = AtomicBool::new(false);
// for debugging purpose, return ControlLeak when the calls amount exceeds this
// value
pub static CALL_UNTIL: AtomicU32 = AtomicU32::new(u32::MAX);

/// RAII guard for the process-global [`CALL_UNTIL`].
///
/// The count-based control leak is a REPLAY-time mechanism: `cov_stage` and
/// `minimizer` set `CALL_UNTIL` to a recorded `call_leak` boundary so a found
/// trace re-leaks at the exact same call. The normal fuzzing loop, by
/// contrast, must run with the neutral `u32::MAX` -- leaks there come from
/// the address/caller-based paths, never from the count.
///
/// That value is process-global and was left set after every replay, so a
/// campaign that had replayed a leak-dependent trace fuzzed with a stale,
/// tiny `CALL_UNTIL` for the rest of the run (a leak after 2 calls is a very
/// different search from no count-based leak at all). Holding this guard for
/// the duration of a replay restores the previous value -- `u32::MAX` when
/// the replay began from the neutral state -- even if the replay panics.
pub struct CallUntilGuard {
    previous: u32,
}

impl CallUntilGuard {
    /// Set `CALL_UNTIL` to `value` and restore the prior value on drop.
    pub fn set(value: u32) -> Self {
        let previous = CALL_UNTIL.swap(value, Ordering::Relaxed);
        Self { previous }
    }

    /// Capture the current value and restore it on drop without changing it.
    /// Use this to make a self-contained replay (which mutates `CALL_UNTIL`
    /// per step) leave the process-global value exactly as it found it.
    pub fn preserve() -> Self {
        Self {
            previous: CALL_UNTIL.load(Ordering::Relaxed),
        }
    }
}

impl Drop for CallUntilGuard {
    fn drop(&mut self) {
        CALL_UNTIL.store(self.previous, Ordering::Relaxed);
    }
}

/// FAZA 2.4: while set, the call dispatch below NEVER takes the control-leak
/// path (`call_allow_control_leak`) -- every call runs the real callee code
/// via `call_forbid_control_leak`, exactly as an on-chain transaction would.
/// The concolic stage raises this for the duration of its execution so that
/// no concolic-discovered trace can rest on a faked/intercepted call return
/// (a state the chain cannot produce). The normal fuzzing loop leaves it
/// unset, so the (deliberate) leak-based exploration is unchanged there.
pub static CONCOLIC_NO_CONTROL_LEAK: AtomicBool = AtomicBool::new(false);

/// Whether the current call must bypass the control-leak path. True when the
/// caller is a "fast call" (never leak) or while the concolic stage has
/// raised `CONCOLIC_NO_CONTROL_LEAK` (FAZA 2.4). Split out so the bypass
/// condition is unit-testable without constructing a full `FuzzHost`.
#[inline]
pub fn control_leak_bypassed() -> bool {
    IS_FAST_CALL_STATIC.load(Ordering::Relaxed) ||
        IS_FAST_CALL.load(Ordering::Relaxed) ||
        CONCOLIC_NO_CONTROL_LEAK.load(Ordering::Relaxed)
}

/// Shall we dump the contract calls
pub static WRITE_RELATIONSHIPS: AtomicBool = AtomicBool::new(false);

/// How deep into a call chain the sha3-bypass taint analysis
/// (`middlewares/sha3_bypass.rs`) and concolic/symbolic Z3 solving
/// (`concolic/concolic_host.rs`) keep analyzing, instead of skipping.
/// Was a hardcoded `const MAX_CALL_DEPTH: _ = 3` in each of those two
/// files independently -- deep call chains (nested proxies, multi-level
/// reentrancy, flashloan callback chains) routinely exceed that, silently
/// losing taint/symbolic coverage past depth 3 with no way to raise it.
/// Set once at startup from `--max-call-depth` (see `EvmArgs`), default
/// 10. Higher values cost more (Z3 solving in particular gets
/// expensive the deeper symbolic state is tracked), so this is a
/// tradeoff knob, not a correctness requirement in either direction.
pub static MAX_ANALYSIS_CALL_DEPTH: AtomicU64 = AtomicU64::new(15);

/// Branch status of the current execution
pub static BRANCH_STATUS: RacyCell<[Option<(EVMAddress, usize, bool)>; MAP_SIZE]> = RacyCell::new([None; MAP_SIZE]);
pub static BRANCH_STATUS_IDX: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    /// Every checksummed address the SLOAD-harvest below has ever pulled out
    /// of the TARGET's storage and added to the caller/address pools. These
    /// are identities the fuzzer could only "become" by reading them out of
    /// the contract's own state -- overwhelmingly `owner`/admin/multisig
    /// slots -- as opposed to a real attacker-supplied address.
    ///
    /// A finding whose only caller is in this set is almost always the
    /// fuzzer exercising an owner-gated function AS the legitimate owner
    /// (e.g. calling `escapeHatch()` with `msg.sender == owner`), which is
    /// not an exploit at all: it is the privileged party using their own
    /// privilege. Live on ETC target 0x9f5304...: 1201 plans, ALL skipped,
    /// because the "Fund Loss" findings were exactly this -- `escapeHatch()`
    /// called by the target's own owner multisig, harvested from slot 0.
    /// Recording the harvested set here (not re-deriving it from storage
    /// later) is what lets `solution`'s plan metadata flag such findings
    /// honestly, so the Python layer can label them instead of presenting
    /// 2000+ un-runnable "plans" as if they were exploits.
    pub static ref HARVESTED_STORAGE_ADDRESSES: RwLock<HashSet<String>> = RwLock::new(HashSet::new());

    /// Provenance of every harvested address: checksummed address ->
    /// `(checksummed contract it was read from, storage slot key as hex)`.
    /// `owner_impersonation` was a bare boolean; the report should say WHO
    /// was impersonated, out of WHICH slot, on WHICH contract. The
    /// (contract, slot) is recorded at the SLOAD site, where both are in
    /// hand; `HARVESTED_STORAGE_ADDRESSES` alone cannot answer "from where",
    /// and re-deriving it later would need the exact state the finding ran
    /// on, which is gone by report time.
    pub static ref HARVESTED_ADDRESS_ORIGINS: RwLock<HashMap<String, (String, String)>> =
        RwLock::new(HashMap::new());

    /// `"<checksummed contract>|<checksummed address>"` for every address the
    /// SLOAD-harvest pulled out of THAT contract's own storage. This is the
    /// semantic owner-gated signal (FAZA 3.2 of PROMPT_RESEN_SISTEM.md):
    /// `HARVESTED_STORAGE_ADDRESSES` says an address came from SOME target's
    /// storage, but the exploit shape `require(msg.sender == owner)` is only
    /// proven when the address was read from the SAME contract that the trace
    /// then calls AS that address. Pairing them turns the broad "this caller
    /// was harvested somewhere" heuristic into "this caller is a privileged
    /// identity OF THIS CONTRACT", which is what actually distinguishes
    /// impersonating a stored owner from reading an unrelated address.
    pub static ref HARVESTED_SENDER_GUARDS: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
}

/// Record an address harvested out of target storage as a caller/address
/// pool entry, together with the `(contract, slot)` it was read from.
/// Called from the SLOAD harvest site; see `HARVESTED_STORAGE_ADDRESSES`
/// for why this is tracked at all.
pub fn record_harvested_storage_address(addr: &EVMAddress, contract: &EVMAddress, slot: EVMU256) {
    let addr = checksum(addr);
    let contract = checksum(contract);
    if let Ok(mut set) = HARVESTED_STORAGE_ADDRESSES.write() {
        set.insert(addr.clone());
    }
    if let Ok(mut guards) = HARVESTED_SENDER_GUARDS.write() {
        // The semantic owner-gated pairing: this identity was read from THIS
        // contract's own storage. See HARVESTED_SENDER_GUARDS's doc.
        guards.insert(sender_guard_key(&contract, &addr));
    }
    if let Ok(mut origins) = HARVESTED_ADDRESS_ORIGINS.write() {
        // First writer wins: the first SLOAD that exposed the identity is
        // the most specific provenance, and later reads (the same owner
        // slot read again on every transaction) would only add noise.
        origins.entry(addr).or_insert_with(|| (contract, format!("0x{:064x}", slot)));
    }
}

/// Key for `HARVESTED_SENDER_GUARDS`. Kept as one helper so the writer
/// (above) and the reader (`is_harvested_sender_for`) can never disagree on
/// the format.
fn sender_guard_key(checksummed_contract: &str, checksummed_addr: &str) -> String {
    format!("{}|{}", checksummed_contract, checksummed_addr)
}

/// Whether `checksummed_addr` is a privileged identity OF
/// `checksummed_contract` -- i.e. it was harvested from THAT contract's own
/// storage. This is the semantic owner-gated test (FAZA 3.2): the trace
/// calls the contract AS an identity the contract itself stored, which is
/// exactly `require(msg.sender == owner)` satisfied by impersonation.
/// Distinct from `is_harvested_storage_address`, which is true for an
/// address harvested from ANY target.
pub fn is_harvested_sender_for(checksummed_contract: &str, checksummed_addr: &str) -> bool {
    HARVESTED_SENDER_GUARDS
        .read()
        .map(|set| set.contains(&sender_guard_key(checksummed_contract, checksummed_addr)))
        .unwrap_or(false)
}

/// Whether `checksummed` (a plan caller string, already checksummed by
/// `types::checksum`) was harvested from target storage. Used by
/// `solution::build_plan_meta` to set `owner_impersonation`.
pub fn is_harvested_storage_address(checksummed: &str) -> bool {
    HARVESTED_STORAGE_ADDRESSES
        .read()
        .map(|set| set.contains(checksummed))
        .unwrap_or(false)
}

/// The `(contract, slot)` an address was harvested from, when known. Used
/// by `solution::build_plan_meta` to fill the structured
/// `owner_impersonation` record.
pub fn harvested_address_origin(checksummed: &str) -> Option<(String, String)> {
    HARVESTED_ADDRESS_ORIGINS.read().ok()?.get(checksummed).cloned()
}

pub fn clear_branch_status() {
    unsafe {
        for i in BRANCH_STATUS.get_mut().iter_mut().take(BRANCH_STATUS_IDX.load(Ordering::Relaxed) + 1) {
            *i = None;
        }
    }

    BRANCH_STATUS_IDX.store(0, Ordering::Relaxed);
}

pub fn add_branch(branch: (EVMAddress, usize, bool)) {
    let idx = BRANCH_STATUS_IDX.load(Ordering::Relaxed);
    if idx >= MAP_SIZE {
        return;
    }
    unsafe {
        BRANCH_STATUS.get_mut()[idx] = Some(branch);
    }
    BRANCH_STATUS_IDX.store(idx + 1, Ordering::Relaxed);
}

const SCRIBBLE_EVENT_HEX: [u8; 32] = [
    0xb4, 0x26, 0x04, 0xcb, 0x10, 0x5a, 0x16, 0xc8, 0xf6, 0xdb, 0x8a, 0x41, 0xe6, 0xb0, 0x0c, 0x0c, 0x1b, 0x48, 0x26,
    0x46, 0x5e, 0x8b, 0xc5, 0x04, 0xb3, 0xeb, 0x3e, 0x88, 0xb3, 0xe6, 0xa4, 0xa0,
];

/// Check if address is precompile by having assumption
/// that precompiles are in range of 1 to N.
#[inline(always)]
pub fn is_precompile(address: EVMAddress, num_of_precompiles: usize) -> bool {
    if !address[..18].iter().all(|i| *i == 0) {
        return false;
    }
    let num = u16::from_be_bytes([address[18], address[19]]);
    num.wrapping_sub(1) < num_of_precompiles as u16
}

#[allow(clippy::type_complexity)]
pub struct FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub evmstate: EVMState,
    /// [EIP-1153[(https://eips.ethereum.org/EIPS/eip-1153) transient storage that is discarded after every transactions
    pub transient_storage: HashMap<(EVMAddress, EVMU256), EVMU256>,
    // these are internal to the host
    pub env: Env,
    pub code: HashMap<EVMAddress, Arc<BytecodeLocked>>,
    pub hash_to_address: HashMap<[u8; 4], HashSet<EVMAddress>>,
    pub address_to_hash: HashMap<EVMAddress, Vec<[u8; 4]>>,
    pub _pc: usize,
    pub pc_to_addresses: HashMap<(EVMAddress, usize), HashSet<EVMAddress>>,
    pub pc_to_create: HashMap<(EVMAddress, usize), usize>,
    pub pc_to_call_hash: HashMap<(EVMAddress, usize, usize), HashSet<Vec<u8>>>,
    // distinct DELEGATECALL targets observed at each (caller, pc) callsite
    // across the whole campaign -- used to flag an attacker-controlled
    // delegatecall target (see middlewares/delegatecall.rs)
    pub pc_to_delegatecall_targets: HashMap<(EVMAddress, usize), HashSet<EVMAddress>>,
    pub middlewares_enabled: bool,
    // If you use RefCell, modifying middlewares during execution will cause a panic
    // because the executor borrows middlewares over its entire lifetime.
    pub middlewares: RwLock<Vec<Rc<RefCell<dyn Middleware<SC>>>>>,

    pub coverage_changed: bool,

    pub flashloan_middleware: Option<Rc<RefCell<Flashloan>>>,

    pub middlewares_latent_call_actions: Vec<CallMiddlewareReturn>,

    pub scheduler: SC,

    // controlled by onchain module, if sload cant find the slot, use this value
    pub next_slot: EVMU256,

    pub access_pattern: Rc<RefCell<AccessPattern>>,

    pub bug_hit: bool,
    pub current_typed_bug: Vec<(String, (EVMAddress, usize))>,
    pub call_count: u32,

    #[cfg(feature = "print_logs")]
    pub logs: HashSet<u64>,
    // set_code data
    pub setcode_data: HashMap<EVMAddress, Bytecode>,
    // selftdestruct
    pub current_self_destructs: Vec<(EVMAddress, usize)>,
    // arbitrary calls
    pub current_arbitrary_calls: Vec<(EVMAddress, EVMAddress, usize)>,
    // integer_overflow
    pub current_integer_overflow: HashSet<(EVMAddress, usize, &'static str)>,
    // delegatecall injection (threshold crossed in pc_to_delegatecall_targets)
    pub current_delegatecall_injections: HashSet<(EVMAddress, usize)>,
    // ecrecover() returned the zero address (invalid signature) and the
    // caller's tx still succeeded (see middlewares/ecrecover.rs)
    pub current_ecrecover_zero: HashSet<(EVMAddress, usize)>,
    // persistent (never reset): per-(address,slot) record of whether it has
    // been written natively vs. from inside a DELEGATECALL frame (see
    // middlewares/storage_collision.rs)
    pub slot_write_contexts: HashMap<(EVMAddress, EVMU256), (bool, bool)>,
    // transient: slots where both native and delegated writes have now been observed
    pub current_storage_collisions: HashSet<(EVMAddress, EVMU256)>,
    // transient: (caller, pc, target) for every DELEGATECALL observed this tx
    // (see middlewares/delegatecall_target.rs)
    pub current_delegatecall_targets_seen: HashSet<(EVMAddress, usize, EVMAddress)>,
    // transient: (address, pc) of every MLOAD reading a memory word that was
    // never written in the current call frame (see middlewares/uninitialized_memory.rs)
    pub current_uninitialized_memory_reads: HashSet<(EVMAddress, usize)>,
    // transient: the CallScheme (CALL/CALLCODE/DELEGATECALL/STATICCALL) and
    // success of the call that is about to trigger middlewares' `on_return`
    // -- `on_return` itself is only given the return bytes, not the call
    // kind or whether it reverted, so `call()` stashes both here right
    // before invoking it (see middlewares/unchecked_call.rs)
    pub last_call_scheme: CallScheme,
    pub last_call_success: bool,
    // transient: (address, pc) of every plain CALL/CALLCODE whose return
    // value was both (a) failure and (b) immediately discarded by the
    // caller without any check (see middlewares/unchecked_call.rs)
    pub current_unchecked_call: HashSet<(EVMAddress, usize)>,
    // transient: (address, pc) of every ORIGIN read while msg.sender !=
    // tx.origin (see middlewares/tx_origin.rs)
    pub current_tx_origin_checks: HashSet<(EVMAddress, usize)>,
    // transient, reset once per call: for each (address, loop JUMPDEST pc)
    // backward-jumped-to in THIS call, how many times it was hit. See
    // oracles/unbounded_loop.rs for why this -- not a HashSet like the
    // other `current_*` trackers above -- needs an actual count, and why
    // it's reset per call instead of accumulated forever.
    pub current_loop_iterations: HashMap<(EVMAddress, usize), u64>,
    // transient scratch, reset once per call: (pc, slot, value) of the
    // MOST RECENT SLOAD, consulted by JUMPI (see the 0x57 case below) to
    // cheaply link a storage read to a guard check a few bytes later --
    // no real dataflow tracing, just proximity (see oracles/stale_guard.rs).
    pub current_last_sload: Option<(usize, EVMU256, EVMU256)>,
    // transient, reset once per call: (address, jumpi pc, slot, value) for
    // every JUMPI this call whose condition looks SLOAD-derived (see
    // current_last_sload above and oracles/stale_guard.rs).
    pub current_guard_reads: Vec<(EVMAddress, usize, EVMU256, EVMU256)>,
    // transient, reset once per call: every address-shaped value loaded via
    // CALLDATALOAD this call (i.e. address-type function arguments),
    // consulted by `call()` below to catch a payment TO one of them, and
    // by the comparison opcodes (0x10-0x14) below to catch a GUARD CHECK
    // on one of them.
    pub current_calldata_addresses: HashSet<EVMAddress>,
    // transient, reset once per call: EVERY raw 32-byte word loaded via
    // CALLDATALOAD this call, unfiltered (unlike current_calldata_addresses
    // above, which only keeps address-shaped ones) -- consulted by SSTORE
    // (see middlewares/arbitrary_storage_write.rs) to catch a storage slot
    // index that came straight from calldata, undisturbed by any KECCAK256
    // mapping/array-slot derivation (the normal, safe `mapping[key] = v`
    // compiles to `sstore(keccak256(key . base_slot), v)`, which this does
    // NOT flag -- only a slot value that matches a calldata word VERBATIM,
    // the shape of a raw, deliberately low-level `assembly { sstore(slot,
    // value) }` with an attacker-supplied slot, e.g. the 2017 Parity
    // multisig library pattern).
    pub current_calldata_words: HashSet<EVMU256>,
    // transient scratch, reset once per call: (token, amount) latched by
    // call() right after a successful transferFrom(from, address(this),
    // amount) -- consumed (and cleared) by the 0x55 SSTORE case, see
    // oracles/token_accounting_mismatch.rs.
    pub current_pending_token_transfer_in: Option<(EVMAddress, EVMU256)>,
    // transient scratch, reset once per call: the value most recently
    // read via BALANCE(address(this)) or SELFBALANCE -- consumed by the
    // very next EQ (0x14) comparison that uses it as an operand (see
    // that case below and oracles/forced_eth_accounting.rs). SWC-132: an
    // EXACT equality against the contract's own real ETH balance can be
    // permanently broken by force-feeding it 1 extra wei via SELFDESTRUCT
    // (no legitimate transaction can ever remove unwanted ETH again).
    pub current_last_self_balance_read: Option<EVMU256>,
    // PERSISTENT -- never reset (same convention as slot_write_contexts
    // above, see middlewares/storage_collision.rs's own precedent for
    // this exact pattern): (target, selector) -> return bytes observed
    // for a call made while NO control-leak was pending
    // (evmstate.post_execution.len() == 0) -- the "stable" baseline
    // value for a view-shaped call, consulted by call() itself when the
    // SAME (target, selector) is called again WHILE a control-leak IS
    // pending (see oracles/readonly_reentrancy.rs). Found live
    // 2026-11-03: this CANNOT be a per-call "current_*" scratch field
    // like the others nearby -- the per-call reset sites in vm.rs also
    // fire when RESUMING a control-leak continuation (the `cleanup`
    // flag there isn't scoped to "genuinely new top-level transaction
    // only"), which wiped the baseline before the reentrant call that
    // needs to compare against it ever ran. Confirmed via temporary
    // debug instrumentation: the depth>0 lookup always found
    // baseline_present=false until this field was made persistent.
    pub view_call_baseline: HashMap<(EVMAddress, [u8; 4]), Vec<u8>>,
    // transient, reset once per call: (caller, pc) of every call that
    // re-queried a (target, selector) already baselined above and got a
    // DIFFERENT return value while a control-leak was pending -- the
    // read-only reentrancy shape (Curve Jan 2023 and others): a view
    // function returns inconsistent, mid-transaction state to whichever
    // contract queries it during the reentrant window.
    pub current_readonly_reentrancy_hits: HashSet<(EVMAddress, usize)>,
    // transient, reset once per call: (address, pc) of every EQ (0x14)
    // comparison that used current_last_self_balance_read as an operand
    // (see oracles/forced_eth_accounting.rs).
    pub current_forced_eth_accounting_checks: HashSet<(EVMAddress, usize)>,
    // transient, reset once per call: (address, pc) of every SSTORE whose
    // new value is exactly (prior SLOAD'd value + an unverified
    // transferFrom amount) -- see current_pending_token_transfer_in above.
    pub current_token_accounting_mismatches: HashSet<(EVMAddress, usize)>,
    // transient, reset once per call: (address, pc, slot) for every SSTORE
    // this call whose slot argument matched a value in
    // current_calldata_words above (see middlewares/arbitrary_storage_write.rs).
    pub current_arbitrary_storage_writes: HashSet<(EVMAddress, usize, EVMU256)>,
    // transient, reset once per call: (address, pc, slot) for every SSTORE
    // this call that overwrote a nonzero, address-shaped slot value with
    // EXACTLY zero, at a pc not (yet) known to write a mapping/array slot
    // -- the missing `require(newAddr != address(0))` pattern on a direct
    // state-variable setter (owner/admin/implementation), see
    // oracles/zero_address_setter.rs.
    pub current_zero_address_setters: HashSet<(EVMAddress, usize, EVMU256)>,
    // transient, reset once per call: (address, pc, gas_limit) for every
    // outgoing CALL this call was made with a hardcoded, low gas stipend
    // (the 2300-gas `.transfer()`/`.send()` shape, SWC-134) -- see
    // oracles/gas_stipend.rs.
    pub current_hardcoded_gas_stipends: HashSet<(EVMAddress, usize, u64)>,
    // transient scratch, reset once per call: (pc, value) of the most
    // recent block-environment read (TIMESTAMP/NUMBER/PREVRANDAO/BASEFEE/
    // COINBASE/GASLIMIT) -- consumed by the next MOD/AND/comparison that
    // uses it as an operand, see oracles/weak_randomness.rs.
    pub current_last_env_read: Option<(usize, EVMU256)>,
    // transient, reset once per call: (address, pc) of every MOD/AND/
    // comparison whose operand was a block-environment read (weak
    // randomness, SWC-120) -- see oracles/weak_randomness.rs.
    pub current_weak_randomness_uses: HashSet<(EVMAddress, usize)>,
    // transient, reset once per call: (address, pc) of every DIV whose
    // result was immediately multiplied again (a/b)*c, the classic
    // precision-loss ordering -- see oracles/precision_loss.rs.
    pub current_precision_losses: HashSet<(EVMAddress, usize)>,
    // transient scratch, reset once per call: (pc, result) of the most
    // recent DIV -- see oracles/precision_loss.rs.
    pub current_last_div: Option<(usize, EVMU256)>,
    // transient, reset once per call: (address, pc) of every outgoing CALL
    // that FAILED while a backward-jump loop was active in the same call
    // -- the push-payment DoS shape (SWC-113), see
    // oracles/revert_in_loop.rs.
    pub current_revert_in_loop: HashSet<(EVMAddress, usize)>,
    // transient, reset once per call: how many times each (address, pc)
    // outgoing CALL was executed in this call. A failing call executed
    // 2+ times is direct, unambiguous evidence the call sits inside a
    // loop -- no fragile pc-range inference needed (solc emits a single
    // backward JUMP as the return edge of every internal helper, so a
    // range check alone misattributes a failed call in a helper as
    // "in a loop"). See oracles/revert_in_loop.rs.
    pub current_call_site_counts: HashMap<(EVMAddress, usize), u64>,
    // transient, reset once per call: (address, pc) outgoing CALL sites
    // that FAILED at least once in this call. Intersected with
    // current_call_site_counts (a site executed 2+ times) to identify a
    // failing call inside a loop -- see oracles/revert_in_loop.rs.
    pub current_failed_call_sites: HashSet<(EVMAddress, usize)>,
    // transient, reset once per call: how many times each (address, pc)
    // outgoing CALL site FAILED in this call. Combined with
    // current_call_site_counts (executions >= 2) to identify a failing
    // call inside a loop even when the failing run is not the last one
    // (e.g. the reverting recipient is first and a later one succeeds).
    pub current_call_fail_counts: HashMap<(EVMAddress, usize), u64>,
    // transient, reset once per call: (address, pc) of every INVALID
    // (0xfe) opcode reached with a non-empty calldata present -- a
    // reachable `assert()` on attacker input rather than an internal
    // invariant (SWC-110), see oracles/assert_violation.rs.
    pub current_assert_violations: HashSet<(EVMAddress, usize)>,
    // transient scratch, reset once per call: the address-shaped calldata
    // argument most recently seen as an OPERAND of a comparison opcode
    // (LT/GT/SLT/SGT/EQ). Consumed by the VERY NEXT JUMPI (see the 0x57
    // case below) -- comparisons are always chronologically adjacent to
    // the branch they feed (at most an ISZERO/PUSH in between, neither of
    // which touches this field), so no pc-distance heuristic is needed
    // here the way current_last_sload needs one for stale_guard.rs: this
    // one tried proximity-by-pc first and it broke on real solc output,
    // which decodes ALL calldata arguments up front (far from where
    // they're actually compared) -- adjacency in EXECUTION order, not
    // byte distance, is what actually holds.
    pub current_last_calldata_compare: Option<EVMAddress>,
    // transient scratch, reset once per call: (address, eq pc, calldata
    // root word) latched by an EQ comparing a freshly computed SHA3 result
    // against a caller-supplied calldata word, consumed by the VERY NEXT
    // JUMPI (see oracles/forged_proof.rs).
    pub current_last_proof_compare: Option<(EVMAddress, usize, EVMU256)>,
    // transient, reset once per call: (address, jumpi pc, arg address,
    // branch taken) for every JUMPI this call whose condition looks
    // derived from a comparison against an address-type calldata argument
    // (see current_last_calldata_compare above and oracles/self_referral.rs).
    pub current_arg_guard_reads: Vec<(EVMAddress, usize, EVMAddress, bool)>,
    // transient, reset once per call: address-shaped calldata arguments
    // that ALSO received value > 0 via an outgoing CALL this same call
    // (see `call()` below and oracles/self_referral.rs).
    pub current_paid_calldata_addresses: HashSet<EVMAddress>,
    // transient, reset once per call: every address-shaped 32-byte word
    // copied via RETURNDATACOPY this call (i.e. a prior call's return
    // value this call read back) -- see the 0x3e case below and
    // oracles/delegatecall_target.rs's cross-contract value-flow check.
    pub current_returndata_addresses: HashSet<EVMAddress>,
    // transient, reset once per call: the MOST RECENT SHA3 result computed
    // this call -- consulted by EQ (0x14) to recognize a hash being
    // compared against a caller-supplied value, i.e. a proof verified
    // against an attacker-chosen root instead of the contract's own
    // authoritative one (see oracles/forged_proof.rs).
    pub current_last_sha3: Option<EVMU256>,
    // transient, reset once per call: every calldata word that was ever
    // compared (EQ, 0x14) against a value read from storage this call --
    // i.e. a caller-supplied value that WAS checked against authoritative
    // on-chain state. A calldata word absent from this set was only ever
    // compared against a locally recomputed hash (see
    // oracles/forged_proof.rs).
    pub current_calldata_sload_compared: HashSet<EVMU256>,
    // transient, reset once per call: (address, eq pc, root word) for every
    // JUMPI this call that ACCEPTED (jumped) a condition comparing a
    // freshly-computed SHA3 result against a caller-supplied calldata
    // word -- the forged-proof shape, see oracles/forged_proof.rs.
    pub current_proof_accepted: Vec<(EVMAddress, usize, EVMU256)>,
    // transient, reset once per call: every EIP-1153 transient-storage slot
    // TLOAD'd this call. Transient storage is almost exclusively used for
    // reentrancy guards/locks, so a TLOAD marks a candidate guard slot (see
    // oracles/transient_guard.rs).
    pub current_transient_loaded: HashSet<(EVMAddress, EVMU256)>,
    // transient, reset once per call: transient slots written NONZERO via
    // TSTORE this call (i.e. actually locked).
    pub current_transient_locked: HashSet<(EVMAddress, EVMU256)>,
    // transient scratch, reset once per call: (address, tstore pc, slot) of
    // the most recent TSTORE of ZERO to a slot that was locked this call --
    // cleared the instant that slot is re-locked. A CALL observed while this
    // is set is an unlock-before-external-call (see
    // oracles/transient_guard.rs).
    pub current_transient_unlock: Option<(EVMAddress, usize, EVMU256)>,
    // transient, reset once per call: (address, call pc, slot) for every
    // external CALL executed while a transient guard slot was unlocked (see
    // oracles/transient_guard.rs).
    pub current_transient_unlock_calls: Vec<(EVMAddress, usize, EVMU256)>,
    // relations file handle
    relations_file: std::fs::File,
    // Filter duplicate relations
    relations_hash: HashSet<u64>,
    /// Randomness from inputs
    pub randomness: Vec<u8>,
    /// workdir
    pub work_dir: String,
    /// custom SpecId
    pub spec_id: SpecId,
    /// Precompiles
    pub precompiles: Precompiles,

    /// All SSTORE PCs that are for mapping (i.e., writing to multiple storage
    /// slots)
    pub mapping_sstore_pcs: HashSet<(EVMAddress, usize)>,
    pub mapping_sstore_pcs_to_slot: HashMap<(EVMAddress, usize), HashSet<EVMU256>>,

    /// For future continue executing when control leak happens
    pub leak_ctx: Vec<SinglePostExecution>,

    pub jumpi_trace: usize,

    /// Depth of call stack
    pub call_depth: u64,
    // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved
    // /// Prank information
    // pub prank: Option<Prank>,
    // /// Expected revert information
    // pub expected_revert: Option<ExpectedRevert>,
    // /// Expected emits
    // pub expected_emits: VecDeque<ExpectedEmit>,
    // /// Expected calls
    // pub expected_calls: ExpectedCallTracker,
    /// Assert failed message for the cheatcode
    pub assert_msg: Option<String>,
}

impl<SC> Debug for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzHost")
            .field("data", &self.evmstate)
            .field("env", &self.env)
            .field("hash_to_address", &self.hash_to_address)
            .field("address_to_hash", &self.address_to_hash)
            .field("_pc", &self._pc)
            .field("pc_to_addresses", &self.pc_to_addresses)
            .field("pc_to_call_hash", &self.pc_to_call_hash)
            .field("pc_to_delegatecall_targets", &self.pc_to_delegatecall_targets)
            .field("middlewares_enabled", &self.middlewares_enabled)
            .field("middlewares", &self.middlewares)
            .field("middlewares_latent_call_actions", &self.middlewares_latent_call_actions)
            .finish()
    }
}

// all clones would not include middlewares and states
impl<SC> Clone for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            evmstate: self.evmstate.clone(),
            transient_storage: self.transient_storage.clone(),
            env: self.env.clone(),
            code: self.code.clone(),
            hash_to_address: self.hash_to_address.clone(),
            address_to_hash: self.address_to_hash.clone(),
            _pc: self._pc,
            pc_to_addresses: self.pc_to_addresses.clone(),
            pc_to_create: self.pc_to_create.clone(),
            pc_to_call_hash: self.pc_to_call_hash.clone(),
            pc_to_delegatecall_targets: self.pc_to_delegatecall_targets.clone(),
            middlewares_enabled: false,
            middlewares: RwLock::new(Default::default()),
            coverage_changed: false,
            flashloan_middleware: self.flashloan_middleware.clone(),
            middlewares_latent_call_actions: vec![],
            scheduler: self.scheduler.clone(),
            next_slot: Default::default(),
            access_pattern: self.access_pattern.clone(),
            bug_hit: false,
            call_count: 0,
            #[cfg(feature = "print_logs")]
            logs: Default::default(),
            setcode_data: self.setcode_data.clone(),
            current_self_destructs: self.current_self_destructs.clone(),
            current_arbitrary_calls: self.current_arbitrary_calls.clone(),
            current_integer_overflow: self.current_integer_overflow.clone(),
            current_delegatecall_injections: self.current_delegatecall_injections.clone(),
            current_ecrecover_zero: self.current_ecrecover_zero.clone(),
            slot_write_contexts: self.slot_write_contexts.clone(),
            current_storage_collisions: self.current_storage_collisions.clone(),
            current_delegatecall_targets_seen: self.current_delegatecall_targets_seen.clone(),
            current_uninitialized_memory_reads: self.current_uninitialized_memory_reads.clone(),
            last_call_scheme: self.last_call_scheme,
            last_call_success: self.last_call_success,
            current_unchecked_call: self.current_unchecked_call.clone(),
            current_tx_origin_checks: self.current_tx_origin_checks.clone(),
            current_loop_iterations: self.current_loop_iterations.clone(),
            current_last_sload: self.current_last_sload,
            current_guard_reads: self.current_guard_reads.clone(),
            current_last_calldata_compare: self.current_last_calldata_compare,
            current_last_proof_compare: self.current_last_proof_compare,
            current_calldata_addresses: self.current_calldata_addresses.clone(),
            current_calldata_words: self.current_calldata_words.clone(),
            current_pending_token_transfer_in: self.current_pending_token_transfer_in.clone(),
            current_last_self_balance_read: self.current_last_self_balance_read,
            view_call_baseline: self.view_call_baseline.clone(),
            current_readonly_reentrancy_hits: self.current_readonly_reentrancy_hits.clone(),
            current_forced_eth_accounting_checks: self.current_forced_eth_accounting_checks.clone(),
            current_token_accounting_mismatches: self.current_token_accounting_mismatches.clone(),
            current_arbitrary_storage_writes: self.current_arbitrary_storage_writes.clone(),
            current_zero_address_setters: self.current_zero_address_setters.clone(),
            current_hardcoded_gas_stipends: self.current_hardcoded_gas_stipends.clone(),
            current_last_env_read: self.current_last_env_read,
            current_weak_randomness_uses: self.current_weak_randomness_uses.clone(),
            current_precision_losses: self.current_precision_losses.clone(),
            current_last_div: self.current_last_div,
            current_revert_in_loop: self.current_revert_in_loop.clone(),
            current_call_site_counts: self.current_call_site_counts.clone(),
            current_failed_call_sites: self.current_failed_call_sites.clone(),
            current_call_fail_counts: self.current_call_fail_counts.clone(),
            current_assert_violations: self.current_assert_violations.clone(),
            current_arg_guard_reads: self.current_arg_guard_reads.clone(),
            current_paid_calldata_addresses: self.current_paid_calldata_addresses.clone(),
            current_returndata_addresses: self.current_returndata_addresses.clone(),
            current_last_sha3: self.current_last_sha3,
            current_calldata_sload_compared: self.current_calldata_sload_compared.clone(),
            current_proof_accepted: self.current_proof_accepted.clone(),
            current_transient_loaded: self.current_transient_loaded.clone(),
            current_transient_locked: self.current_transient_locked.clone(),
            current_transient_unlock: self.current_transient_unlock,
            current_transient_unlock_calls: self.current_transient_unlock_calls.clone(),
            relations_file: self.relations_file.try_clone().unwrap(),
            relations_hash: self.relations_hash.clone(),
            current_typed_bug: self.current_typed_bug.clone(),
            randomness: vec![],
            work_dir: self.work_dir.clone(),
            spec_id: self.spec_id,
            precompiles: Precompiles::default(),
            leak_ctx: self.leak_ctx.clone(),
            mapping_sstore_pcs: self.mapping_sstore_pcs.clone(),
            mapping_sstore_pcs_to_slot: self.mapping_sstore_pcs_to_slot.clone(),
            jumpi_trace: self.jumpi_trace,
            call_depth: self.call_depth,
            // prank: self.prank.clone(),
            // expected_emits: self.expected_emits.clone(),
            // expected_revert: self.expected_revert.clone(),
            // expected_calls: self.expected_calls.clone(),
            assert_msg: self.assert_msg.clone(),
        }
    }
}

// hack: I don't want to change evm internal to add a new type of return
// this return type is never used as we disabled gas
pub static ACTIVE_MATCH_EXT_CALL: AtomicBool = AtomicBool::new(false);
/// How many distinct callee addresses seen at ONE (caller, pc) before the
/// call target is treated as unbounded (attacker-controlled). Widened from
/// 50: a legitimate router/aggregator dispatching to a large, fixed
/// allowlist of venues, or a target reached through several layers of
/// indirection, needs more samples before "many distinct targets" is real
/// evidence of unboundedness rather than a genuinely wide dispatch table.
const UNBOUND_CALL_THRESHOLD: usize = 200;
/// Same widening, same reasoning, for the address-unbounded CONTROL-LEAK
/// trigger (see `is_target_address_unbounded`).
const CONTROL_LEAK_THRESHOLD: usize = 200;

// if a PC transfers control to >10 addresses, we consider call at this PC to be
// unbounded

impl<SC> FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub fn new(scheduler: SC, workdir: String) -> Self {
        Self {
            evmstate: EVMState::new(),
            transient_storage: HashMap::new(),
            env: Env::default(),
            code: HashMap::new(),
            hash_to_address: HashMap::new(),
            address_to_hash: HashMap::new(),
            _pc: 0,
            pc_to_addresses: HashMap::new(),
            pc_to_create: HashMap::new(),
            pc_to_call_hash: HashMap::new(),
            pc_to_delegatecall_targets: HashMap::new(),
            middlewares_enabled: false,
            middlewares: RwLock::new(Default::default()),
            coverage_changed: false,
            flashloan_middleware: None,
            middlewares_latent_call_actions: vec![],
            scheduler,
            next_slot: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            bug_hit: false,
            call_count: 0,
            #[cfg(feature = "print_logs")]
            logs: Default::default(),
            setcode_data: HashMap::new(),
            current_self_destructs: Default::default(),
            current_arbitrary_calls: Default::default(),
            current_integer_overflow: Default::default(),
            current_delegatecall_injections: Default::default(),
            current_ecrecover_zero: Default::default(),
            slot_write_contexts: Default::default(),
            current_storage_collisions: Default::default(),
            current_delegatecall_targets_seen: Default::default(),
            current_uninitialized_memory_reads: Default::default(),
            last_call_scheme: CallScheme::Call,
            last_call_success: true,
            current_unchecked_call: Default::default(),
            current_tx_origin_checks: Default::default(),
            current_loop_iterations: Default::default(),
            current_last_sload: Default::default(),
            current_guard_reads: Default::default(),
            current_last_calldata_compare: Default::default(),
            current_last_proof_compare: Default::default(),
            current_calldata_addresses: Default::default(),
            current_calldata_words: Default::default(),
            current_pending_token_transfer_in: Default::default(),
            current_last_self_balance_read: Default::default(),
            view_call_baseline: Default::default(),
            current_readonly_reentrancy_hits: Default::default(),
            current_forced_eth_accounting_checks: Default::default(),
            current_token_accounting_mismatches: Default::default(),
            current_arbitrary_storage_writes: Default::default(),
            current_zero_address_setters: Default::default(),
            current_hardcoded_gas_stipends: Default::default(),
            current_last_env_read: Default::default(),
            current_weak_randomness_uses: Default::default(),
            current_precision_losses: Default::default(),
            current_last_div: Default::default(),
            current_revert_in_loop: Default::default(),
            current_call_site_counts: Default::default(),
            current_failed_call_sites: Default::default(),
            current_call_fail_counts: Default::default(),
            current_assert_violations: Default::default(),
            current_arg_guard_reads: Default::default(),
            current_paid_calldata_addresses: Default::default(),
            current_returndata_addresses: Default::default(),
            current_last_sha3: Default::default(),
            current_calldata_sload_compared: Default::default(),
            current_proof_accepted: Default::default(),
            current_transient_loaded: Default::default(),
            current_transient_locked: Default::default(),
            current_transient_unlock: Default::default(),
            current_transient_unlock_calls: Default::default(),
            relations_file: std::fs::File::create(format!("{}/relations.log", workdir)).unwrap(),
            relations_hash: HashSet::new(),
            current_typed_bug: Default::default(),
            randomness: vec![],
            work_dir: workdir,
            spec_id: SpecId::LATEST,
            precompiles: Default::default(),
            leak_ctx: vec![],
            mapping_sstore_pcs: Default::default(),
            mapping_sstore_pcs_to_slot: Default::default(),
            jumpi_trace: 37,
            call_depth: 0,
            // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved
            // prank: None,
            // expected_revert: None,
            // expected_emits: VecDeque::new(),
            // expected_calls: ExpectedCallTracker::new(),
            assert_msg: None,
        }
    }

    pub fn set_spec_id(&mut self, spec_id: String) {
        self.spec_id = SpecId::from(spec_id.as_str());
    }

    /// custom spec id run_inspect
    pub fn run_inspect(&mut self, interp: &mut Interpreter, state: &mut EVMFuzzState) -> InstructionResult {
        match self.spec_id {
            SpecId::LATEST => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, LatestSpec>(self, state),
            SpecId::FRONTIER => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, FrontierSpec>(self, state),
            SpecId::HOMESTEAD => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, HomesteadSpec>(self, state),
            SpecId::TANGERINE => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, TangerineSpec>(self, state),
            SpecId::SPURIOUS_DRAGON => {
                interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, SpuriousDragonSpec>(self, state)
            }
            SpecId::BYZANTIUM => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, ByzantiumSpec>(self, state),
            SpecId::CONSTANTINOPLE | SpecId::PETERSBURG => {
                interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, PetersburgSpec>(self, state)
            }
            SpecId::ISTANBUL => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, IstanbulSpec>(self, state),
            SpecId::MUIR_GLACIER | SpecId::BERLIN => {
                interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, BerlinSpec>(self, state)
            }
            SpecId::LONDON => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, LondonSpec>(self, state),
            SpecId::MERGE => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, MergeSpec>(self, state),
            SpecId::SHANGHAI => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, ShanghaiSpec>(self, state),
            SpecId::CANCUN => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, CancunSpec>(self, state),
            _ => interp.run_inspect::<EVMFuzzState, FuzzHost<SC>, LatestSpec>(self, state),
        }
    }

    pub fn remove_all_middlewares(&mut self) {
        self.middlewares_enabled = false;
        self.middlewares = RwLock::new(Default::default());
    }

    pub fn add_middlewares(&mut self, middleware: Rc<RefCell<dyn Middleware<SC>>>) {
        self.middlewares_enabled = true;
        self.middlewares.write().unwrap().push(middleware);
    }

    pub fn remove_middlewares(&mut self, middlewares: Rc<RefCell<dyn Middleware<SC>>>) {
        let ty = middlewares.deref().borrow().get_type();

        self.middlewares
            .write()
            .unwrap()
            .retain(|x| x.deref().borrow().get_type() != ty);
    }

    pub fn remove_middlewares_by_ty(&mut self, ty: &MiddlewareType) {
        self.middlewares
            .write()
            .unwrap()
            .retain(|x| x.deref().borrow().get_type() != *ty);
    }

    pub fn add_flashloan_middleware(&mut self, middlware: Flashloan) {
        self.flashloan_middleware = Some(Rc::new(RefCell::new(middlware)));
    }

    pub fn initialize(&mut self, state: &EVMFuzzState) {
        self.hash_to_address = state.get_hash_to_address().clone();
        for key in self.hash_to_address.keys() {
            let addresses = self.hash_to_address.get(key).unwrap();
            for addr in addresses {
                match self.address_to_hash.get_mut(addr) {
                    Some(s) => {
                        s.push(*key);
                    }
                    None => {
                        self.address_to_hash.insert(*addr, vec![*key]);
                    }
                }
            }
        }
    }

    pub fn add_hashes(&mut self, address: EVMAddress, hashes: Vec<[u8; 4]>) {
        self.address_to_hash.insert(address, hashes.clone());

        for hash in hashes {
            // insert if exists or create new
            match self.hash_to_address.get_mut(&hash) {
                Some(s) => {
                    s.insert(address);
                }
                None => {
                    self.hash_to_address.insert(hash, HashSet::from([address]));
                }
            }
        }
    }

    pub fn add_one_hashes(&mut self, address: EVMAddress, hash: [u8; 4]) {
        match self.address_to_hash.get_mut(&address) {
            Some(s) => {
                s.push(hash);
            }
            None => {
                self.address_to_hash.insert(address, vec![hash]);
            }
        }

        match self.hash_to_address.get_mut(&hash) {
            Some(s) => {
                s.insert(address);
            }
            None => {
                self.hash_to_address.insert(hash, HashSet::from([address]));
            }
        }
    }

    pub fn set_codedata(&mut self, address: EVMAddress, code: Bytecode) {
        self.setcode_data.insert(address, code);
    }

    pub fn clear_codedata(&mut self) {
        self.setcode_data.clear();
    }

    pub fn set_code(&mut self, address: EVMAddress, mut code: Bytecode, state: &mut EVMFuzzState) {
        unsafe {
            invoke_middlewares!(self, None, state, on_insert, &mut code, address);
        }
        self.code
            .insert(address, Arc::new(BytecodeLocked::try_from(to_analysed(code)).unwrap()));
    }

    pub fn find_static_call_read_slot(
        &self,
        _address: EVMAddress,
        _data: Bytes,
        _state: &mut EVMFuzzState,
    ) -> Vec<EVMU256> {
        vec![]
        // let call = Contract::new_with_context_not_cloned::<LatestSpec>(
        //     data,
        //     self.code.get(&address).expect("no code").clone(),
        //     &CallContext {
        //         address,
        //         caller: Default::default(),
        //         code_address: address,
        //         apparent_value: Default::default(),
        //         scheme: CallScheme::StaticCall,
        //     },
        // );
        // let mut interp = Interpreter::new::<LatestSpec>(call, 1e10 as u64);
        // let (ret, slots) =
        //     interp.locate_slot::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut
        // self.clone(), state); if ret != Return::Revert {
        //     slots
        // } else {
        //     vec![]
        // }
    }
    pub fn write_relations(&mut self, caller: EVMAddress, target: EVMAddress, funtion_hash: Bytes) {
        if funtion_hash.len() < 0x4 {
            return;
        }
        let cur_write_str = format!(
            "{{caller:0x{} --> target:0x{} function(0x{})}}\n",
            hex::encode(caller),
            hex::encode(target),
            hex::encode(&funtion_hash[..4])
        );
        let mut hasher = DefaultHasher::new();
        cur_write_str.hash(&mut hasher);
        let cur_wirte_hash = hasher.finish();
        if self.relations_hash.contains(&cur_wirte_hash) {
            return;
        }
        if self.relations_hash.is_empty() {
            let write_head = "[forksploit relations] caller, traget, function hash\n".to_string();
            self.relations_file.write_all(write_head.as_bytes()).unwrap();
        }

        self.relations_hash.insert(cur_wirte_hash);
        self.relations_file.write_all(cur_write_str.as_bytes()).unwrap();
    }

    fn call_allow_control_leak(
        &mut self,
        input: &mut CallInputs,
        interp: &mut Interpreter,
        (out_offset, out_len): (usize, usize),
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Gas, Bytes) {
        macro_rules! push_interp {
            () => {{
                self.leak_ctx = vec![SinglePostExecution::from_interp(interp, (out_offset, out_len))];
            }};
        }
        self.call_count += 1;
        if self.call_count >= CALL_UNTIL.load(Ordering::Relaxed) {
            push_interp!();
            return (ControlLeak, Gas::new(0), Bytes::new());
        }

        if WRITE_RELATIONSHIPS.load(Ordering::Relaxed) {
            self.write_relations(input.transfer.source, input.contract, input.input.clone());
        }

        let mut hash = input.input.to_vec();
        hash.resize(4, 0);

        macro_rules! record_func_hash {
            () => {
                unsafe {
                    let mut s = DefaultHasher::new();
                    hash.hash(&mut s);
                    let _hash = s.finish();
                    ABI_MAX_SIZE.get_mut()[(_hash as usize) % MAP_SIZE] = RET_SIZE.load(Ordering::Relaxed);
                }
            };
        }

        // middlewares
        let mut middleware_result: Option<(InstructionResult, Gas, Bytes)> = None;
        for action in &self.middlewares_latent_call_actions {
            match action {
                CallMiddlewareReturn::Continue => {}
                CallMiddlewareReturn::ReturnRevert => {
                    middleware_result = Some((Revert, Gas::new(0), Bytes::new()));
                }
                CallMiddlewareReturn::ReturnSuccess(b) => {
                    middleware_result = Some((Continue, Gas::new(0), b.clone()));
                }
            }
            if middleware_result.is_some() {
                break;
            }
        }
        self.middlewares_latent_call_actions.clear();

        if let Some(m) = middleware_result {
            return m;
        }

        let input_seq = input.input.to_vec();

        let is_target_address_unbounded = {
            assert_ne!(self._pc, 0);
            self.pc_to_addresses
                .entry((input.context.caller, self._pc))
                .or_default();
            let addresses_at_pc = self.pc_to_addresses.get_mut(&(input.context.caller, self._pc)).unwrap();
            addresses_at_pc.insert(input.contract);
            addresses_at_pc.len() > CONTROL_LEAK_THRESHOLD
        };

        if input.context.scheme == CallScheme::StaticCall &&
            (state.has_caller(&input.contract) || is_target_address_unbounded)
        {
            record_func_hash!();
            push_interp!();
            // println!(
            //     "staticcall self {:?} -> {:?} with {:?}",
            //     input.context.caller,
            //     input.contract,
            //     hex::encode(input.input.clone())
            // );
            return (InstructionResult::AddressUnboundedStaticCall, Gas::new(0), Bytes::new());
        }

        if input.context.scheme == CallScheme::Call {
            // if calling sender, then definitely control leak
            if state.has_caller(&input.contract) || is_target_address_unbounded {
                record_func_hash!();
                push_interp!();
                // println!(
                //     "call self {:?} -> {:?} with {:?}",
                //     input.context.caller,
                //     input.contract,
                //     hex::encode(input.input.clone())
                // );
                return (ControlLeak, Gas::new(0), Bytes::new());
            }
            // check whether the whole CALLDATAVALUE can be arbitrary
            self.pc_to_call_hash
                .entry((input.context.caller, self._pc, self.jumpi_trace))
                .or_default();
            self.pc_to_call_hash
                .get_mut(&(input.context.caller, self._pc, self.jumpi_trace))
                .unwrap()
                .insert(hash.to_vec());
            if self
                .pc_to_call_hash
                .get(&(input.context.caller, self._pc, self.jumpi_trace))
                .unwrap()
                .len() >
                UNBOUND_CALL_THRESHOLD &&
                input_seq.len() >= 4
            {
                self.current_arbitrary_calls.push((
                    input.context.caller,
                    input.context.address,
                    interp.program_counter(),
                ));
                // println!(
                //     "ub leak {:?} -> {:?} with {:?} {}",
                //     input.context.caller,
                //     input.contract,
                //     hex::encode(input.input.clone()),
                //     self.jumpi_trace
                // );
                push_interp!();
                return (
                    InstructionResult::ArbitraryExternalCallAddressBounded(
                        input.context.caller,
                        input.context.address,
                        input.transfer.value,
                    ),
                    Gas::new(0),
                    Bytes::new(),
                );
            }
        }

        let input_bytes = Bytes::from(input_seq);

        // find contracts that have this function hash
        let contract_loc_option = self.hash_to_address.get(hash.as_slice());
        if ACTIVE_MATCH_EXT_CALL.load(Ordering::Relaxed) {
            if let Some(loc) = contract_loc_option {
                // if there is such a location known, then we can use exact call
                if !loc.contains(&input.contract) {
                    // todo(@shou): resolve multi locs
                    if loc.len() != 1 {
                        panic!("more than one contract found for the same hash");
                    }
                    let mut interp = Interpreter::new_with_memory_limit(
                        Contract::new_with_context_analyzed(
                            input_bytes,
                            self.code.get(loc.iter().next().unwrap()).unwrap().clone(),
                            &input.context,
                        ),
                        1e10 as u64,
                        false,
                        MEM_LIMIT,
                    );

                    let ret = self.run_inspect(&mut interp, state);
                    return (ret, Gas::new(0), interp.return_value());
                }
            }
        }

        // if there is code, then call the code
        let res = self.call_forbid_control_leak(input, state);
        match res.0 {
            ControlLeak |
            InstructionResult::ArbitraryExternalCallAddressBounded(_, _, _) |
            InstructionResult::AddressUnboundedStaticCall => {
                self.leak_ctx
                    .push(SinglePostExecution::from_interp(interp, (out_offset, out_len)));
            }
            _ => {}
        }
        res
    }

    fn call_forbid_control_leak(
        &mut self,
        input: &mut CallInputs,
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Gas, Bytes) {
        let mut hash = input.input.to_vec();
        hash.resize(4, 0);
        // if there is code, then call the code
        if let Some(code) = self.code.get(&input.context.code_address) {
            let mut interp = Interpreter::new_with_memory_limit(
                Contract::new_with_context_analyzed(Bytes::from(input.input.to_vec()), code.clone(), &input.context),
                1e10 as u64,
                false,
                MEM_LIMIT,
            );

            let ret = self.run_inspect(&mut interp, state);
            return (ret, Gas::new(0), interp.return_value());
        }

        // transfer txn and fallback provided
        if hash == [0x00, 0x00, 0x00, 0x00] {
            return (Continue, Gas::new(0), Bytes::new());
        }
        (Revert, Gas::new(0), Bytes::new())
    }

    fn call_precompile(
        &mut self,
        input: &mut CallInputs,
        _state: &mut EVMFuzzState,
    ) -> (InstructionResult, Gas, Bytes) {
        let precompile = self
            .precompiles
            .get(&input.contract)
            .expect("Check for precompile should be already done");
        let out = match precompile {
            Precompile::Standard(fun) => fun(input.input.to_vec().as_slice(), u64::MAX),
            Precompile::Custom(fun) => fun(input.input.to_vec().as_slice(), u64::MAX),
        };
        match out {
            Ok((_, data)) => (InstructionResult::Return, Gas::new(0), Bytes::from(data)),
            Err(_) => (InstructionResult::PrecompileError, Gas::new(0), Bytes::new()),
        }
    }

    /// Apply the prank
    pub fn apply_prank(&mut self, _contract_caller: &EVMAddress, _input: &mut CallInputs) {
        // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved

        // if let Some(prank) = &self.prank {
        //     if self.call_depth >= prank.depth && contract_caller ==
        // &prank.old_caller {         // At the target depth we set
        // `msg.sender`         if self.call_depth == prank.depth {
        //             input.context.caller = prank.new_caller;
        //             input.transfer.source = prank.new_caller;
        //         }

        //         // At the target depth, or deeper, we set `tx.origin`
        //         if let Some(new_origin) = prank.new_origin {
        //             self.env.tx.caller = new_origin;
        //         }
        //     }
        // }
    }

    /// Clean up the prank
    pub fn clean_prank(&mut self) {
        // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved

        // if let Some(prank) = &self.prank {
        //     if self.call_depth != prank.depth {
        //         return;
        //     }
        //     if let Some(old_origin) = prank.old_origin {
        //         self.env.tx.caller = old_origin;
        //     }
        //     if prank.single_call {
        //         let _ = self.prank.take();
        //     }
        // }
    }

    /// Check expected
    pub fn check_expected(
        &mut self,
        call: &CallInputs,
        res: (InstructionResult, Gas, Bytes),
    ) -> (InstructionResult, Gas, Bytes) {
        // Check assert result
        if let Some(res) = self.check_assert_result() {
            return res;
        }

        // Check expected reverts
        let res = self.check_expected_revert(res);
        if res.0 == Revert {
            return res;
        }
        // Check expected emits
        let res = self.check_expected_emits(call, res);
        if res.0 == Revert {
            return res;
        }
        // Check expected calls
        self.check_expected_calls(res)
    }

    pub fn check_assert_result(&mut self) -> Option<(InstructionResult, Gas, Bytes)> {
        if let Some(ref msg) = self.assert_msg {
            return Some((InstructionResult::Revert, Gas::new(0), msg.abi_encode().into()));
        }

        None
    }

    /// Check expected reverts
    fn check_expected_revert(&mut self, res: (InstructionResult, Gas, Bytes)) -> (InstructionResult, Gas, Bytes) {
        return res;

        // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved

        // // Check if we should check for reverts
        // if self.expected_revert.is_none() {
        //     return res;
        // }
        // let expected_revert = self.expected_revert.as_ref().unwrap();
        // if self.call_depth > expected_revert.depth {
        //     return res;
        // }
        // let (result, gas, retdata) = res;
        // let mut expected_revert = self.expected_revert.take().unwrap();

        // // Check result
        // if matches!(result, return_ok!()) {
        //     return (
        //         InstructionResult::Revert,
        //         gas,
        //         "Call did not revert as expected".abi_encode().into(),
        //     );
        // }

        // // Check revert reason
        // if expected_revert.reason.is_none() {
        //     return (InstructionResult::Return, gas, retdata);
        // }
        // let expected_reason = expected_revert.reason.take().unwrap();
        // let mut actual_reason = retdata.clone();
        // if actual_reason.len() >= 4 &&
        // matches!(actual_reason[..4].try_into(), Ok(ERROR_PREFIX |
        // REVERT_PREFIX)) {     if let Ok(parsed_bytes) =
        // DynSolType::Bytes.abi_decode(&actual_reason[4..]) {
        //         if let Some(bytes) = parsed_bytes.as_bytes().map(|b|
        // b.to_vec()) {             actual_reason = bytes.into();
        //         }
        //     }
        // }
        // if actual_reason != expected_reason {
        //     return (
        //         InstructionResult::Revert,
        //         gas,
        //         "Revert reason mismatch".abi_encode().into(),
        //     );
        // }

        // (InstructionResult::Return, gas, retdata)
    }

    /// Check expected emits
    fn check_expected_emits(
        &mut self,
        _call: &CallInputs,
        res: (InstructionResult, Gas, Bytes),
    ) -> (InstructionResult, Gas, Bytes) {
        return res;

        // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved

        // let should_check_emits = self
        //     .expected_emits
        //     .iter()
        //     .any(|expected| expected.depth == self.call_depth) &&
        //     // Ignore staticcalls
        //     !call.is_static;
        // if !should_check_emits {
        //     return res;
        // }

        // let (result, gas, retdata) = res;
        // // Not all emits were matched.
        // if self.expected_emits.iter().any(|expected| !expected.found) {
        //     return (
        //         InstructionResult::Revert,
        //         gas,
        //         "log != expected log".abi_encode().into(),
        //     );
        // }

        // self.expected_emits.clear();
        // (result, gas, retdata)
    }

    /// Check expected calls
    fn check_expected_calls(&mut self, res: (InstructionResult, Gas, Bytes)) -> (InstructionResult, Gas, Bytes) {
        return res;

        // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved

        // // Only check expected calls at the root call
        // if self.call_depth > 0 {
        //     return res;
        // }

        // let (result, gas, retdata) = res;
        // let expected_calls = std::mem::take(&mut self.expected_calls);
        // for (_, calldatas) in expected_calls {
        //     // Loop over each address, and for each address, loop over each
        // calldata it     // expects.
        //     for (_, (expected, actual_count)) in calldatas {
        //         // Grab the values we expect to see
        //         let ExpectedCallData { count, call_type, .. } = expected;

        //         let failed = match call_type {
        //             ExpectedCallType::Count => count != actual_count,
        //             ExpectedCallType::NonCount => count > actual_count,
        //         };
        //         if failed {
        //             let msg = "expected call count mismatch";
        //             return (InstructionResult::Revert, gas,
        // msg.abi_encode().into());         }
        //     }
        // }

        // (result, gas, retdata)
    }
    fn note_outgoing_call_outcome(&mut self, key: (EVMAddress, usize), success: bool) {
        if !success {
            self.current_failed_call_sites.insert(key);
            *self.current_call_fail_counts.entry(key).or_insert(0) += 1;
        }
        let seen = *self.current_call_site_counts.get(&key).unwrap_or(&0);
        let fails = *self.current_call_fail_counts.get(&key).unwrap_or(&0);
        if seen >= 2 && fails >= 1 {
            self.current_revert_in_loop.insert(key);
        }
    }
}

macro_rules! process_rw_key {
    ($key:ident) => {
        if $key > EVMU256::from(RW_SKIPPER_PERCT_IDX) {
            // $key >>= 4;
            $key %= EVMU256::from(RW_SKIPPER_AMT);
            $key += EVMU256::from(RW_SKIPPER_PERCT_IDX);
            as_u64($key) as usize % MAP_SIZE
        } else {
            as_u64($key) as usize % MAP_SIZE
        }
    };
}

macro_rules! u256_to_u8 {
    ($key:ident) => {
        (as_u64($key >> 4) % 254) as u8
    };
}

#[macro_export]
macro_rules! invoke_middlewares {
    ($host:expr, $interp:expr, $state:expr, $invoke:ident $(, $arg:expr)*) => {
        if $host.middlewares_enabled {
            if let Some(m) = $host.flashloan_middleware.clone() {
                let mut middleware = m.deref().borrow_mut();
                middleware.$invoke($interp, $host, $state $(, $arg)*);
            }

            if !$host.setcode_data.is_empty() {
                $host.clear_codedata();
            }

            let mut middlewares = $host.middlewares.read().unwrap().clone();
            for middleware in middlewares.iter_mut() {
                middleware.deref().borrow_mut().$invoke($interp, $host, $state $(, $arg)*);
            }

            if !$host.setcode_data.is_empty() {
                for (address, code) in &$host.setcode_data.clone() {
                    $host.set_code(address.clone(), code.clone(), $state);
                }
            }
        }
    };
}

impl<SC> Host<EVMFuzzState> for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn step(&mut self, interp: &mut Interpreter, state: &mut EVMFuzzState) -> InstructionResult {
        unsafe {
            // debug!("pc: {}", interp.program_counter());
            // debug!("{:?}", *interp.instruction_pointer);
            invoke_middlewares!(self, interp, state, on_step);
            if IS_FAST_CALL_STATIC.load(Ordering::Relaxed) {
                return Continue;
            }

            macro_rules! fast_peek {
                ($idx:expr) => {
                    interp.stack.data()[interp.stack.len() - 1 - $idx]
                };
            }

            // Shared by the LT/SLT/GT/SGT/EQ opcode cases below: if
            // either operand is an address-shaped value this call
            // already loaded via CALLDATALOAD, latch it for the next
            // JUMPI (see current_last_calldata_compare's doc comment
            // and the 0x57 case below).
            macro_rules! latch_calldata_compare {
                ($v1:expr, $v2:expr) => {
                    for v in [$v1, $v2] {
                        if !v.is_zero() {
                            let vb: [u8; 32] = v.to_be_bytes();
                            if vb[..12].iter().all(|b| *b == 0) {
                                let addr = convert_u256_to_h160(v);
                                if self.current_calldata_addresses.contains(&addr) {
                                    self.current_last_calldata_compare = Some(addr);
                                }
                            }
                        }
                    }
                };
            }
            match *interp.instruction_pointer {
                // 0xfd => {
                //     println!("fd {} @ {:?}", interp.program_counter(), interp.contract.address);
                // }
                // 0x3b => {
                //     println!(
                //         "3b {} @ {:?} {:?}",
                //         interp.program_counter(),
                //         interp.contract.address,
                //         fast_peek!(0)
                //     );
                // }
                0x47 => {
                    // SELFBALANCE. Feeds oracles/forced_eth_accounting.rs
                    // (SWC-132): latch this contract's own real ETH
                    // balance so the very next EQ (0x14) comparison below
                    // can tell whether it's comparing this exact value.
                    if let Some((bal, _)) = self.balance(interp.contract.address) {
                        self.current_last_self_balance_read = Some(bal);
                    }
                }
                0x31 => {
                    // BALANCE(address). Same latch as SELFBALANCE above,
                    // but only when the queried address is THIS
                    // contract's own (the stack arg hasn't been popped
                    // yet at this pre-execution hook, so fast_peek!(0)
                    // is exactly what BALANCE is about to read).
                    let queried = convert_u256_to_h160(fast_peek!(0));
                    if queried == interp.contract.address {
                        if let Some((bal, _)) = self.balance(queried) {
                            self.current_last_self_balance_read = Some(bal);
                        }
                    }
                }
                0x56 => {
                    // JUMP (unconditional). Confirmed live: solc's own
                    // standard `for` loop codegen -- condition check with
                    // a FORWARD jumpi out when false, falling through into
                    // the body, ending in an unconditional backward JUMP
                    // back to the condition check -- means the loop's
                    // real repeat/continue edge is THIS opcode, not
                    // JUMPI. The 0x57 case below only ever sees this
                    // same loop's EXIT check (whose jumpi target is
                    // forward, to skip past the loop), so relying on it
                    // alone for loop-iteration tracking (see
                    // oracles/unbounded_loop.rs) silently tracked zero
                    // iterations for this extremely common shape.
                    let jump_dest = as_u64(fast_peek!(0));
                    let _pc = interp.program_counter();
                    if (jump_dest as usize) < _pc {
                        let count = self
                            .current_loop_iterations
                            .entry((interp.contract.address, jump_dest as usize))
                            .or_insert(0);
                        *count += 1;
                    }
                }
                0x57 => {
                    // JUMPI counter cond
                    let br = fast_peek!(1);
                    let jump_dest = if is_zero(br) { 1 } else { as_u64(fast_peek!(0)) };
                    let _pc = interp.program_counter();

                    // A JUMPI that actually jumps (br != 0) BACKWARD (to an
                    // earlier pc) is, by construction, a loop iterating --
                    // see oracles/unbounded_loop.rs for what this feeds.
                    // Reset once per call (see the `current_loop_iterations
                    // = HashMap::new()` resets alongside the other
                    // `current_*` per-call trackers), so this genuinely
                    // counts iterations within THIS ONE call, not across
                    // the whole fuzzing campaign.
                    if !is_zero(br) && (jump_dest as usize) < _pc {
                        let count = self
                            .current_loop_iterations
                            .entry((interp.contract.address, jump_dest as usize))
                            .or_insert(0);
                        *count += 1;
                    }

                    // Proximity link to the most recent SLOAD (see the
                    // 0x54 case): storage reads happen right where they're
                    // used, so a short byte-distance window reliably
                    // covers solc's typical `SLOAD; PUSH <const>;
                    // LT/GT/EQ; [ISZERO]; PUSH <dest>; JUMPI` guard shape
                    // (see oracles/stale_guard.rs).
                    const GUARD_PROXIMITY_BYTES: usize = 40;

                    if let Some((sload_pc, slot, value)) = self.current_last_sload {
                        if _pc.saturating_sub(sload_pc) <= GUARD_PROXIMITY_BYTES {
                            self.current_guard_reads.push((interp.contract.address, _pc, slot, value));
                        }
                    }
                    // Consume the pending comparison-against-a-calldata-
                    // address latch (see the 0x10-0x14 cases below) --
                    // execution-order adjacency, not byte distance (see
                    // current_last_calldata_compare's own doc comment for
                    // why that's what actually holds for function
                    // arguments, unlike storage reads above).
                    if let Some(arg_addr) = self.current_last_calldata_compare.take() {
                        self.current_arg_guard_reads.push((interp.contract.address, _pc, arg_addr, !is_zero(br)));
                    }
                    // oracles/forged_proof.rs: this JUMPI ACCEPTED (jumped)
                    // a comparison of a freshly computed hash against a
                    // caller-supplied calldata word -- record it.
                    if let Some((addr, eq_pc, root)) = self.current_last_proof_compare.take() {
                        if !is_zero(br) {
                            self.current_proof_accepted.push((addr, eq_pc, root));
                        }
                    }

                    let (shash, _) = self.jumpi_trace.overflowing_mul(54059);
                    self.jumpi_trace = (shash) ^ (_pc * 76963);
                    let idx = (_pc * (jump_dest as usize)) % MAP_SIZE;
                    let jmp_map = { JMP_MAP.get_mut() };
                    if jmp_map[idx] == 0 {
                        self.coverage_changed = true;
                    }
                    jmp_map[idx] = jmp_map[idx].saturating_add(1);

                    #[cfg(feature = "cmp")]
                    {
                        let idx = (interp.program_counter()) % MAP_SIZE;
                        ({ CMP_MAP.get_mut() })[idx] = br;
                    }

                    add_branch((interp.contract.address, interp.program_counter(), jump_dest != 1));
                }

                #[cfg(any(feature = "dataflow", feature = "cmp"))]
                0x55 => {
                    // SSTORE
                    let pc = interp.program_counter();
                    if !self.mapping_sstore_pcs.contains(&(interp.contract.address, pc)) {
                        let mut key = fast_peek!(0);
                        let slots = self
                            .mapping_sstore_pcs_to_slot
                            .entry((interp.contract.address, pc))
                            .or_default();
                        slots.insert(key);
                        if slots.len() > 10 {
                            self.mapping_sstore_pcs.insert((interp.contract.address, pc));
                        }

                        let value = fast_peek!(1);
                        let compressed_value = u256_to_u8!(value) + 1;
                        ({ WRITE_MAP.get_mut() })[process_rw_key!(key)] = compressed_value;

                        let res =
                            <FuzzHost<SC> as Host<EVMFuzzState>>::sload(self, interp.contract.address, fast_peek!(0));
                        let value_changed = res.expect("sload failed").0 != value;

                        let idx = interp.program_counter() % MAP_SIZE;
                        ({ JMP_MAP.get_mut() })[idx] = if value_changed { 1 } else { 0 };

                        STATE_CHANGE.fetch_or(value_changed, Ordering::Relaxed);
                    }

                    // oracles/token_accounting_mismatch.rs: this SSTORE's
                    // new value is exactly (the slot's own prior SLOAD'd
                    // value + an UNVERIFIED transferFrom amount latched in
                    // call() above) -- the classic `balances[x] += amount`
                    // accounting pattern applied to a token amount that
                    // was never confirmed via a real balanceOf() delta,
                    // which a fee-on-transfer or rebasing token breaks.
                    if let Some((_token, pending_amount)) = self.current_pending_token_transfer_in {
                        let slot = fast_peek!(0);
                        let new_value = fast_peek!(1);
                        if let Some((_, sload_slot, old_value)) = self.current_last_sload {
                            if sload_slot == slot && new_value == old_value.saturating_add(pending_amount) {
                                self.current_token_accounting_mismatches
                                    .insert((interp.contract.address, pc));
                            }
                        }
                        self.current_pending_token_transfer_in = None;
                    }

                    // oracles/zero_address_setter.rs: this SSTORE zeroed
                    // out a slot that previously held a nonzero,
                    // address-shaped value (upper 96 bits clear), and the
                    // pc is NOT one the fuzzer already knows writes a
                    // mapping/array slot (those legitimately zero out
                    // individual entries and would otherwise flood this
                    // signal). That is the missing
                    // `require(newAddr != address(0))` pattern on a direct
                    // state-variable setter -- owner/admin/implementation
                    // being permanently cemented to address(0). Reads the
                    // slot's CURRENT (pre-SSTORE) value directly rather
                    // than relying on a preceding SLOAD: a plain
                    // `owner = newOwner` compiles to a bare SSTORE with no
                    // read of its own.
                    {
                        let slot = fast_peek!(0);
                        let new_value = fast_peek!(1);
                        if new_value.is_zero() && !self.mapping_sstore_pcs.contains(&(interp.contract.address, pc)) {
                            if let Some((old_value, _)) =
                                <FuzzHost<SC> as Host<EVMFuzzState>>::sload(self, interp.contract.address, slot)
                            {
                                let ob: [u8; 32] = old_value.to_be_bytes();
                                if !old_value.is_zero() && ob[..12].iter().all(|b| *b == 0) {
                                    self.current_zero_address_setters
                                        .insert((interp.contract.address, pc, slot));
                                }
                            }
                        }
                    }
                }

                0x35 => {
                    // CALLDATALOAD. Mirrors revm's own
                    // `instructions::system::calldataload` read (offset
                    // clamped to calldata length, short reads zero-padded)
                    // purely to OBSERVE an address-shaped argument value --
                    // doesn't touch the interpreter's own stack/memory, so
                    // it can't desync real execution. Feeds
                    // oracles/self_referral.rs: an address-type function
                    // argument that later both (a) gates a JUMPI check and
                    // (b) receives an outgoing payment is exactly the
                    // "validation doesn't gate the payout" shape (e.g. a
                    // referral fee paid to an address regardless of whether
                    // it passed its own "valid referral" check).
                    let offset = as_u64(fast_peek!(0)) as usize;
                    let input = &interp.contract.input;
                    if offset < input.len() {
                        let have = (input.len() - offset).min(32);
                        let mut bytes = [0u8; 32];
                        bytes[..have].copy_from_slice(&input[offset..offset + have]);
                        let value = EVMU256::from_be_bytes(bytes);
                        if !value.is_zero() && bytes[..12].iter().all(|b| *b == 0) {
                            self.current_calldata_addresses.insert(convert_u256_to_h160(value));
                        }
                        // Also feed oracles/arbitrary_storage_write.rs:
                        // every raw word, not just address-shaped ones --
                        // a storage slot index can be any uint256.
                        if !value.is_zero() {
                            self.current_calldata_words.insert(value);
                        }
                    }
                }

                0x3e => {
                    // RETURNDATACOPY (destOffset, offset, size -- top to
                    // bottom). Same observe-only read as 0x35
                    // CALLDATALOAD above, for the LATEST completed call's
                    // return data instead of this call's own calldata.
                    // Feeds oracles/delegatecall_target.rs: a DELEGATECALL
                    // target read from a prior call's return value (e.g.
                    // `Registry(target).getImplementation()`) is exactly
                    // as attacker-controlled as one read straight from
                    // calldata whenever that prior call's target is
                    // itself untrusted/attacker-influenced -- but it was
                    // never in THIS transaction's calldata at all, so a
                    // calldata-only check can never see it. Only tracks
                    // the common single-word-return shape (size == 32);
                    // a copy of any other size isn't a single ABI-decoded
                    // address value and is out of scope here.
                    let size = as_u64(fast_peek!(2)) as usize;
                    if size == 32 {
                        let offset = as_u64(fast_peek!(1)) as usize;
                        let buf = &interp.return_data_buffer;
                        if offset + 32 <= buf.len() {
                            let mut bytes = [0u8; 32];
                            bytes.copy_from_slice(&buf[offset..offset + 32]);
                            let value = EVMU256::from_be_bytes(bytes);
                            if !value.is_zero() && bytes[..12].iter().all(|b| *b == 0) {
                                self.current_returndata_addresses.insert(convert_u256_to_h160(value));
                            }
                        }
                    }
                }

                0x5c => {
                    // TLOAD (EIP-1153). Pre-execution: stack top is the
                    // slot. Mark it as a candidate reentrancy-guard slot
                    // (see oracles/transient_guard.rs). Observe-only.
                    let slot = fast_peek!(0);
                    self.current_transient_loaded
                        .insert((interp.contract.address, slot));
                }

                0x5d => {
                    // TSTORE (EIP-1153). Pre-execution: stack top is the
                    // slot, next the value. Track lock/unlock transitions
                    // of transient guard slots (see
                    // oracles/transient_guard.rs). Observe-only.
                    let slot = fast_peek!(0);
                    let value = fast_peek!(1);
                    let key = (interp.contract.address, slot);
                    if !value.is_zero() {
                        self.current_transient_locked.insert(key);
                        // A re-lock cancels a pending unlock.
                        if let Some((a, _pc, sl)) = self.current_transient_unlock {
                            if a == key.0 && sl == slot {
                                self.current_transient_unlock = None;
                            }
                        }
                    } else if self.current_transient_locked.contains(&key) {
                        self.current_transient_unlock =
                            Some((interp.contract.address, interp.program_counter(), slot));
                    }
                }

                0x20 => {
                    // SHA3 (KECCAK256). Pre-execution observation: the
                    // stack top is the memory offset, the next the length.
                    // Compute the same hash revm is about to, so a later
                    // EQ against a caller-supplied word can be recognized
                    // as a proof verified against an attacker-chosen root
                    // (see oracles/forged_proof.rs). Observe-only; does
                    // not touch the interpreter's stack/memory.
                    let offset = as_u64(fast_peek!(0)) as usize;
                    let len = as_u64(fast_peek!(1)) as usize;
                    if interp.memory.len() >= offset + len {
                        let data = interp.memory.get_slice(offset, len);
                        let h = keccak256(data);
                        self.current_last_sha3 = Some(EVMU256::from_be_slice(h.as_slice()));
                    }
                }

                0x54 => {
                    // SLOAD
                    let key = fast_peek!(0);

                    #[cfg(feature = "dataflow")]
                    {
                        let mut key = key;
                        ({ READ_MAP.get_mut() })[process_rw_key!(key)] = true;
                    }

                    // Harvest real, concrete addresses straight out of
                    // storage into the global address/caller pools.
                    // Without this, the pools stay fixed at whatever
                    // setup_default_callers/setup_contract_callers
                    // (corpus_initializer.rs) seeded at startup -- a
                    // small, generic, hardcoded set of ~4 test sender
                    // addresses that never includes anything specific to
                    // THIS target. Confirmed live this session: a 3-of-3
                    // multisig's real owner addresses, or a DEX factory's
                    // real paired-token addresses, are never discovered
                    // by random mutation alone (astronomically unlikely
                    // to guess a specific 160-bit value by chance), so
                    // fuzzing plateaus well short of any owner-gated or
                    // address-specific code path no matter how long it
                    // runs. A loaded word that "looks like" an address
                    // (nonzero, upper 96 bits clear -- the same shape
                    // convert_u256_to_h160 always assumes) is cheap to
                    // detect here and harmless to add even on a false
                    // positive (an ordinary small uint): worst case it's
                    // simply never useful as a caller/address argument.
                    let sload_res = <FuzzHost<SC> as Host<EVMFuzzState>>::sload(self, interp.contract.address, key);
                    if let Some((value, _)) = sload_res {
                        let value_bytes: [u8; 32] = value.to_be_bytes();
                        if !value.is_zero() && value_bytes[..12].iter().all(|b| *b == 0) {
                            // Added as a CALLER too (not just an ABI
                            // argument value), since this fuzzer runs
                            // against a local forked simulation -- no
                            // real private key is ever needed to set
                            // msg.sender to an arbitrary address, so a
                            // storage-discovered address (plausibly an
                            // owner/admin identity) is exactly as cheap
                            // to try impersonating as it is to pass as a
                            // function argument.
                            let harvested = convert_u256_to_h160(value);
                            state.add_caller(&harvested);
                            // Remember it globally so a finding whose only
                            // "attacker" is this identity can be flagged as
                            // owner-impersonation rather than reported as an
                            // exploit -- see HARVESTED_STORAGE_ADDRESSES.
                            // The (contract, slot) pair is recorded too, so
                            // the report can name WHERE the identity came
                            // from, not just that it was harvested.
                            record_harvested_storage_address(&harvested, &interp.contract.address, key);
                        }
                    }

                    // Latch (pc, slot, value) for oracles/stale_guard.rs:
                    // a JUMPI shortly after this SLOAD (see the 0x57 case
                    // above) is treated as a guard check derived from this
                    // same storage read -- proximity, not real dataflow,
                    // but cheap and good enough to link "this counter was
                    // read" to "this is the check that gates on it".
                    if let Some((value, _)) = sload_res {
                        self.current_last_sload = Some((interp.program_counter(), key, value));
                    }
                }

                // todo(shou): support signed checking
                #[cfg(feature = "cmp")]
                0x10 | 0x12 => {
                    // LT, SLT
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    latch_calldata_compare!(v1, v2);
                    // oracles/weak_randomness.rs: a comparison against a
                    // block-environment value (SWC-120) gates on
                    // attacker-predictable "randomness".
                    if let Some((_pc, env_val)) = self.current_last_env_read {
                        if v1 == env_val || v2 == env_val {
                            self.current_weak_randomness_uses
                                .insert((interp.contract.address, interp.program_counter()));
                        }
                    }
                    let abs_diff = if v1 >= v2 {
                        if v1 - v2 != EVMU256::ZERO {
                            v1 - v2
                        } else {
                            EVMU256::from(1)
                        }
                    } else {
                        EVMU256::ZERO
                    };
                    let idx = interp.program_counter() % MAP_SIZE;
                    let cmp_map = { CMP_MAP.get_mut() };
                    if abs_diff < cmp_map[idx] {
                        cmp_map[idx] = abs_diff;
                    }
                }

                #[cfg(feature = "cmp")]
                0x11 | 0x13 => {
                    // GT, SGT
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    latch_calldata_compare!(v1, v2);
                    // oracles/weak_randomness.rs (see the LT case above).
                    if let Some((_pc, env_val)) = self.current_last_env_read {
                        if v1 == env_val || v2 == env_val {
                            self.current_weak_randomness_uses
                                .insert((interp.contract.address, interp.program_counter()));
                        }
                    }
                    let abs_diff = if v1 <= v2 {
                        if v2 - v1 != EVMU256::ZERO {
                            v2 - v1
                        } else {
                            EVMU256::from(1)
                        }
                    } else {
                        EVMU256::ZERO
                    };
                    let idx = interp.program_counter() % MAP_SIZE;
                    let cmp_map = { CMP_MAP.get_mut() };
                    if abs_diff < cmp_map[idx] {
                        cmp_map[idx] = abs_diff;
                    }
                }

                #[cfg(feature = "cmp")]
                0x14 => {
                    // EQ
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    latch_calldata_compare!(v1, v2);

                    // oracles/forged_proof.rs: is one operand a hash this
                    // call just recomputed (SHA3 above) and the other a
                    // caller-supplied calldata word? That is exactly
                    // `require(keccak(...) == root)` with `root` coming
                    // from calldata (the Nomad/KelpDAO shape) -- latch it
                    // for the next JUMPI. Separately, record when a
                    // calldata word is compared against an SLOAD'd value
                    // (the SAFE `root == trustedRoot` form), so a later
                    // accepted-proof check on that same word is excluded.
                    if v1 != v2 {
                        if let Some(sha3v) = self.current_last_sha3 {
                            // The computed hash must itself be a DERIVED
                            // value, not one of the caller's raw words --
                            // otherwise this is not a proof comparison at
                            // all (e.g. solc's mapping-slot arithmetic
                            // comparing a calldata-derived key against
                            // itself).
                            if !self.current_calldata_words.contains(&sha3v) {
                                let other = if v1 == sha3v {
                                    v2
                                } else if v2 == sha3v {
                                    v1
                                } else {
                                    EVMU256::ZERO
                                };
                                if !other.is_zero() && self.current_calldata_words.contains(&other) {
                                    self.current_last_proof_compare =
                                        Some((interp.contract.address, interp.program_counter(), other));
                                }
                            }
                        }
                    }
                    if let Some((_, _slot, sload_value)) = self.current_last_sload {
                        for v in [v1, v2] {
                            if v == sload_value {
                                // The OTHER operand is the candidate
                                // calldata word -- `root == trustedRoot`
                                // compares the caller's word against the
                                // stored one, so `root` (not the SLOAD'd
                                // value) is what gets marked as tied to
                                // authoritative state.
                                let other = if v1 == sload_value { v2 } else { v1 };
                                if self.current_calldata_words.contains(&other) {
                                    self.current_calldata_sload_compared.insert(other);
                                }
                            }
                        }
                    }

                    // oracles/weak_randomness.rs (see the LT case above).
                    if let Some((_pc, env_val)) = self.current_last_env_read {
                        if v1 == env_val || v2 == env_val {
                            self.current_weak_randomness_uses
                                .insert((interp.contract.address, interp.program_counter()));
                        }
                    }

                    // oracles/forced_eth_accounting.rs (SWC-132): this EQ
                    // uses the contract's own real ETH balance (just
                    // latched by BALANCE(self)/SELFBALANCE above) as one
                    // of its two operands -- an exact-equality check
                    // against address(this).balance, which a forced
                    // SELFDESTRUCT donation of even 1 wei can brick
                    // forever (no legitimate path ever removes unwanted
                    // ETH again).
                    if let Some(self_bal) = self.current_last_self_balance_read {
                        if v1 == self_bal || v2 == self_bal {
                            self.current_forced_eth_accounting_checks
                                .insert((interp.contract.address, interp.program_counter()));
                        }
                        self.current_last_self_balance_read = None;
                    }
                    let abs_diff = if v1 < v2 {
                        (v2 - v1) % (EVMU256::MAX - EVMU256::from(1)) + EVMU256::from(1)
                    } else {
                        (v1 - v2) % (EVMU256::MAX - EVMU256::from(1)) + EVMU256::from(1)
                    };
                    let idx = interp.program_counter() % MAP_SIZE;
                    let cmp_map = { CMP_MAP.get_mut() };
                    if abs_diff < cmp_map[idx] {
                        cmp_map[idx] = abs_diff;
                    }
                }

                0x03 => {
                    // SUB. solc compiles a masked 160-bit `==`/`!=`
                    // between two addresses (e.g. `referral ==
                    // msg.sender`) down to a plain SUB + JUMPI on the
                    // (non-)zero result, NOT an EQ opcode -- confirmed
                    // live via `solc --asm` while building
                    // oracles/self_referral.rs's own test fixture. Same
                    // latch as the real comparison opcodes above.
                    latch_calldata_compare!(fast_peek!(0), fast_peek!(1));
                }

                0x04 => {
                    // DIV. Feeds oracles/precision_loss.rs: latch the
                    // result so a MUL (0x02) using it as an operand
                    // immediately after is recognized as the classic
                    // `(a / b) * c` ordering (lossy division before the
                    // scaling multiply), instead of `(a * c) / b`.
                    // The EVM defines `x / 0` as 0; guard the host-side
                    // division so a zero divisor cannot panic the fuzzer.
                    let divisor = fast_peek!(1);
                    let quotient = if divisor.is_zero() {
                        EVMU256::ZERO
                    } else {
                        fast_peek!(0) / divisor
                    };
                    self.current_last_div = Some((interp.program_counter(), quotient));
                }

                0x02 => {
                    // MUL. If one operand is the result of the DIV just
                    // seen, this is division-before-multiplication
                    // precision loss (see current_last_div above and
                    // oracles/precision_loss.rs). Restricted to a small
                    // pc window and to non-trivial results (>1) so
                    // multiplying by an incidental 0/1 divisor result
                    // can't register as a false positive.
                    if let Some((div_pc, div_res)) = self.current_last_div {
                        if div_res > EVMU256::from(1)
                            && interp.program_counter().saturating_sub(div_pc) <= 24
                        {
                            let v1 = fast_peek!(0);
                            let v2 = fast_peek!(1);
                            if v1 == div_res || v2 == div_res {
                                self.current_precision_losses
                                    .insert((interp.contract.address, interp.program_counter()));
                            }
                        }
                    }
                    self.current_last_div = None;
                }

                0x06 => {
                    // MOD. Feeds oracles/weak_randomness.rs: a modulo of
                    // a block-environment value (see current_last_env_read)
                    // is the canonical "pick a pseudo-random winner/index"
                    // shape (SWC-120).
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    if let Some((_pc, env_val)) = self.current_last_env_read {
                        if (v1 == env_val || v2 == env_val) && !v2.is_zero() {
                            self.current_weak_randomness_uses
                                .insert((interp.contract.address, interp.program_counter()));
                        }
                    }
                }

                // Block-environment reads (SWC-120 weak randomness). Latch
                // the value this opcode is about to push, so the next
                // MOD/AND/comparison that consumes it can be attributed.
                0x42 => {
                    // TIMESTAMP
                    self.current_last_env_read = Some((interp.program_counter(), self.env.block.timestamp));
                }
                0x43 => {
                    // NUMBER
                    self.current_last_env_read = Some((interp.program_counter(), self.env.block.number));
                }
                0x44 => {
                    // DIFFICULTY / PREVRANDAO
                    self.current_last_env_read = Some((interp.program_counter(), self.env.block.difficulty));
                }
                0x45 => {
                    // GASLIMIT
                    self.current_last_env_read = Some((interp.program_counter(), self.env.block.gas_limit));
                }
                0x48 => {
                    // BASEFEE
                    self.current_last_env_read = Some((interp.program_counter(), self.env.block.basefee));
                }

                0xfe => {
                    // INVALID. solc emits this for a failed `assert()`.
                    // oracles/assert_violation.rs (SWC-110): reaching it
                    // while the calling transaction carried non-empty
                    // calldata means an attacker-supplied input violated
                    // what the developer wrote as an internal invariant
                    // -- `assert` used for input validation, which burns
                    // ALL gas instead of refunding the remainder.
                    if !interp.contract.input.is_empty() {
                        self.current_assert_violations
                            .insert((interp.contract.address, interp.program_counter()));
                    }
                }

                0xfd => {
                    // REVERT. Solidity 0.8.x compiles `assert(x)` to a
                    // REVERT carrying the 4-byte Panic(uint256) selector
                    // 0x4e487b71 followed by the panic code 0x01 -- NOT to
                    // the INVALID (0xfe) opcode (verified live against
                    // tests/evm/assert_violation: solc 0.8.24 emits
                    // `REVERT` with panic code 1, plus a trailing 0xfe
                    // that is only the metadata-terminating byte, never
                    // executed). oracles/assert_violation.rs (SWC-110):
                    // record a reachable assertion when a revert on an
                    // input-carrying transaction is a Panic(0x01) --
                    // `assert` used for validation, which burns all
                    // remaining gas on failure instead of reverting
                    // cheaply.
                    if !interp.contract.input.is_empty() {
                        let offset = as_u64(fast_peek!(0)) as usize;
                        let len = as_u64(fast_peek!(1)) as usize;
                        if len >= 36 && interp.memory.len() >= offset + 36 {
                            let data = interp.memory.get_slice(offset, 36);
                            if data[0..4] == [0x4e, 0x48, 0x7b, 0x71]
                                && data[4..35].iter().all(|b| *b == 0)
                                && data[35] == 0x01
                            {
                                self.current_assert_violations.insert((
                                    interp.contract.address,
                                    interp.program_counter(),
                                ));
                            }
                        }
                    }
                }

                0xf1 | 0xf2 | 0xf4 | 0xfa => {
                    // oracles/transient_guard.rs: an external CALL executed
                    // while a TLOAD'd transient guard slot is unlocked --
                    // the guard's protection window closed before the
                    // external call, so it does not actually guard against
                    // reentrancy. Only CALL/STATICCALL (0xf1/0xf2); the
                    // DELEGATECALL/CALLCODE (0xf4/0xfa) share this arm but
                    // are not external-value reentrancy vectors in the same
                    // way, so restrict the hit to 0xf1/0xf2.
                    if matches!(*interp.instruction_pointer, 0xf1 | 0xf2) {
                        if let Some((addr, tstore_pc, slot)) = self.current_transient_unlock {
                            if self.current_transient_loaded.contains(&(addr, slot)) {
                                self.current_transient_unlock_calls.push((
                                    addr,
                                    tstore_pc,
                                    slot,
                                ));
                            }
                        }
                    }
                    let offset_of_ret_size: usize = match *interp.instruction_pointer {
                        0xf1 | 0xf2 => 6,
                        0xf4 | 0xfa => 5,
                        _ => unreachable!(),
                    };
                    {
                        RET_OFFSET.store(as_u64(fast_peek!(offset_of_ret_size - 1)) as usize, Ordering::Relaxed);
                        // debug!("RET_OFFSET: {}", RET_OFFSET.load(Ordering::Relaxed));
                        RET_SIZE.store(as_u64(fast_peek!(offset_of_ret_size)) as usize, Ordering::Relaxed);
                    }
                    self._pc = interp.program_counter();
                }
                0xf0 | 0xf5 | 0xa0..=0xa4 | 0xff => {
                    // CREATE, CREATE2
                    self._pc = interp.program_counter();
                }
                _ => {}
            }

            self.access_pattern.deref().borrow_mut().decode_instruction(interp);
        }
        Continue
    }

    fn step_end(
        &mut self,
        _interp: &mut Interpreter,
        _ret: InstructionResult,
        _: &mut EVMFuzzState,
    ) -> InstructionResult {
        Continue
    }

    fn env(&mut self) -> &mut Env {
        &mut self.env
    }

    fn load_account(&mut self, _address: EVMAddress) -> Option<(bool, bool)> {
        Some((
            true, true, // self.data.contains_key(&address) || self.code.contains_key(&address),
        ))
    }

    fn block_hash(&mut self, _number: EVMU256) -> Option<B256> {
        Some(B256::zero())
    }

    fn balance(&mut self, _address: EVMAddress) -> Option<(EVMU256, bool)> {
        #[cfg(feature = "real_balance")]
        {
            if let Some(balance) = self.evmstate.get_balance(&_address) {
                return Some((*balance, true));
            }
            self.evmstate.set_balance(_address, self.next_slot);
            Some((self.next_slot, true))
        }
        #[cfg(not(feature = "real_balance"))]
        {
            Some((EVMU256::MAX, true))
        }
    }

    fn code(&mut self, address: EVMAddress) -> Option<(Arc<BytecodeLocked>, bool)> {
        // debug!("code");
        match self.code.get(&address) {
            Some(code) => Some((code.clone(), true)),
            None => Some((Arc::new(BytecodeLocked::default()), true)),
        }
    }

    fn code_hash(&mut self, address: EVMAddress) -> Option<(B256, bool)> {
        match self.code.get(&address) {
            Some(code) => Some((code.hash(), true)),
            None => Some((B256::zero(), true)),
        }
    }

    fn sload(&mut self, address: EVMAddress, index: EVMU256) -> Option<(EVMU256, bool)> {
        if let Some(account) = self.evmstate.get_mut(&address) {
            if let Some(slot) = account.get(&index) {
                // println!("sload: {:?} -> {:?} = {:?}", address, index, slot);
                return Some((*slot, true));
            } else {
                account.insert(index, self.next_slot);
            }
        } else {
            let mut account = HashMap::new();
            account.insert(index, self.next_slot);
            self.evmstate.insert(address, account);
        }
        // println!("sload(c): {:?} -> {:?} = {:?}", address, index, self.next_slot);
        Some((self.next_slot, true))
    }

    fn sstore(
        &mut self,
        address: EVMAddress,
        index: EVMU256,
        value: EVMU256,
    ) -> Option<(EVMU256, EVMU256, EVMU256, bool)> {
        match self.evmstate.get_mut(&address) {
            Some(account) => {
                account.insert(index, value);
            }
            None => {
                let mut account = HashMap::new();
                account.insert(index, value);
                self.evmstate.insert(address, account);
            }
        };

        Some((EVMU256::from(0), EVMU256::from(0), EVMU256::from(0), true))
    }

    fn tload(&mut self, address: EVMAddress, index: EVMU256) -> EVMU256 {
        if let Some(slot) = self.transient_storage.get(&(address, index)) {
            *slot
        } else {
            self.transient_storage.insert((address, index), self.next_slot);
            self.next_slot
        }
    }

    fn tstore(&mut self, address: EVMAddress, index: EVMU256, value: EVMU256) {
        self.transient_storage.insert((address, index), value);
    }

    fn log(&mut self, _address: EVMAddress, _topics: Vec<B256>, _data: Bytes) {
        // flag check
        if _topics.len() == 1 {
            let current_flag = _topics.last().unwrap().0;
            // hex is "forksploit"
            if current_flag[0] == 0x66 &&
                current_flag[1] == 0x75 &&
                current_flag[2] == 0x7a &&
                current_flag[3] == 0x7a &&
                current_flag[4] == 0x6c &&
                current_flag[5] == 0x61 &&
                current_flag[6] == 0x6e &&
                current_flag[7] == 0x64 &&
                current_flag[8] == 0x00 &&
                current_flag[9] == 0x00 ||
                current_flag == SCRIBBLE_EVENT_HEX
            {
                let data_string = String::from_utf8(_data[64..].to_vec()).unwrap();
                if PANIC_ON_BUG.load(Ordering::Relaxed) {
                    panic!("target bug found: {}", data_string);
                }
                self.current_typed_bug
                    .push((data_string.trim_end_matches('\u{0}').to_string(), (_address, self._pc)));
            }
        }

        #[cfg(feature = "print_logs")]
        {
            let mut hasher = DefaultHasher::new();
            _data.to_vec().hash(&mut hasher);
            let h = hasher.finish();
            if self.logs.contains(&h) {
                return;
            }
            self.logs.insert(h);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            let timestamp = now.as_nanos();
            debug!("log@{} {:?}", timestamp, hex::encode(_data));
        }
    }

    fn selfdestruct(&mut self, _address: EVMAddress, _target: EVMAddress) -> Option<SelfDestructResult> {
        self.current_self_destructs.push((_address, self._pc));
        Some(SelfDestructResult::default())
    }

    fn create(
        &mut self,
        inputs: &mut CreateInputs,
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Option<EVMAddress>, Gas, Bytes) {
        if IN_DEPLOY.load(Ordering::Relaxed) {
            // todo: use nonce + hash instead
            let r_addr = generate_random_address(state);

            // update local balance
            // for create we don't check sender balance
            // todo: only disable checking in setUp
            let value = EVMU256::from(inputs.value);
            if cfg!(feature = "real_balance") && value != EVMU256::ZERO {
                let receiver = r_addr;
                if let Some(balance) = self.evmstate.get_balance(&receiver) {
                    self.evmstate.set_balance(receiver, *balance + value);
                } else {
                    self.evmstate.set_balance(receiver, self.next_slot + value);
                };
            }

            let mut interp = Interpreter::new_with_memory_limit(
                Contract::new_with_context(
                    Bytes::new(),
                    Bytecode::new_raw(inputs.init_code.clone()),
                    &CallContext {
                        address: r_addr,
                        caller: inputs.caller,
                        code_address: r_addr,
                        apparent_value: inputs.value,
                        scheme: CallScheme::Call,
                    },
                ),
                1e10 as u64,
                false,
                MEM_LIMIT,
            );
            let ret = self.run_inspect(&mut interp, state);
            debug!("create: {:?} -> {:?} = {:?}", inputs.caller, r_addr, ret);
            if !is_reverted_or_control_leak(&ret) {
                let runtime_code: Bytes = interp.return_value();
                self.set_code(r_addr, Bytecode::new_raw(runtime_code.clone()), state);
                if !SETCODE_ONLY.load(Ordering::Relaxed) {
                    // now we build & insert abi
                    let contract_code_str = hex::encode(&runtime_code);
                    let sigs = extract_sig_from_contract(&contract_code_str);
                    let mut unknown_sigs: usize = 0;
                    let mut parsed_abi = vec![];
                    for sig in &sigs {
                        if let Some(abi) = state.metadata_map().get::<ABIMap>().unwrap().get(sig) {
                            parsed_abi.push(abi.clone());
                        } else {
                            unknown_sigs += 1;
                        }
                    }

                    if unknown_sigs >= sigs.len() / 30 {
                        debug!("Too many unknown function signature for newly created contract, we are going to decompile this contract using EVMole");
                        let abis = fetch_abi_evmole(&runtime_code)
                            .iter()
                            .map(|abi| {
                                if let Some(known_abi) =
                                    state.metadata_map().get::<ABIMap>().unwrap().get(&abi.function)
                                {
                                    known_abi
                                } else {
                                    abi
                                }
                            })
                            .cloned()
                            .collect_vec();
                        parsed_abi = abis;
                    }
                    // notify flashloan and blacklisting flashloan addresses
                    handle_contract_insertion!(state, self, r_addr, r_addr, parsed_abi);

                    parsed_abi.iter().filter(|v| !v.is_constructor).for_each(|abi| {
                        #[cfg(not(feature = "fuzz_static"))]
                        if abi.is_static {
                            return;
                        }

                        let mut abi_instance = get_abi_type_boxed(&abi.abi);
                        abi_instance.set_func_with_signature(abi.function, &abi.function_name, &abi.abi);
                        register_abi_instance(r_addr, abi_instance.clone(), state);

                        let input = EVMInput {
                            caller: state.get_rand_caller(),
                            contract: r_addr,
                            data: Some(abi_instance),
                            sstate: StagedVMState::new_uninitialized(),
                            sstate_idx: 0,
                            txn_value: if abi.is_payable { Some(EVMU256::ZERO) } else { None },
                            step: false,
                            env: Default::default(),
                            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                            liquidation_percent: 0,
                            input_type: EVMInputTy::ABI,
                            direct_data: Default::default(),
                            randomness: vec![0],
                            repeat: 1,
                            swap_data: HashMap::new(),
                        };
                        add_corpus(self, state, &input);
                    });
                }
                (Continue, Some(r_addr), Gas::new(0), runtime_code)
            } else {
                (ret, Some(r_addr), Gas::new(0), Bytes::new())
            }
        } else {
            (InstructionResult::Revert, None, Gas::new(0), Bytes::new())
        }
    }

    // oracles/revert_in_loop.rs (SWC-113): bookkeeping for one execution of
    // an outgoing CALL site. Counted per (address, pc): a site executed 2+
    // times in the same call is unambiguously inside a loop, and if any of
    // those executions failed, the loop re-runs a call that a recipient
    // made fail -- the push-payment DoS shape. This must run for EVERY
    // execution path (including the insufficient-balance early return
    // below), otherwise a fuzzer-model balance failure silently hides the
    // loop. Called with the *outer* interpreter's pc, which is the CALL
    // opcode's own pc.

    fn call(
        &mut self,
        input: &mut CallInputs,
        interp: &mut Interpreter,
        output_info: (usize, usize),
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Gas, Bytes) {
        self.apply_prank(&interp.contract().caller, input);
        self.call_depth += 1;

        // oracles/gas_stipend.rs (SWC-134): an outgoing CALL made with a
        // hardcoded, LOW gas stipend -- the `.transfer()`/`.send()` shape
        // (EIP-150's 2300 gas, forwarded verbatim by solc). A callee whose
        // fallback/receive needs more than that (e.g. WETH9's own
        // `transfer()`, which this project hit live) silently reverts.
        // 2300 is the classic value; the small ceiling catches `.send()`
        // and any other deliberately-tiny literal.
        if input.gas_limit > 0 && input.gas_limit <= 2300 {
            self.current_hardcoded_gas_stipends.insert((
                interp.contract().address,
                interp.program_counter(),
                input.gas_limit,
            ));
        }

        // Register this execution of the call site before any early
        // return, so a model-level failure (e.g. insufficient balance
        // below) is still counted -- see note_outgoing_call.
        let call_key = (interp.contract().address, interp.program_counter());
        {
            let seen = self.current_call_site_counts.entry(call_key).or_insert(0);
            *seen += 1;
        }

        let value = EVMU256::from(input.transfer.value);

        // Self-referral / validation-bypass payment signal (see
        // oracles/self_referral.rs): this outgoing, value-carrying CALL's
        // target is one of THIS call's own address-type arguments (see the
        // 0x35 CALLDATALOAD case above) -- i.e. money is flowing straight
        // to a caller-supplied address, not one derived from storage/logic.
        if value != EVMU256::ZERO && self.current_calldata_addresses.contains(&input.transfer.target) {
            self.current_paid_calldata_addresses.insert(input.transfer.target);
        }

        if cfg!(feature = "real_balance") && value != EVMU256::ZERO {
            let sender = input.transfer.source;
            debug!("call sender: {:?}", sender);
            let current = if let Some(balance) = self.evmstate.get_balance(&sender) {
                *balance
            } else {
                self.evmstate.set_balance(sender, self.next_slot);
                self.next_slot
            };
            // debug!("call sender balance: {}", current);
            if current < value {
                self.note_outgoing_call_outcome(call_key, false);
                return (Revert, Gas::new(0), Bytes::new());
            }
            self.evmstate.set_balance(sender, current - value);

            let receiver = input.transfer.target;
            if let Some(balance) = self.evmstate.get_balance(&receiver) {
                self.evmstate.set_balance(receiver, *balance + value);
            } else {
                self.evmstate.set_balance(receiver, self.next_slot + value);
            };
        }

        let mut res = if is_precompile(input.contract, self.precompiles.len()) {
            self.call_precompile(input, state)
        } else if control_leak_bypassed() {
            self.call_forbid_control_leak(input, state)
        } else {
            self.call_allow_control_leak(input, interp, output_info, state)
        };

        let ret_buffer = res.2.clone();

        self.call_depth -= 1;
        res = self.check_expected(input, res);
        self.clean_prank();

        self.last_call_scheme = input.context.scheme;
        self.last_call_success = !is_reverted_or_control_leak(&res.0);

        // The execution count was registered up-front (see call_key above);
        // record the outcome of this execution now.
        self.note_outgoing_call_outcome(call_key, self.last_call_success);

        // Feeds oracles/token_accounting_mismatch.rs (SWC-unlisted but a
        // real, repeated real-world DeFi bug class: fee-on-transfer/
        // rebasing token incompatibility). A successful
        // `transferFrom(from, address(this), amount)` pulls tokens INTO
        // this contract; `amount` is what the CALLER asked to move, not
        // necessarily what actually arrived (a fee-on-transfer token
        // deducts a cut; a rebasing token's balance can differ from the
        // naive transferred amount entirely). Latching (token, amount)
        // here lets the 0x55 SSTORE case below check whether the very
        // next accounting write literally adds this UNVERIFIED `amount`
        // to a prior SLOAD'd balance, instead of the REAL observed
        // balance delta (a `balanceOf(address(this))` read before/after).
        // oracles/readonly_reentrancy.rs: did this call re-query a
        // (target, selector) that was already baselined at
        // control-leak depth 0 earlier in THIS transaction, and get a
        // DIFFERENT return value while a control-leak is now pending
        // (depth > 0)? Applies to any call scheme (CALL or STATICCALL --
        // not every "view" function is actually marked `view` on-chain).
        if self.last_call_success && input.input.len() >= 4 {
            let selector: [u8; 4] = [input.input[0], input.input[1], input.input[2], input.input[3]];
            let key = (input.contract, selector);
            let depth = self.evmstate.post_execution.len();
            if depth == 0 {
                self.view_call_baseline.insert(key, ret_buffer.to_vec());
            } else if let Some(baseline) = self.view_call_baseline.get(&key) {
                if !ret_buffer.is_empty() && baseline.as_slice() != ret_buffer.as_ref() {
                    self.current_readonly_reentrancy_hits
                        .insert((interp.contract.address, interp.program_counter()));
                }
            }
        }

        if self.last_call_success && input.context.scheme == CallScheme::Call && input.input.len() >= 100 {
            let selector = &input.input[0..4];
            if selector == [0x23, 0xb8, 0x72, 0xdd] {
                let to = convert_u256_to_h160(EVMU256::from_be_slice(&input.input[36..68]));
                if to == interp.contract.address {
                    let amount = EVMU256::from_be_slice(&input.input[68..100]);
                    self.current_pending_token_transfer_in = Some((input.contract, amount));
                }
            }
        }

        unsafe {
            if self.middlewares_enabled {
                let mut middlewares = self.middlewares.read().unwrap().clone();
                for middleware in middlewares.iter_mut() {
                    middleware
                        .deref()
                        .borrow_mut()
                        .on_return(interp, self, state, &ret_buffer);
                }
            }
        }
        res
    }
}

#[cfg(test)]
mod harvest_tests {
    use super::*;

    /// The structured provenance record must survive a round trip and
    /// answer exactly the three questions the report needs: WHO was
    /// harvested, on WHICH contract, out of WHICH slot. Also pins the
    /// "first writer wins" rule -- a later read of the same identity must
    /// not overwrite the first, most specific provenance.
    #[test]
    fn test_harvested_origin_round_trip() {
        // A distinct address per run so a parallel test can't collide.
        let addr = EVMAddress::from_slice(&[
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let contract = EVMAddress::from_slice(&[
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11,
        ]);
        let key = EVMU256::from(0u64);
        record_harvested_storage_address(&addr, &contract, key);

        let checksummed = checksum(&addr);
        assert!(is_harvested_storage_address(&checksummed));
        let (got_contract, got_slot) =
            harvested_address_origin(&checksummed).expect("origin must be recorded");
        assert_eq!(got_contract, checksum(&contract));
        assert_eq!(got_slot, format!("0x{:064x}", EVMU256::from(0u64)));

        // A later read from a DIFFERENT contract/slot must not overwrite
        // the first provenance (first writer wins).
        let other = EVMAddress::from_slice(&[0x22u8; 20]);
        record_harvested_storage_address(&addr, &other, EVMU256::from(7u64));
        let (got_contract2, _) = harvested_address_origin(&checksummed).unwrap();
        assert_eq!(got_contract2, checksum(&contract), "first provenance must win");
    }

    #[test]
    fn test_unharvested_address_has_no_origin() {
        let addr = EVMAddress::from_slice(&[0x99u8; 20]);
        assert!(!is_harvested_storage_address(&checksum(&addr)));
        assert!(harvested_address_origin(&checksum(&addr)).is_none());
    }

    /// FAZA 3.2: the semantic owner-gated pairing. An identity is a
    /// privileged sender FOR a contract only when it was harvested from
    /// THAT contract's own storage -- not merely from some target.
    #[test]
    fn test_harvested_sender_guard_is_contract_scoped() {
        let owner = EVMAddress::from_slice(&[0xaa; 20]);
        let target = EVMAddress::from_slice(&[0xbb; 20]);
        let unrelated = EVMAddress::from_slice(&[0xcc; 20]);
        record_harvested_storage_address(&owner, &target, EVMU256::from(0u64));

        let owner_cs = checksum(&owner);
        let target_cs = checksum(&target);
        let unrelated_cs = checksum(&unrelated);

        // Harvested from target -> privileged sender FOR target ...
        assert!(is_harvested_sender_for(&target_cs, &owner_cs));
        // ... but NOT for a different contract (the address is not that
        // contract's own stored identity).
        assert!(!is_harvested_sender_for(&unrelated_cs, &owner_cs));
        // ... and an address never harvested is privileged for nobody.
        assert!(!is_harvested_sender_for(&target_cs, &unrelated_cs));
    }
}

#[cfg(test)]
mod control_leak_bypass_tests {
    use super::*;

    /// FAZA 2.4: the concolic stage must be able to force every call through
    /// the REAL callee (`call_forbid_control_leak`), never the leak path.
    /// Asserted as an implication, not an absolute false, so a parallel test
    /// that happens to hold a fast-call flag cannot make this flaky: the
    /// concolic flag must force `true`, and clearing it must restore exactly
    /// the decision that held before.
    #[test]
    fn concolic_flag_forces_control_leak_bypass() {
        let prior = CONCOLIC_NO_CONTROL_LEAK.load(Ordering::Relaxed);
        let before = control_leak_bypassed();

        CONCOLIC_NO_CONTROL_LEAK.store(true, Ordering::Relaxed);
        assert!(
            control_leak_bypassed(),
            "concolic must route calls to the real callee, not the leak path"
        );

        CONCOLIC_NO_CONTROL_LEAK.store(prior, Ordering::Relaxed);
        assert_eq!(
            control_leak_bypassed(),
            before,
            "clearing the concolic flag must restore the prior dispatch decision"
        );
    }
}

#[cfg(test)]
mod call_until_guard_tests {
    use super::*;

    /// The replay-time `CALL_UNTIL` boundary is process-global; the guard must
    /// leave it exactly as it found it, whatever it was, even when the guarded
    /// section mutates it (which is what a replay does). Written relative to
    /// the observed value so it is robust to whatever the initial state is.
    #[test]
    fn call_until_guard_restores_previous_value() {
        let before = CALL_UNTIL.load(Ordering::Relaxed);

        {
            let _g = CallUntilGuard::set(3);
            assert_eq!(CALL_UNTIL.load(Ordering::Relaxed), 3, "set() must apply the value");
        }
        assert_eq!(CALL_UNTIL.load(Ordering::Relaxed), before, "drop must restore the prior value");

        let mid = CALL_UNTIL.load(Ordering::Relaxed);
        {
            let _g = CallUntilGuard::preserve();
            assert_eq!(CALL_UNTIL.load(Ordering::Relaxed), mid, "preserve() must not change the value");
            // Simulate a replay mutating the global mid-section.
            CALL_UNTIL.store(99, Ordering::Relaxed);
        }
        assert_eq!(CALL_UNTIL.load(Ordering::Relaxed), mid, "preserve() must restore on drop");
    }
}
