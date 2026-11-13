//! Declarative, user-configurable invariant oracle.
//!
//! Every other economic oracle in this crate hard-codes ONE pattern
//! (`eth_backing` only knows `balances(address)`; `unbacked_mint` only knows
//! `totalSupply()`; `token_accounting_mismatch` only knows one
//! `transferFrom`-then-SSTORE shape). A target whose economic promise does
//! not match one of those fingerprints is simply not checked -- and a NEW or
//! COMPOSED bug is invisible until someone writes another Rust oracle.
//!
//! This oracle closes that gap the way a user actually needs it: the
//! invariant is written in a JSON file, not in Rust. The fuzzer evaluates it
//! after every non-reverted transaction and reports a violation the moment
//! it holds.
//!
//! File format (`--invariants invariant.json`):
//! ```json
//! { "invariants": [
//!   { "name": "balances never exceed supply",
//!     "op": "le",
//!     "lhs": { "sum_over_callers": { "sig": "balanceOf(address)" } },
//!     "rhs": { "call": { "sig": "totalSupply()" } } },
//!   { "name": "vault solvent",
//!     "op": "le",
//!     "lhs": { "sum_over_callers": { "sig": "balances(address)" } },
//!     "rhs": { "native_balance": true } }
//! ] }
//! ```
//!
//! Operands:
//! - `{"native_balance": true}` -- the target's real native-token balance.
//! - `{"literal": "1000"}` -- a decimal or `0x`-hex constant.
//! - `{"call": {"sig": "...", "args": ["$caller", "0x..", "123"]}}` -- one
//!   static call; `$caller` is the transaction's caller.
//! - `{"sum_over_callers": {"sig": "balanceOf(address)"}}` -- the named call
//!   evaluated once per observed caller and summed (the call must take
//!   exactly one `address`, supplied automatically).
//!
//! Ops: `le`, `lt`, `ge`, `gt`, `eq`, `ne`.
//!
//! A violation is reported as bug_type `"Invariant Violation"` with the
//! user's own `name` in the detail, at `sim-confirmed` tier: it is a
//! directly observed state, not an inference.

use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
    ops::Deref,
};

use alloy_dyn_abi::{DynSolValue, JsonAbiExt, Specifier};
use alloy_json_abi::Function;
use bytes::Bytes;
use revm_primitives::Bytecode;
use serde::Deserialize;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::INVARIANT_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::VMInputT,
    oracle::Oracle,
    state::HasExecutionResult,
};

/// A single view-call template.
#[derive(Debug, Clone, Deserialize)]
pub struct CallSpec {
    pub sig: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// One operand of a comparison.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operand {
    #[serde(default)]
    pub native_balance: Option<bool>,
    #[serde(default)]
    pub literal: Option<String>,
    #[serde(default)]
    pub call: Option<CallSpec>,
    #[serde(default)]
    pub sum_over_callers: Option<CallSpec>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CmpOp {
    Le,
    Lt,
    Ge,
    Gt,
    Eq,
    Ne,
}

impl CmpOp {
    fn holds(self, lhs: EVMU256, rhs: EVMU256) -> bool {
        match self {
            CmpOp::Le => lhs <= rhs,
            CmpOp::Lt => lhs < rhs,
            CmpOp::Ge => lhs >= rhs,
            CmpOp::Gt => lhs > rhs,
            CmpOp::Eq => lhs == rhs,
            CmpOp::Ne => lhs != rhs,
        }
    }
}

/// One user-declared invariant.
#[derive(Debug, Clone, Deserialize)]
pub struct Invariant {
    pub name: String,
    pub op: CmpOp,
    pub lhs: Operand,
    pub rhs: Operand,
}

/// The parsed contents of an invariant file.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct InvariantSpec {
    #[serde(default)]
    pub invariants: Vec<Invariant>,
}

impl InvariantSpec {
    pub fn from_file(path: &str) -> Option<Self> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to read invariants file {}: {}", path, e);
                return None;
            }
        };
        match serde_json::from_str::<InvariantSpec>(&content) {
            Ok(spec) => Some(spec),
            Err(e) => {
                tracing::error!("Failed to parse invariants file {}: {}", path, e);
                None
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }
}

/// Build calldata for `spec` with `addr` (if any) supplied as the sole
/// address argument. Returns `None` on any parse/encode failure so a bad
/// declaration is skipped, never fatal.
fn encode_call(spec: &CallSpec, addr: Option<EVMAddress>, caller: EVMAddress) -> Option<Bytes> {
    let function = Function::parse(&spec.sig).ok()?;

    // The `sum_over_callers` form always supplies exactly one address.
    let raw_args: Vec<String> = if let Some(a) = addr {
        if function.inputs.len() != 1 {
            return None;
        }
        vec![format!("0x{}", hex::encode(a))]
    } else {
        if function.inputs.len() != spec.args.len() {
            return None;
        }
        spec.args
            .iter()
            .map(|raw| match raw.as_str() {
                "$caller" => format!("0x{}", hex::encode(caller)),
                "$zero" => format!("0x{}", "00".repeat(20)),
                other => other.to_string(),
            })
            .collect()
    };

    let mut values: Vec<DynSolValue> = Vec::with_capacity(raw_args.len());
    for (resolved, param) in raw_args.iter().zip(function.inputs.iter()) {
        let ty = param.resolve().ok()?;
        let v = ty.coerce_str(resolved).ok()?;
        values.push(v);
    }
    function.abi_encode_input(&values).ok().map(Bytes::from)
}

fn word_to_u256(raw: &[u8]) -> Option<EVMU256> {
    if raw.len() != 32 {
        return None;
    }
    EVMU256::try_from_be_slice(raw)
}

/// Evaluate one operand to a concrete value. `None` means "could not be
/// evaluated" (call reverted, bad declaration) -- the invariant is skipped,
/// never falsely reported.
fn eval_operand(
    operand: &Operand,
    target: EVMAddress,
    caller: EVMAddress,
    callers: &[EVMAddress],
    native_balance: EVMU256,
    executor: &mut EVMQueueExecutor,
    post_state: &EVMState,
    fuzz_state: &mut EVMFuzzState,
) -> Option<EVMU256> {
    if operand.native_balance.unwrap_or(false) {
        return Some(native_balance);
    }
    if let Some(lit) = &operand.literal {
        let lit = lit.trim();
        return if let Some(hex) = lit.strip_prefix("0x") {
            EVMU256::from_str_radix(hex, 16).ok()
        } else {
            EVMU256::from_str_radix(lit, 10).ok()
        };
    }
    if let Some(call) = &operand.call {
        let data = encode_call(call, None, caller)?;
        let probes = [(target, data)];
        let out = executor.fast_static_call(&probes, post_state, fuzz_state);
        return word_to_u256(out.first()?);
    }
    if let Some(call) = &operand.sum_over_callers {
        if callers.is_empty() {
            return None;
        }
        let probes: Vec<(EVMAddress, Bytes)> = callers
            .iter()
            .filter_map(|c| encode_call(call, Some(*c), caller).map(|d| (target, d)))
            .collect();
        if probes.is_empty() {
            return None;
        }
        let out = executor.fast_static_call(&probes, post_state, fuzz_state);
        let mut sum = EVMU256::ZERO;
        let mut answered = false;
        for raw in &out {
            if let Some(v) = word_to_u256(raw) {
                answered = true;
                sum = sum.saturating_add(v);
            }
        }
        return answered.then_some(sum);
    }
    None
}

/// The declarative-invariant oracle. Holds the user's spec and the callers
/// observed so far per target (so `sum_over_callers` has a holder set).
pub struct InvariantOracle {
    spec: InvariantSpec,
    known_callers: RefCell<HashMap<EVMAddress, HashSet<EVMAddress>>>,
    reported: RefCell<HashSet<(EVMAddress, String)>>,
}

impl InvariantOracle {
    pub fn new(spec: InvariantSpec) -> Self {
        Self {
            spec,
            known_callers: RefCell::new(HashMap::new()),
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
    > for InvariantOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        if self.spec.is_empty() {
            return vec![];
        }
        // A control-leak (post-execution) state is an INTERMEDIATE state --
        // feedback.rs's OracleFeedback unconditionally discards any oracle()
        // result produced on it (see its `has_post_exec` check). The invariant
        // below would still evaluate on such a state (its post-state can even
        // violate a real invariant) and, worse, insert into `reported` --
        // permanently suppressing that invariant for the WHOLE run, so the
        // real, finished execution that would surface it never does. Bail out
        // before touching `reported`, exactly like the sibling oracles
        // (curve_virtual_price, erc20, ...).
        if ctx.fuzz_state.get_execution_result().new_state.state.has_post_execution() {
            return vec![];
        }
        let target = ctx.input.get_contract();
        let caller = ctx.input.get_caller();
        self.known_callers
            .borrow_mut()
            .entry(target)
            .or_default()
            .insert(caller);

        let callers: Vec<EVMAddress> = self
            .known_callers
            .borrow()
            .get(&target)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();

        let native_balance = ctx.post_state.balance.get(&target).copied().unwrap_or(EVMU256::ZERO);

        let mut violations = vec![];
        for inv in &self.spec.invariants {
            let key = (target, inv.name.clone());
            if self.reported.borrow().contains(&key) {
                continue;
            }

            // Snapshot executor/state access: `ctx.executor` is a shared
            // Rc<RefCell<..>>; borrow it once per operand.
            let mut exec = ctx.executor.deref().borrow_mut();
            let lhs = eval_operand(
                &inv.lhs, target, caller, &callers, native_balance, &mut exec,
                &ctx.post_state, ctx.fuzz_state,
            );
            let rhs = eval_operand(
                &inv.rhs, target, caller, &callers, native_balance, &mut exec,
                &ctx.post_state, ctx.fuzz_state,
            );
            drop(exec);

            let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
                continue;
            };
            // `holds` describes the REQUIRED relationship; a false result is
            // the violation we report.
            if inv.op.holds(lhs, rhs) {
                continue;
            }

            self.reported.borrow_mut().insert(key);

            let mut hasher = DefaultHasher::new();
            target.hash(&mut hasher);
            inv.name.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + INVARIANT_BUG_IDX;

            EVMBugResult::new_simple(
                "Invariant Violation".to_string(),
                bug_idx,
                format!(
                    "User-declared invariant '{}' is violated on {:?}: lhs={:?} {:?} rhs={:?} does not hold (caller {:?}). This is a directly observed post-transaction state, not an inference.\n",
                    inv.name, target, lhs, inv.op, rhs, caller
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();

            violations.push(bug_idx);
        }
        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_spec() {
        let json = r#"{
            "invariants": [
              { "name": "solvent", "op": "le",
                "lhs": { "sum_over_callers": { "sig": "balances(address)" } },
                "rhs": { "native_balance": true } },
              { "name": "supply", "op": "eq",
                "lhs": { "literal": "1000" },
                "rhs": { "call": { "sig": "totalSupply()" } } }
            ]
        }"#;
        let spec: InvariantSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.invariants.len(), 2);
        assert!(matches!(spec.invariants[0].op, CmpOp::Le));
        assert!(spec.invariants[0].lhs.sum_over_callers.is_some());
        assert_eq!(spec.invariants[0].rhs.native_balance, Some(true));
    }

    #[test]
    fn cmp_ops_behave() {
        assert!(CmpOp::Le.holds(EVMU256::from(1), EVMU256::from(2)));
        assert!(!CmpOp::Le.holds(EVMU256::from(3), EVMU256::from(2)));
        assert!(CmpOp::Eq.holds(EVMU256::from(2), EVMU256::from(2)));
        assert!(CmpOp::Ne.holds(EVMU256::from(2), EVMU256::from(3)));
        assert!(CmpOp::Gt.holds(EVMU256::from(3), EVMU256::from(2)));
        assert!(CmpOp::Ge.holds(EVMU256::from(2), EVMU256::from(2)));
        assert!(CmpOp::Lt.holds(EVMU256::from(1), EVMU256::from(2)));
    }

    #[test]
    fn encodes_call_with_caller_placeholder() {
        let spec = CallSpec { sig: "balanceOf(address)".to_string(), args: vec!["$caller".to_string()] };
        let caller = EVMAddress::from_slice(&[0x11u8; 20]);
        let data = encode_call(&spec, None, caller).expect("encode");
        // selector(4) + 32-byte word
        assert_eq!(data.len(), 36);
        // last 20 bytes are the caller
        assert_eq!(&data[16..36], caller.as_slice());
    }

    #[test]
    fn encodes_sum_over_callers_auto_address() {
        let spec = CallSpec { sig: "balanceOf(address)".to_string(), args: vec![] };
        let holder = EVMAddress::from_slice(&[0x22u8; 20]);
        let data = encode_call(&spec, Some(holder), EVMAddress::from_slice(&[0u8; 20])).expect("encode");
        assert_eq!(data.len(), 36);
        assert_eq!(&data[16..36], holder.as_slice());
    }

    #[test]
    fn rejects_bad_signature() {
        let spec = CallSpec { sig: "not a signature".to_string(), args: vec![] };
        assert!(encode_call(&spec, None, EVMAddress::from_slice(&[0u8; 20])).is_none());
    }
}
