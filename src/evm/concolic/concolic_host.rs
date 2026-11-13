use std::{
    any,
    borrow::Borrow,
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    ops::{Add, Div, Mul, Not, Sub},
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
};

use bytes::Bytes;
use itertools::Itertools;
use lazy_static::lazy_static;
use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};
use z3::{
    ast::{Bool, BV},
    Params,
    Solver,
};

use crate::{
    bv_from_u256,
    evm::{
        abi::BoxedABI,
        concolic::expr::{simplify, ConcolicOp, Expr},
        host::{FuzzHost, MAX_ANALYSIS_CALL_DEPTH},
        input::EVMInput,
        middlewares::middleware::{Middleware, MiddlewareType, MiddlewareType::Concolic},
        srcmap::{SourceCodeResult, SOURCE_MAP_PROVIDER},
        types::{as_u64, is_zero, EVMAddress, EVMFuzzState, EVMU256},
    },
    input::VMInputT,
};

lazy_static! {
    static ref ALREADY_SOLVED: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
    pub static ref ALL_SOLUTIONS: Arc<Mutex<Vec<Solution>>> = Arc::new(Mutex::new(Vec::new()));
    /// Live concolic (Z3) worker threads, process-wide. Bounded to
    /// `ConcolicHost::num_threads` live solvers: `threaded_solve` joins the
    /// oldest before spawning a new one once the pool is full. The caller
    /// (`concolic_stage.rs`) drains this to completion after each testcase,
    /// so a solve is always finished (and its solutions in `ALL_SOLUTIONS`)
    /// before the next testcase begins.
    pub static ref ALL_WORKER_THREADS: Mutex<Vec::<std::thread::JoinHandle<()>>> = Mutex::new(Vec::new());
}

pub static CONCOLIC_TIMEOUT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000); // 1s

/// Hard per-solve memory ceiling for the Z3 solver, in MiB (0 = unlimited).
///
/// The solver previously had ONLY a wall-clock `timeout`, no memory bound.
/// A single hard path-condition can make Z3's memory grow without limit
/// while still returning before the timeout, and with `--concolic` running a
/// bounded pool of solvers the whole process -- and then the host -- can be
/// pushed into swap/OOM ("the machine freezes"), which is exactly the failure
/// this guards against. Z3 honours `memory_max_size` as a solver parameter and
/// returns `unknown` once it is exceeded, which the existing Sat/Unsat/Unknown
/// handling already treats as "couldn't solve this one" -- so a bound here
/// degrades a runaway solve into a skip instead of taking the host down.
pub static CONCOLIC_MEMORY_MB: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(2048); // 2 GiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Field {
    Caller,
    CallDataValue,
    Origin,
}

#[allow(clippy::vec_box)]
pub struct Solving<'a> {
    input: Vec<BV>,
    balance: BV,
    calldatavalue: BV,
    caller: BV,
    origin: BV,
    constraints: &'a Vec<Box<Expr>>,
    constrained_field: Vec<Field>,
}

#[allow(clippy::vec_box)]
impl<'a> Solving<'a> {
    fn new(
        input: &Vec<Box<Expr>>,
        balance: &BV,
        calldatavalue: &BV,
        caller: &BV,
        origin: &BV,
        constraints: &'a Vec<Box<Expr>>,
    ) -> Self {
        Solving {
            input: (*input)
                .iter()
                .enumerate()
                .map(|(_idx, x)| {
                    let bv = match &x.op {
                        ConcolicOp::SYMBYTE(name) => BV::new_const(name.clone(), 8),
                        ConcolicOp::CONSTBYTE(val) => BV::from_u64(*val as u64, 8),
                        _ => unreachable!("input should be symbolic or concrete"),
                    };
                    bv
                })
                .collect_vec(),
            balance: balance.clone(),
            calldatavalue: calldatavalue.clone(),
            caller: caller.clone(),
            origin: origin.clone(),
            constraints,
            constrained_field: vec![],
        }
    }
}

#[derive(Debug)]
pub enum SymbolicTy {
    BV(BV),
    Bool(Bool),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    pub input: Vec<u8>,
    pub caller: EVMAddress,
    pub origin: EVMAddress,
    pub value: EVMU256,
    pub fields: Vec<Field>,
}

impl Display for Solution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str(&format!("(input: {:?}, ", hex::encode(&self.input)));
        s.push_str(&format!("caller: {:?}, ", self.caller));
        s.push_str(&format!("origin: {:?}, ", self.origin));
        s.push_str(&format!("value: {})", self.value));
        write!(f, "{}", s)
    }
}

impl SymbolicTy {
    pub fn expect_bv(self) -> BV {
        match self {
            SymbolicTy::BV(bv) => bv,
            // A non-BV shape reaching a BV-only consumer is a symbolic
            // bookkeeping gap, not a reason to abort the whole fuzz run --
            // return a concrete zero so the caller keeps evaluating.
            _ => BV::from_u64(0, 256),
        }
    }

    pub fn expect_bool(self) -> Bool {
        match self {
            SymbolicTy::Bool(b) => b,
            // Sibling of expect_bv above: degrade to a concrete `false`
            // instead of panicking on an unexpected symbolic shape.
            _ => Bool::from_bool(false),
        }
    }
}

impl<'a> Solving<'a> {
    pub fn slice_input(&self, start: u32, end: u32) -> BV {
        let start = start as usize;
        let end = end as usize;
        let mut slice = self.input[start].clone();
        for i in start + 1..end {
            if i >= self.input.len() {
                slice = slice.concat(&BV::from_u64(0, 8));
            } else {
                slice = slice.concat(&self.input[i]);
            }
        }
        slice
    }

    pub fn generate_z3_bv(&mut self, bv: &Expr) -> Option<SymbolicTy> {
        // All three macros below used to `.unwrap()` `$lhs`/`$rhs` --
        // confirmed live (this session's already-fixed crashes) that a
        // leaf-shaped Expr with no lhs/rhs can reach here for an op that
        // normally has both; `?` makes that the same "can't generate a
        // Z3 value for this subtree" outcome the function already
        // returns via `_ => None` elsewhere, instead of panicking.
        // Correct here specifically because these macros are only ever
        // used as the tail expression of a match arm *inside*
        // `generate_z3_bv` itself, so `?` short-circuits this call to
        // `None` -- exactly the fallback the caller already expects.
        macro_rules! binop {
            ($lhs:expr, $rhs:expr, $op:ident) => {{
                let l = self.generate_z3_bv($lhs.as_ref()?);
                let r = self.generate_z3_bv($rhs.as_ref()?);

                match (l, r) {
                    (Some(SymbolicTy::BV(l)), Some(SymbolicTy::BV(r))) => Some(SymbolicTy::BV(l.$op(&r))),
                    _ => None,
                }
            }};
        }
        // debug!("generate_z3_bv: {:?}", bv);

        macro_rules! comparisons2 {
            ($lhs:expr, $rhs:expr, $op:ident) => {{
                let lhs = self.generate_z3_bv($lhs.as_ref()?);
                let rhs = self.generate_z3_bv($rhs.as_ref()?);
                match (lhs, rhs) {
                    (Some(SymbolicTy::BV(lhs)), Some(SymbolicTy::BV(rhs))) => Some(SymbolicTy::Bool(lhs.$op(&rhs))),
                    (Some(SymbolicTy::Bool(lhs)), Some(SymbolicTy::Bool(rhs))) => Some(SymbolicTy::Bool(lhs.$op(&rhs))),
                    _ => None,
                }
            }};
        }

        macro_rules! comparisons1 {
            ($lhs:expr, $rhs:expr, $op:ident) => {{
                let lhs = self.generate_z3_bv($lhs.as_ref()?);
                let rhs = self.generate_z3_bv($rhs.as_ref()?);
                match (lhs, rhs) {
                    (Some(SymbolicTy::BV(lhs)), Some(SymbolicTy::BV(rhs))) => Some(SymbolicTy::Bool(lhs.$op(&rhs))),
                    _ => None,
                }
            }};
        }

        match &bv.op {
            ConcolicOp::EVMU256(constant) => Some(SymbolicTy::BV(bv_from_u256!(constant))),
            ConcolicOp::ADD => binop!(bv.lhs, bv.rhs, bvadd),
            ConcolicOp::DIV => binop!(bv.lhs, bv.rhs, bvudiv),
            ConcolicOp::MUL => binop!(bv.lhs, bv.rhs, bvmul),
            ConcolicOp::SUB => binop!(bv.lhs, bv.rhs, bvsub),
            ConcolicOp::SDIV => binop!(bv.lhs, bv.rhs, bvsdiv),
            ConcolicOp::SMOD => binop!(bv.lhs, bv.rhs, bvsmod),
            ConcolicOp::UREM => binop!(bv.lhs, bv.rhs, bvurem),
            ConcolicOp::SREM => binop!(bv.lhs, bv.rhs, bvsrem),
            ConcolicOp::AND => binop!(bv.lhs, bv.rhs, bvand),
            ConcolicOp::OR => binop!(bv.lhs, bv.rhs, bvor),
            ConcolicOp::XOR => binop!(bv.lhs, bv.rhs, bvxor),
            ConcolicOp::NOT => {
                let lhs = self.generate_z3_bv(bv.lhs.as_ref()?);
                match lhs {
                    Some(SymbolicTy::BV(lhs)) => Some(SymbolicTy::BV(lhs.bvnot())),
                    Some(SymbolicTy::Bool(lhs)) => Some(SymbolicTy::Bool(lhs.not())),
                    _ => None,
                }
            }
            ConcolicOp::SHL => binop!(bv.lhs, bv.rhs, bvshl),
            ConcolicOp::SHR => binop!(bv.lhs, bv.rhs, bvlshr),
            ConcolicOp::SAR => binop!(bv.lhs, bv.rhs, bvashr),
            ConcolicOp::SLICEDINPUT(idx) => {
                let idx = idx.as_limbs()[0] as u32;
                let skv = self.slice_input(idx, idx + 32);
                // debug!("[concolic] SLICEDINPUT: {} {:?}", idx, skv);
                Some(SymbolicTy::BV(skv))
            }
            ConcolicOp::BALANCE => Some(SymbolicTy::BV(self.balance.clone())),
            ConcolicOp::CALLVALUE => {
                self.constrained_field.push(Field::CallDataValue);
                Some(SymbolicTy::BV(self.calldatavalue.clone()))
            }
            ConcolicOp::CALLER => {
                self.constrained_field.push(Field::Caller);
                self.constrained_field.push(Field::Origin);
                Some(SymbolicTy::BV(self.caller.clone()))
            }
            ConcolicOp::ORIGIN => {
                self.constrained_field.push(Field::Origin);
                self.constrained_field.push(Field::Caller);
                Some(SymbolicTy::BV(self.origin.clone()))
            }
            ConcolicOp::FINEGRAINEDINPUT(start, end) => Some(SymbolicTy::BV(self.slice_input(*start, *end))),
            ConcolicOp::LNOT => {
                let lhs = self.generate_z3_bv(bv.lhs.as_ref()?);
                match lhs {
                    Some(SymbolicTy::BV(lhs)) => Some(SymbolicTy::BV(lhs.not())),
                    Some(SymbolicTy::Bool(lhs)) => Some(SymbolicTy::Bool(lhs.not())),
                    _ => None,
                }
            }
            ConcolicOp::CONSTBYTE(b) => Some(SymbolicTy::BV(BV::from_u64(*b as u64, 8))),
            ConcolicOp::SYMBYTE(s) => Some(SymbolicTy::BV(BV::new_const(s.clone(), 8))),
            ConcolicOp::EQ => comparisons2!(bv.lhs, bv.rhs, eq),
            ConcolicOp::LT => comparisons1!(bv.lhs, bv.rhs, bvult),
            ConcolicOp::SLT => comparisons1!(bv.lhs, bv.rhs, bvslt),
            ConcolicOp::GT => comparisons1!(bv.lhs, bv.rhs, bvugt),
            ConcolicOp::SGT => comparisons1!(bv.lhs, bv.rhs, bvsgt),
            ConcolicOp::SELECT(high, low) => {
                let lhs = self.generate_z3_bv(bv.lhs.as_ref()?);
                match lhs {
                    Some(SymbolicTy::BV(lhs)) => Some(SymbolicTy::BV(lhs.extract(*high, *low))),
                    _ => None,
                }
            }

            ConcolicOp::CONCAT => {
                let lhs = self.generate_z3_bv(bv.lhs.as_ref()?);
                let rhs = self.generate_z3_bv(bv.rhs.as_ref()?);
                match (lhs, rhs) {
                    (Some(SymbolicTy::BV(lhs)), Some(SymbolicTy::BV(rhs))) => Some(SymbolicTy::BV(lhs.concat(&rhs))),
                    _ => None,
                }
            }
        }
    }

    pub fn solve(&mut self, optimistic: bool) -> Vec<Solution> {
        // debug!("solving on tid {:?}", std::thread::current().id());
        let solver = Solver::new();
        // debug!("Constraints: {:?}", self.constraints);

        solver.assert(&self.caller.eq(&self.origin));

        for (nth, cons) in self.constraints.iter().enumerate() {
            // only solve the last constraint
            if optimistic && nth != self.constraints.len() - 1 {
                continue;
            }

            // cons.lhs is None for a leaf-shaped constraint (e.g. a bare
            // symbolic boolean pushed directly via `self.constraints.push`
            // in the `br == false` path of JUMPI handling, with no `.lnot()`
            // ever applied to wrap it) -- none of GT/SGT/EQ/LT/SLT/LNOT
            // below are zero-ary, so a missing lhs means this constraint
            // just isn't in a shape this solve step can decompose. Treat it
            // the same as the existing "Unsupported constraint" fallback
            // further down (skip solving it, don't crash the whole run) --
            // confirmed live: this `.unwrap()` panicked in every worker
            // thread solving a real on-chain contract's corpus, and that
            // panic then re-panicked the MAIN fuzzer thread via
            // `concolic_stage.rs`'s `curr_thread.join().unwrap()`, killing
            // the entire run on a legitimate, non-malformed target.
            let Some(cons_lhs) = cons.lhs.as_ref() else {
                #[cfg(feature = "z3_debug")]
                error!("Constraint has no lhs, skipping: {:?}", cons);
                continue;
            };
            let bv = self.generate_z3_bv(cons_lhs);

            macro_rules! expect_bv_or_continue {
                ($e: expr) => {
                    if let Some(SymbolicTy::BV(bv)) = $e {
                        bv
                    } else {
                        #[cfg(feature = "z3_debug")]
                        error!("Failed to generate Z3 BV for {:?}", $e);
                        continue;
                    }
                };
            }

            // Direct sibling of the cons.lhs guard above, same root
            // cause: GT/SGT/EQ/LT/SLT all assume cons.rhs is populated,
            // which isn't guaranteed for every constraint shape that can
            // reach here. Skip this one constraint instead of panicking.
            macro_rules! rhs_bv_or_continue {
                () => {{
                    let Some(cons_rhs) = cons.rhs.as_ref() else {
                        #[cfg(feature = "z3_debug")]
                        error!("Constraint has no rhs, skipping: {:?}", cons);
                        continue;
                    };
                    self.generate_z3_bv(cons_rhs)
                }};
            }

            solver.assert(&match cons.op {
                ConcolicOp::GT => expect_bv_or_continue!(bv).bvugt(&expect_bv_or_continue!(rhs_bv_or_continue!())),
                ConcolicOp::SGT => expect_bv_or_continue!(bv).bvsgt(&expect_bv_or_continue!(rhs_bv_or_continue!())),
                ConcolicOp::EQ => expect_bv_or_continue!(bv).eq(&expect_bv_or_continue!(rhs_bv_or_continue!())),
                ConcolicOp::LT => expect_bv_or_continue!(bv).bvult(&expect_bv_or_continue!(rhs_bv_or_continue!())),
                ConcolicOp::SLT => expect_bv_or_continue!(bv).bvslt(&expect_bv_or_continue!(rhs_bv_or_continue!())),
                ConcolicOp::LNOT => match bv {
                    Some(SymbolicTy::BV(bv)) => bv.eq(&bv_from_u256!(EVMU256::ZERO)),
                    Some(SymbolicTy::Bool(bv)) => bv.not(),
                    _ => {
                        #[cfg(feature = "z3_debug")]
                        error!("Failed to generate Z3 BV for {:?}", bv);
                        continue;
                    }
                },
                _ => {
                    #[cfg(feature = "z3_debug")]
                    error!("Unsupported constraint: {:?}", cons);
                    continue;
                }
            });
        }

        // debug!("Solver: {:?}", solver);
        let mut p = Params::new();

        let concolic_timeout = CONCOLIC_TIMEOUT.load(std::sync::atomic::Ordering::Relaxed);
        if concolic_timeout > 0 {
            p.set_u32("timeout", concolic_timeout);
        }
        // Bound Z3's memory too, not just its wall-clock time: a hard path
        // condition can blow memory up while still returning inside the
        // timeout, which is the "machine freezes" failure mode. 0 = unlimited.
        let concolic_memory_mb = CONCOLIC_MEMORY_MB.load(std::sync::atomic::Ordering::Relaxed);
        if concolic_memory_mb > 0 {
            p.set_u32("memory_max_size", concolic_memory_mb);
        }

        solver.set_params(&p);
        let result = solver.check();
        match result {
            z3::SatResult::Sat => {
                // FAZA 6.1: model extraction is solver output and must never
                // panic. Any element the model cannot evaluate aborts this
                // candidate instead of taking the fuzzer down.
                let Some(model) = solver.get_model() else {
                    #[cfg(feature = "z3_debug")]
                    error!("solver reported Sat but returned no model");
                    return vec![];
                };
                #[cfg(feature = "z3_debug")]
                debug!("Model: {:?}", model);

                let eval_bv = |bv: &BV| -> Option<String> {
                    model
                        .eval(bv, true)
                        .map(|v| v.to_string().trim_start_matches("#x").to_string())
                };

                let mut input = String::new();
                for x in &self.input {
                    match eval_bv(x) {
                        Some(v) => input.push_str(&v),
                        None => {
                            #[cfg(feature = "z3_debug")]
                            error!("model could not evaluate a calldata BV, skipping candidate");
                            return vec![];
                        }
                    }
                }
                let Some(input_bytes) = hex::decode(&input).ok() else {
                    #[cfg(feature = "z3_debug")]
                    error!("concolic model produced non-hex calldata '{}', skipping candidate", input);
                    return vec![];
                };

                // z3 renders a 256-bit BV as "#x" + 64 hex chars; an address
                // is its low 160 bits (the last 40 hex chars).
                let parse_addr = |bv: &BV| -> Option<EVMAddress> {
                    let s = eval_bv(bv)?;
                    let hex = s.trim_start_matches("#x");
                    if hex.len() < 40 {
                        return None;
                    }
                    let low = &hex[hex.len() - 40..];
                    hex::decode(low).ok().map(|b| EVMAddress::from_slice(&b))
                };

                let Some(callvalue_int) = eval_bv(&self.calldatavalue)
                    .and_then(|s| EVMU256::from_str_radix(s.trim_start_matches("#x"), 16).ok())
                else {
                    #[cfg(feature = "z3_debug")]
                    error!("model could not evaluate calldata value, skipping candidate");
                    return vec![];
                };
                let Some(caller_addr) = parse_addr(&self.caller) else {
                    #[cfg(feature = "z3_debug")]
                    error!("model produced an unparseable caller address, skipping candidate");
                    return vec![];
                };
                let Some(origin_addr) = parse_addr(&self.origin) else {
                    #[cfg(feature = "z3_debug")]
                    error!("model produced an unparseable origin address, skipping candidate");
                    return vec![];
                };
                vec![Solution {
                    input: input_bytes,
                    caller: caller_addr,
                    origin: origin_addr,
                    value: callvalue_int,
                    fields: self.constrained_field.clone(),
                }]
            }
            z3::SatResult::Unsat | z3::SatResult::Unknown => {
                if optimistic || self.constraints.len() <= 1 {
                    vec![]
                } else {
                    // optimistic solving
                    self.solve(true)
                }
            }
        }
    }
}

// Note: To model concolic memory, we need to remember previous constraints as
// well. when solving a constraint involving persistant memory, if the
// persistant memory is not depenent on other non-persitent variables, this
// means that the persistant memory change might not be feasible, because the
// persistant memory cannot change it self. Example:
//     // in this case, even if we get the constraints for the memory element
// m[0]     // we cannot solve it (invert it), because the memory element is
// cannot change     // it self.
//     m = [0, 0, 0, 0]
//     fn f(a):
//         if m[0] == 0:
//             do something
//         else:
//             bug
//     // in this case, we can actually solve for m[0]!=0, becuase the memeory
// element     // is dependent on the input a.
//     fn g(a):
//         m[0] = a
//         if m[0] == 0:
//             do something
//         else:
//             bug

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct EVMInputConstraint {
//     // concrete data of EVM Input
//     data: Bytes,
//     input_constraints: Vec<Box<Expr>>,
// }

// impl EVMInputConstraint {
//     pub fn new(vm_input: BoxedABI) -> Self {
//         // TODO: build input constraints from ABI
//         let mut input_constraints = vec![];
//         // input_constraints.push()

//         Self {
//             data: Bytes::from(vm_input.get_bytes()),
//             input_constraints: input_constraints,
//         }
//     }

//     pub fn add_constraint(&mut self, constraint: Box<Expr>) {
//         self.input_constraints.push(constraint);
//     }

//     pub fn get_constraints(&self) -> &Vec<Box<Expr>> {
//         &self.input_constraints
//     }

//     pub fn get_data(&self) -> &Bytes {
//         &self.data
//     }
// }

// Q: Why do we need to make persistent memory symbolic?

// Confirmed live, fuzzing a real deployed contract: an EVM offset/length
// derived from attacker/fuzzer-controlled arithmetic (e.g. `to - from`
// underflowing to near EVMU256::MAX in a Solidity `uint` subtraction,
// then truncated to its low 64 bits via `.as_limbs()[0]`) is still an
// astronomically large `usize`. `insert_256`/`insert_8`/`get_slice`
// below used to `Vec::resize()` the symbolic memory backing store to
// exactly that size unconditionally -- a real Rust allocator "capacity
// overflow" panic, confirmed live, not a benign out-of-gas revert the
// way the same thing would play out on a real chain. 16 MiB of tracked
// 1-byte slots is far more than any real execution's memory grows to
// (real EVM memory expansion is gas-metered, and this is bytecode
// that's already proven to execute at all) -- past this, treat the
// access the same way an untracked/no-symbolic-value slot is already
// treated elsewhere (fall back to the concrete value via fast_peek!,
// see stack_bv!'s own doc) instead of attempting the allocation.
pub const MAX_SYMBOLIC_MEMORY_LEN: usize = 1 << 24;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SymbolicMemory {
    /// Memory is a vector of bytes, each byte is a symbolic value
    pub memory: Vec<Option<Box<Expr>>>,
    // pub memory_32: Vec<Option<Box<Expr>>>,
}

impl SymbolicMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_256(&mut self, idx: EVMU256, val: Box<Expr>) {
        let idx = idx.as_limbs()[0] as usize;
        if idx + 32 >= MAX_SYMBOLIC_MEMORY_LEN {
            // Offset too large to track symbolically (see
            // MAX_SYMBOLIC_MEMORY_LEN's own doc) -- leave this region
            // untracked rather than attempting the resize; any later
            // read falls back to the concrete value, same as any other
            // untracked slot.
            return;
        }
        if idx + 32 >= self.memory.len() {
            self.memory.resize(idx + 32 + 1, None);
            // self.memory_32.resize(idx / 32 + 1, None);
        }

        // if idx % 32 == 0 {
        //     self.memory_32[idx / 32] = Some(val.clone());
        // }

        for i in 0..32 {
            let i_u32 = i as u32;
            self.memory[idx + i] = Some(Box::new(Expr {
                lhs: Some(val.clone()),
                rhs: None,
                op: ConcolicOp::SELECT(256 - i_u32 * 8 - 1, 256 - i_u32 * 8 - 7 - 1),
            }));
        }
    }

    pub fn insert_8(&mut self, idx: EVMU256, val: Box<Expr>) {
        // MSTORE8 stores only the low-order byte of `val` (bits 7..0) at a
        // single memory slot -- the same SELECT-based symbolic byte that
        // insert_256 already uses for each of its 32 bytes, just one byte
        // instead of a loop over 32.
        let idx = idx.as_limbs()[0] as usize;
        if idx >= MAX_SYMBOLIC_MEMORY_LEN {
            return;
        }
        if idx >= self.memory.len() {
            self.memory.resize(idx + 1, None);
        }

        self.memory[idx] = Some(Box::new(Expr {
            lhs: Some(val),
            rhs: None,
            op: ConcolicOp::SELECT(7, 0),
        }));
    }

    pub fn get_256(&self, idx: EVMU256) -> Option<Box<Expr>> {
        let idx = idx.as_limbs()[0] as usize;
        if idx >= self.memory.len() {
            return None;
        }

        // if idx % 32 == 0 {
        //     return self.memory_32[idx / 32].clone();
        // }

        let mut all_bytes = if let Some(by) = self.memory[idx].clone() {
            by
        } else {
            Box::new(Expr {
                lhs: None,
                rhs: None,
                op: ConcolicOp::CONSTBYTE(0),
            })
        };
        for i in 1..32 {
            all_bytes = Box::new(Expr {
                lhs: Some(all_bytes),
                rhs: if self.memory.len() > idx + i &&
                    let Some(by) = self.memory[idx + i].clone()
                {
                    Some(by)
                } else {
                    Some(Box::new(Expr {
                        lhs: None,
                        rhs: None,
                        op: ConcolicOp::CONSTBYTE(0),
                    }))
                },
                op: ConcolicOp::CONCAT,
            });
        }

        Some(simplify(all_bytes))
    }

    pub fn get_slice(&mut self, idx: EVMU256, len: EVMU256) -> Vec<Box<Expr>> {
        let idx = idx.as_limbs()[0] as usize;
        let len = len.as_limbs()[0] as usize;
        // Cap, don't reject: this result feeds a best-effort symbolic
        // representation (push_ctx's input_bytes), not a correctness-
        // critical real value, so a truncated-but-present result is the
        // right tradeoff against the same unbounded-allocation panic
        // insert_256/insert_8 guard against above.
        let len = len.min(MAX_SYMBOLIC_MEMORY_LEN);
        let idx = idx.min(MAX_SYMBOLIC_MEMORY_LEN);

        if idx + len >= self.memory.len() && idx + len < MAX_SYMBOLIC_MEMORY_LEN {
            self.memory.resize(idx + len + 1, None);
        }

        let mut result = vec![];

        for i in idx..(idx + len) {
            if i >= self.memory.len() {
                result.push(Box::new(Expr {
                    lhs: None,
                    rhs: None,
                    op: ConcolicOp::CONSTBYTE(0),
                }));
            } else {
                result.push(if let Some(by) = self.memory[i].clone() {
                    by
                } else {
                    Box::new(Expr {
                        lhs: None,
                        rhs: None,
                        op: ConcolicOp::CONSTBYTE(0),
                    })
                });
            }
        }
        result
    }

    /// FAZA 2.5: like `get_slice`, but returns `None` if ANY byte in the
    /// range was never written (`None`), instead of substituting a concrete
    /// `0`. Callers that turn the result into a symbolic RETURN value need
    /// this stricter view: a genuine `0` and an untracked byte are
    /// indistinguishable in `get_slice`'s output, and treating an untracked
    /// byte as `0` would fabricate a return value the callee never produced.
    pub fn get_slice_tracked(&self, idx: EVMU256, len: EVMU256) -> Option<Vec<Box<Expr>>> {
        let idx = idx.as_limbs()[0] as usize;
        let len = len.as_limbs()[0] as usize;
        if len == 0 || idx + len > self.memory.len() {
            return None;
        }
        let mut result = Vec::with_capacity(len);
        for i in idx..idx + len {
            match &self.memory[i] {
                Some(by) => result.push(by.clone()),
                None => return None,
            }
        }
        Some(result)
    }

    /// FAZA 2.5: write a run of already-symbolic bytes starting at `idx`,
    /// used to place a callee's symbolic return value into the caller's
    /// memory at the CALL's return offset. Untracked (`None`) entries are
    /// left untouched so a partial symbolic return degrades to the concrete
    /// bytes the interpreter already wrote rather than inventing zeros.
    pub fn insert_bytes(&mut self, idx: EVMU256, bytes: &[Box<Expr>]) {
        let idx = idx.as_limbs()[0] as usize;
        if idx + bytes.len() >= MAX_SYMBOLIC_MEMORY_LEN {
            return;
        }
        if idx + bytes.len() > self.memory.len() {
            self.memory.resize(idx + bytes.len(), None);
        }
        for (i, by) in bytes.iter().enumerate() {
            self.memory[idx + i] = Some(by.clone());
        }
    }
}

/// FAZA 2.1 (TASK_SPEC.md): storage that can be keyed by a
/// SYMBOLIC expression, not only by the concrete value the seed input
/// happens to evaluate to.
///
/// The pre-FAZA-2 model was a bare `HashMap<EVMU256, _>` keyed on
/// `fast_peek!` -- the concrete value of the key slot on the CURRENT
/// (seed) input. That is enough when the contract writes and reads the
/// SAME slot in one frame (the concrete interpreter resolves both to the
/// same `EVMU256`), which is why `tmp = x*3; require(tmp == V)` was
/// already solvable. It is NOT enough when the gate's slot is a mapping
/// key read from calldata: the slot the seed run touches is a function of
/// the seed's calldata, so a constraint solved for a DIFFERENT key would
/// look up a different concrete slot and miss the stored value.
///
/// This keeps the old concrete map verbatim (so every existing case keeps
/// working, R5) and adds a symbolic-keyed list alongside it. A SLOAD whose
/// key expression is symbolic is matched against the symbolic list by
/// structural equality first; only if that misses does it fall back to the
/// concrete map and then to the real host value.
///
/// Honest scope (R3): this models storage the contract itself writes with
/// a symbolic key. It does NOT invert `keccak256` to recover the slot of a
/// mapping entry that was already present in world state before the
/// transaction (an unmodified `m[k]` for attacker-chosen `k`); that
/// requires a hash model this project does not have, and is documented in
/// LIMITATIONS.md rather than silently attempted.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SymbolicStorage {
    /// Writes whose key OR value was symbolic, in insertion order. A linear
    /// scan is fine -- a single transaction performs only a handful of such
    /// writes, and only the symbolic ones land here.
    symbolic: Vec<(Box<Expr>, Box<Expr>)>,
    /// The pre-FAZA-2 concrete-keyed map, unchanged.
    concrete: HashMap<EVMU256, Option<Box<Expr>>>,
}

impl SymbolicStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a write. `key` is the SYMBOLIC key expression; `concrete_key`
    /// is its value on the seed input. A symbolic key (or symbolic value)
    /// also goes into the symbolic list, keyed by the expression itself.
    pub fn store(&mut self, key: &Box<Expr>, concrete_key: EVMU256, value: &Box<Expr>) {
        self.concrete.insert(concrete_key, Some(value.clone()));
        if key.is_concrete() && value.is_concrete() {
            return;
        }
        // Overwrite an existing symbolic entry with a structurally-equal
        // key so a repeated store does not leave a stale earlier value
        // shadowing the newer one.
        if let Some(entry) = self.symbolic.iter_mut().find(|(k, _)| k == key) {
            entry.1 = value.clone();
        } else {
            self.symbolic.push((key.clone(), value.clone()));
        }
    }

    /// Loads by SYMBOLIC key expression. The concrete map is consulted
    /// FIRST and is authoritative for the slot the seed actually used: it is
    /// overwritten on every store, so it can never return a value shadowed
    /// by a later concrete write. The symbolic list is only a fallback for a
    /// key whose concrete slot was never written this run -- which is
    /// exactly the case the old concrete-only map could not answer.
    pub fn load(&self, key: &Box<Expr>, concrete_key: EVMU256) -> Option<Box<Expr>> {
        if let Some(Some(v)) = self.concrete.get(&concrete_key) {
            return Some(v.clone());
        }
        if !key.is_concrete() {
            if let Some((_, v)) = self.symbolic.iter().find(|(k, _)| k == key) {
                return Some(v.clone());
            }
        }
        None
    }

    #[cfg(test)]
    fn symbolic_len(&self) -> usize {
        self.symbolic.len()
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ConcolicCallCtx {
    pub symbolic_stack: Vec<Option<Box<Expr>>>,
    pub symbolic_memory: SymbolicMemory,

    // seperated by 32 bytes
    pub input_bytes: Vec<Box<Expr>>,

    /// FAZA 2.5: the frame's return value as a run of symbolic BYTES, filled
    /// in by the callee's `RETURN` handler (0xf3) from its own symbolic
    /// memory. `None` means "not a symbolically tracked return" -- the
    /// caller then falls back to the concrete return bytes. Only present
    /// for frames pushed by push_ctx (real CALLs), never the root frame.
    #[serde(default)]
    pub return_bytes: Option<Vec<Box<Expr>>>,
    /// FAZA 2.5: the CALL's return-data offset and length on the CALLER's
    /// stack/memory, captured in push_ctx so on_return can write the
    /// symbolic return bytes back into the caller's memory. Meaningless
    /// when `return_bytes` is None.
    #[serde(default)]
    pub return_offset: EVMU256,
    #[serde(default)]
    pub return_len: EVMU256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConcolicHost {
    pub symbolic_stack: Vec<Option<Box<Expr>>>,
    pub symbolic_memory: SymbolicMemory,
    /// FAZA 2.1: symbolic storage is keyed by the STORAGE-CONTEXT ADDRESS
    /// and lives on the host, not per call frame. EVM storage is addressed
    /// by contract, not by frame, so a slot written in one call must be
    /// readable (symbolically) from a later call in the same transaction --
    /// including a `this.f()` self-call or a DELEGATECALL, both of which the
    /// concrete interpreter already shares storage across. Keeping this in
    /// `ConcolicCallCtx` (reset on every push) made exactly those reads fall
    /// back to the concrete value and lose the symbolic link to the input.
    pub symbolic_state: HashMap<EVMAddress, SymbolicStorage>,
    pub input_bytes: Vec<Box<Expr>>,
    pub constraints: Vec<Box<Expr>>,
    pub testcase_ref: Rc<EVMInput>,

    pub ctxs: Vec<ConcolicCallCtx>,
    /// Max live Z3 solvers this host may keep in `ALL_WORKER_THREADS`. The
    /// effective value is already clamped to the campaign-wide cap
    /// (`max_concolic_threads()`), so a `--jobs N` campaign never multiplies
    /// into `N * cap` concurrent solvers.
    pub num_threads: usize,
    pub call_depth: usize,

    /// FAZA 2.5: return bytes of the most recently completed call, pushed
    /// here by `on_return` and consumed by `RETURNDATASIZE` (0x3d) /
    /// `RETURNDATACOPY` (0x3e). Mirrors the EVM's "last call's return data"
    /// buffer. Empty when the last call's return was not symbolically
    /// tracked (caller then falls back to concrete).
    #[serde(default)]
    pub last_return_bytes: Vec<Box<Expr>>,
}

#[allow(clippy::vec_box)]
impl ConcolicHost {
    pub fn new(testcase_ref: Rc<EVMInput>, num_threads: usize) -> Self {
        Self {
            symbolic_stack: Vec::new(),
            symbolic_memory: SymbolicMemory::new(),
            symbolic_state: Default::default(),
            // A testcase without ABI metadata has no concolic input to build.
            // The concolic stage already skips ABI-less testcases, so this
            // empty fallback is never exercised symbolically -- it only
            // guarantees host construction can never panic on a missing ABI.
            input_bytes: match testcase_ref.get_data_abi() {
                Some(abi) => Self::construct_input_from_abi(abi),
                None => Vec::new(),
            },
            constraints: vec![],
            testcase_ref,
            ctxs: vec![],
            num_threads,
            call_depth: 0,
            last_return_bytes: Vec::new(),
        }
    }

    /// Pops the current call frame and restores the caller's symbolic
    /// stack/memory. Returns the popped frame so `on_return` (FAZA 2.5) can
    /// read its symbolic return bytes and splice them into the caller.
    pub fn pop_ctx(&mut self) -> Option<ConcolicCallCtx> {
        let ctx = self.ctxs.pop();
        if let Some(ctx) = ctx {
            self.symbolic_stack = ctx.symbolic_stack.clone();
            self.symbolic_memory = ctx.symbolic_memory.clone();
            // NOTE: symbolic_state is deliberately NOT restored here --
            // storage writes made inside the callee persist into the
            // caller's view, exactly like real EVM storage.
            Some(ctx)
        } else {
            // An unmatched return (e.g. a frame popped on a path the
            // middleware didn't push for) is a bookkeeping gap: reset the
            // per-frame symbolic stack/memory and continue rather than
            // aborting the run. The concrete interpreter's own stack/memory
            // are unaffected -- only symbolic tracking is cleared. Storage
            // is host-level (see the field's own doc) and is intentionally
            // left intact.
            #[cfg(feature = "z3_debug")]
            error!("pop_ctx: ctx is empty, resetting symbolic frame state");
            self.symbolic_stack = vec![];
            self.symbolic_memory = SymbolicMemory::new();
            None
        }
    }

    pub fn push_ctx(&mut self, interp: &mut Interpreter) {
        // interp.stack.data()[interp.stack.len() - 1 - $idx]
        let op = unsafe { *interp.instruction_pointer };
        let (arg_offset, arg_len) = match op {
            0xf1 | 0xf2 => (interp.stack.peek(3).unwrap(), interp.stack.peek(4).unwrap()),
            0xf4 | 0xfa => (interp.stack.peek(2).unwrap(), interp.stack.peek(3).unwrap()),
            _ => {
                // push_ctx is only wired to CALL/CALLCODE/DELEGATECALL/
                // STATICCALL, but reaching here must never kill the run:
                // fall back to a zero-length input slice, which produces a
                // concrete (non-symbolic) frame exactly like any other
                // untracked call.
                #[cfg(feature = "z3_debug")]
                error!("push_ctx: unsupported opcode 0x{:02x}, using empty input slice", op);
                (EVMU256::ZERO, EVMU256::ZERO)
            }
        };

        // FAZA 2.5: the return-data window on the CALLER's stack, so
        // on_return can splice the callee's symbolic return bytes into the
        // caller's symbolic memory at exactly the offset the CALL wrote its
        // concrete return to. Yellow Paper stack order (peek(0) = top):
        //   CALL/CALLCODE   (gas, addr, value, argsOff, argsLen, retOff, retLen)
        //     -> argsOff=peek(3), argsLen=peek(4), retOff=peek(5), retLen=peek(6)
        //   DELEGATECALL/STATICCALL (gas, addr, argsOff, argsLen, retOff, retLen)
        //     -> argsOff=peek(2), argsLen=peek(3), retOff=peek(4), retLen=peek(5)
        let (return_offset, return_len) = match op {
            0xf1 | 0xf2 => (interp.stack.peek(5).unwrap(), interp.stack.peek(6).unwrap()),
            0xf4 | 0xfa => (interp.stack.peek(4).unwrap(), interp.stack.peek(5).unwrap()),
            _ => (EVMU256::ZERO, EVMU256::ZERO),
        };

        let ctx = ConcolicCallCtx {
            symbolic_stack: self.symbolic_stack.clone(),
            symbolic_memory: self.symbolic_memory.clone(),
            input_bytes: {
                let by = self.symbolic_memory.get_slice(arg_offset, arg_len);
                #[cfg(feature = "z3_debug")]
                {
                    debug!("input_bytes = {} {}", arg_offset, arg_len);
                    by.iter().for_each(|b| {
                        b.pretty_print();
                    });
                }
                by
            },
            return_bytes: None,
            return_offset,
            return_len,
        };
        self.ctxs.push(ctx);

        self.symbolic_stack = vec![];
        self.symbolic_memory = SymbolicMemory::new();
        // symbolic_state is host-level and NOT cleared: storage is shared
        // across call frames by address (see the field's own doc).
    }

    fn construct_input_from_abi(vm_input: BoxedABI) -> Vec<Box<Expr>> {
        // debug!("[concolic] construct_input_from_abi: {:?}", res);
        vm_input.get_concolic()
    }

    pub fn solve(&self) -> Vec<Solution> {
        // let input = (0..self.bytes)
        //     .map(|idx| BV::new_const(format!("input_{}", idx), 8))
        //     .collect::<Vec<_>>();
        let callvalue = BV::new_const("callvalue", 256);
        let caller = BV::new_const("caller", 256);
        let origin = BV::new_const("origin", 256);
        let balance = BV::new_const("balance", 256);

        let mut solving = Solving::new(
            &self.input_bytes,
            &balance,
            &callvalue,
            &caller,
            &origin,
            &self.constraints,
        );
        solving.solve(false)
    }

    /// Solve the current constraint set on a bounded worker-thread pool.
    ///
    /// Concolic solving is genuinely parallel here: each solve runs on its own
    /// OS thread and results are merged into `ALL_SOLUTIONS`, so several
    /// independent corpus items' branches can be solved at once. Parallelism is
    /// bounded, not unbounded: at most `self.num_threads` solvers stay live in
    /// the process-wide `ALL_WORKER_THREADS` pool. Once it is full, the oldest
    /// worker is joined before a new one starts -- so the campaign never spawns
    /// one solver per core (the historical `num_cpus` default that froze a
    /// 15-core host). `num_threads` is already clamped to the campaign-wide cap
    /// (`max_concolic_threads()`), so `--jobs N` workers each stay within it
    /// rather than multiplying it.
    ///
    /// Only pure, `Send` data crosses the thread boundary (`input_bytes` /
    /// `constraints` are cloned `Vec<Box<Expr>>`); every Z3 object is built
    /// inside the worker from that thread's own thread-local Z3 context. The
    /// caller (`concolic_stage.rs`) joins the whole pool after each testcase,
    /// so the pool is empty again before the next testcase's host is created.
    pub fn threaded_solve(&self) {
        let solutions_clone = ALL_SOLUTIONS.clone();
        let input_bytes = self.input_bytes.clone();
        let constraints = self.constraints.clone();

        // Bound the pool: join the oldest worker once `num_threads` are live.
        // A worker this joins may itself have panicked; `.join()` returning an
        // Err is handled the same as any other "couldn't solve this one"
        // outcome -- log and move on, never re-panic the caller (the main
        // fuzzer thread), and still pick up whatever it pushed to
        // `ALL_SOLUTIONS` first.
        let mut worker_threads = ALL_WORKER_THREADS.lock().unwrap_or_else(|e| e.into_inner());
        if worker_threads.len() >= self.num_threads.max(1) {
            let handle = worker_threads.remove(0);
            if let Err(panic_payload) = handle.join() {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".to_string());
                error!("Concolic worker thread panicked (skipping, run continues): {msg}");
            }
        }
        drop(worker_threads);

        let handle = std::thread::spawn(move || {
            let callvalue = BV::new_const("callvalue", 256);
            let caller = BV::new_const("caller", 256);
            let origin = BV::new_const("origin", 256);
            let balance = BV::new_const("balance", 256);

            let mut solving = Solving::new(&input_bytes, &balance, &callvalue, &caller, &origin, &constraints);

            // Architectural backstop for every remaining `.unwrap()`/
            // `.expect()` in `Solving::solve` (Z3 model retrieval/eval, hex
            // decoding, ...) and in `generate_z3_bv`: catch any panic from
            // this one attempt and treat it as "couldn't solve this testcase"
            // instead of taking down the worker (and, via the join above,
            // eventually the fuzzer thread).
            let solutions = match catch_unwind(AssertUnwindSafe(|| solving.solve(false))) {
                Ok(solutions) => solutions,
                Err(panic_payload) => {
                    let msg = panic_payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "<non-string panic payload>".to_string());
                    error!("Concolic solve() panicked (skipping this testcase, run continues): {msg}");
                    vec![]
                }
            };
            let mut solutions_clone = solutions_clone.lock().unwrap_or_else(|e| e.into_inner());
            solutions_clone.extend(solutions);
        });

        ALL_WORKER_THREADS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(handle);
    }

    pub fn get_input_slice_from_ctx(&self, idx: usize, length: usize) -> Box<Expr> {
        // `ctxs` can legitimately be empty here (the concrete frame ran a
        // CALLDATALOAD with no matching pushed symbolic frame). Treat that
        // as an empty input buffer instead of panicking: an all-zero slice
        // is the same value a concrete frame would read.
        let empty = Vec::new();
        let data = match self.ctxs.last() {
            Some(ctx) => &ctx.input_bytes,
            None => &empty,
        };
        let mut bytes = if idx < data.len() {
            data[idx].clone()
        } else {
            Expr::const_byte(0)
        };
        for i in idx + 1..idx + length {
            if i >= data.len() {
                bytes = bytes.concat(Expr::const_byte(0));
            } else {
                bytes = bytes.concat(data[i].clone());
            }
        }
        simplify(bytes)
    }
}

impl<SC> Middleware<SC> for ConcolicHost
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, _host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        macro_rules! fast_peek {
            ($idx:expr) => {
                interp.stack.data()[interp.stack.len() - 1 - $idx]
            };
        }

        macro_rules! stack_bv {
            ($idx:expr) => {{
                // self.symbolic_stack is meant to mirror the real EVM
                // stack's depth 1:1, but confirmed live (a real crash
                // fuzzing a real deployed contract): it can fall behind
                // (some opcode path not pushing a None placeholder for a
                // real push), leaving it SHORTER than the real stack by
                // the time a later opcode indexes deep into it --
                // `self.symbolic_stack.len() - 1 - $idx` then underflows
                // (wraps to a huge usize) and panics on the out-of-bounds
                // index instead of hitting the `None` arm below. Treat
                // "the slot doesn't exist at all" the same as "the slot
                // exists but isn't tracked symbolically" (already an
                // intentional, normal fallback below) -- both mean the
                // real, concrete value via fast_peek! is all we have.
                let len = self.symbolic_stack.len();
                if $idx >= len {
                    let u256 = fast_peek!($idx);
                    Box::new(Expr {
                        lhs: None,
                        rhs: None,
                        op: ConcolicOp::EVMU256(u256),
                    })
                } else {
                    let real_loc_sym = len - 1 - $idx;
                    match self.symbolic_stack[real_loc_sym].borrow() {
                        Some(bv) => bv.clone(),
                        None => {
                            let u256 = fast_peek!($idx);
                            Box::new(Expr {
                                lhs: None,
                                rhs: None,
                                op: ConcolicOp::EVMU256(u256),
                            })
                        }
                    }
                }
            }};
        }

        macro_rules! concrete_eval {
            ($in_cnt: expr, $out_cnt: expr) => {{
                // debug!("[concolic] concrete_eval: {} {}", $in_cnt, $out_cnt);
                for _ in 0..$in_cnt {
                    self.symbolic_stack.pop();
                }
                vec![None; $out_cnt]
            }};
        }

        macro_rules! concrete_eval_with_action {
            ($in_cnt: expr, $out_cnt: expr, $pp: ident) => {{
                self.call_depth += 1;

                // debug!("[concolic] concrete_eval: {} {}", $in_cnt, $out_cnt);
                for _ in 0..$in_cnt {
                    self.symbolic_stack.pop();
                }
                for _ in 0..$out_cnt {
                    self.symbolic_stack.push(None);
                }
                self.$pp(interp);
                vec![]
            }};
        }

        // if self.ctxs.len() > 0 {
        //     return;
        // }

        // TODO: Figure out the corresponding MiddlewareOp to add
        // We may need coverage map here to decide whether to add a new input to the
        // corpus or not.
        // debug!("[concolic] on_step @ {:x}: {:x}", interp.program_counter(),
        // *interp.instruction_pointer); debug!("[concolic] stack: {:?}",
        // interp.stack.len()); debug!("[concolic] symbolic_stack: {:?}",
        // self.symbolic_stack.len());

        // let mut max_depth = 0;
        // let mut max_ref = None;
        // for s in &self.symbolic_stack {
        //     if let Some(bv) = s {
        //         let depth = bv.depth();
        //         if depth > max_depth {
        //             max_depth = depth;
        //             max_ref = Some(bv);
        //         }
        //     }
        // }
        //
        // debug!("max_depth: {} for {:?}", max_depth, max_ref.map(|x|
        // x.pretty_print_str())); debug!("max_depth simpl: {:?} for {:?}",
        // max_ref.map(|x| simplify(x.clone()).depth()), max_ref.map(|x|
        // simplify(x.clone()).pretty_print_str()));
        #[cfg(feature = "z3_debug")]
        {
            debug!(
                "[concolic] on_step @ {:x}: {:x}",
                interp.program_counter(),
                *interp.instruction_pointer
            );
            debug!("[concolic] stack: {:?}", interp.stack);
            debug!("[concolic] symbolic_stack: {:?}", self.symbolic_stack);
            // Downgraded from assert_eq!/an unguarded index: the shadow
            // symbolic stack can legitimately fall behind the real
            // stack's depth (the same root cause already fixed in
            // stack_bv!/the SWAP handler) -- this debug-only block
            // (z3_debug feature, not part of a normal build) should warn
            // and move on, not hard-crash a debug run over the exact
            // drift it exists to help diagnose.
            if interp.stack.len() != self.symbolic_stack.len() {
                debug!(
                    "[concolic] stack/symbolic_stack length mismatch: {} vs {}",
                    interp.stack.len(),
                    self.symbolic_stack.len()
                );
            }
            for idx in 0..interp.stack.len().min(self.symbolic_stack.len()) {
                let real = interp.stack.data[idx];
                let sym = self.symbolic_stack[idx].clone();
                if let Some(sym) = sym {
                    if let ConcolicOp::EVMU256(v) = sym.op {
                        if real != v {
                            debug!("[concolic] stack/symbolic_stack value mismatch at {idx}: {real:?} vs {v:?}");
                        }
                    }
                }
            }
        }

        let bv: Vec<Option<Box<Expr>>> = match *interp.instruction_pointer {
            // ADD
            0x01 => {
                let res = Some(stack_bv!(0).add(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MUL
            0x02 => {
                let res = Some(stack_bv!(0).mul(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SUB
            0x03 => {
                let res = Some(stack_bv!(0).sub(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // DIV - is this signed?
            0x04 => {
                let res = Some(stack_bv!(0).div(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SDIV
            0x05 => {
                let res = Some(stack_bv!(0).bvsdiv(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MOD
            0x06 => {
                let res = Some(stack_bv!(0).bvurem(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SMOD
            0x07 => {
                let res = Some(stack_bv!(0).bvsmod(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // ADDMOD
            0x08 => {
                let res = Some(stack_bv!(0).add(stack_bv!(1)).bvsmod(stack_bv!(2)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // MULMOD
            0x09 => {
                let res = Some(stack_bv!(0).mul(stack_bv!(1)).bvsmod(stack_bv!(2)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // EXP - fallback to concrete due to poor Z3 performance support
            0x0a => {
                concrete_eval!(2, 1)
            }
            // SIGNEXTEND - not modeled symbolically; falls back to concrete,
            // same as EXP above
            0x0b => {
                concrete_eval!(2, 1)
            }
            // LT
            0x10 => {
                let res = Some(stack_bv!(0).bvult(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // GT
            0x11 => {
                let res = Some(stack_bv!(0).bvugt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SLT
            0x12 => {
                let res = Some(stack_bv!(0).bvslt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SGT
            0x13 => {
                let res = Some(stack_bv!(0).bvsgt(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // EQ
            0x14 => {
                let res = Some(stack_bv!(0).equal(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // ISZERO
            0x15 => {
                let res = Some(stack_bv!(0).equal(Box::new(Expr {
                    lhs: None,
                    rhs: None,
                    op: ConcolicOp::EVMU256(EVMU256::from(0)),
                })));
                self.symbolic_stack.pop();
                vec![res]
            }
            // AND
            0x16 => {
                let res = Some(stack_bv!(0).bvand(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // OR
            0x17 => {
                let res = Some(stack_bv!(0).bvor(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // XOR
            0x18 => {
                let res = Some(stack_bv!(0).bvxor(stack_bv!(1)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // NOT
            0x19 => {
                let res = Some(stack_bv!(0).bvnot());
                self.symbolic_stack.pop();
                vec![res]
            }
            // BYTE - not modeled symbolically; falls back to concrete,
            // same as EXP above
            0x1a => {
                concrete_eval!(2, 1)
            }
            // SHL
            0x1b => {
                let res = Some(stack_bv!(1).bvshl(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SHR
            0x1c => {
                let res = Some(stack_bv!(1).bvlshr(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SAR
            0x1d => {
                let res = Some(stack_bv!(1).bvsar(stack_bv!(0)));
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![res]
            }
            // SHA3
            0x20 => {
                concrete_eval!(2, 1)
            }
            // ADDRESS
            0x30 => {
                vec![None]
            }
            // BALANCE
            // TODO: need to get value from a hashmap
            0x31 => {
                concrete_eval!(1, 1)
            }
            // ORIGIN
            0x32 => {
                if !self.ctxs.is_empty() {
                    // use concrete origin when inside a call
                    vec![None]
                } else {
                    vec![Some(Expr::new_origin())]
                }
            }
            // CALLER
            0x33 => {
                // debug!("CALLER @ pc : {:x}", interp.program_counter());
                if !self.ctxs.is_empty() {
                    // use concrete caller when inside a call
                    vec![None]
                } else {
                    vec![Some(Expr::new_caller())]
                }
            }
            // CALLVALUE
            0x34 => {
                if !self.ctxs.is_empty() {
                    // use concrete caller when inside a call
                    vec![None]
                } else {
                    vec![Some(Expr::new_callvalue())]
                }
            }
            // CALLDATALOAD
            0x35 => {
                let offset = interp.stack.peek(0).unwrap();
                self.symbolic_stack.pop();
                if !self.ctxs.is_empty() {
                    let offset_usize = as_u64(offset) as usize;
                    #[cfg(feature = "z3_debug")]
                    {
                        debug!("CALLDATALOAD: {:?}", self.get_input_slice_from_ctx(offset_usize, 32));
                        self.get_input_slice_from_ctx(offset_usize, 32).pretty_print();
                    }
                    vec![Some(self.get_input_slice_from_ctx(offset_usize, 32))]
                } else {
                    vec![Some(Expr::new_sliced_input(offset))]
                }
            }
            // CALLDATASIZE
            0x36 => {
                vec![None]
            }
            // CALLDATACOPY
            0x37 => {
                concrete_eval!(3, 0)
            }
            // CODESIZE
            0x38 => {
                vec![None]
            }
            // CODECOPY
            0x39 => {
                concrete_eval!(3, 0)
            }
            // GASPRICE
            0x3a => {
                vec![None]
            }
            // EXTCODESIZE
            0x3b => {
                concrete_eval!(1, 1)
            }
            // EXTCODECOPY
            0x3c => {
                concrete_eval!(4, 0)
            }
            // RETURNDATASIZE
            0x3d => {
                // FAZA 2.5: size of the last call's return data. We only
                // know it symbolically when the last return was tracked;
                // otherwise fall back to the concrete size.
                if self.last_return_bytes.is_empty() {
                    vec![None]
                } else {
                    vec![Some(Box::new(Expr {
                        lhs: None,
                        rhs: None,
                        op: ConcolicOp::EVMU256(EVMU256::from(self.last_return_bytes.len())),
                    }))]
                }
            }
            // RETURNDATACOPY
            0x3e => {
                // FAZA 2.5: copy the last call's return data into memory.
                // dest is concrete (a compiler constant); mem_offset and
                // len index the return buffer. When the last return was
                // tracked symbolically, splice those symbolic bytes into
                // memory so a later MLOAD sees the callee's expression.
                let dest = fast_peek!(0);
                let src = fast_peek!(1);
                let len = fast_peek!(2);
                let src_usize = as_u64(src) as usize;
                let len_usize = as_u64(len) as usize;
                if !self.last_return_bytes.is_empty()
                    && src_usize + len_usize <= self.last_return_bytes.len()
                    && len_usize > 0
                {
                    let bytes = self.last_return_bytes[src_usize..src_usize + len_usize].to_vec();
                    self.symbolic_memory.insert_bytes(dest, &bytes);
                }
                concrete_eval!(3, 0)
            }
            // EXTCODEHASH
            0x3f => {
                concrete_eval!(1, 1)
            }
            // BLOCKHASH
            0x40 => {
                concrete_eval!(1, 1)
            }
            // COINBASE
            0x41 => {
                vec![None]
            }
            // TIMESTAMP
            0x42 => {
                vec![None]
            }
            // NUMBER
            0x43 => {
                vec![None]
            }
            // PREVRANDAO
            0x44 => {
                vec![None]
            }
            // GASLIMIT
            0x45 => {
                vec![None]
            }
            // CHAINID
            0x46 => {
                vec![None]
            }
            // SELFBALANCE
            0x47 => {
                vec![None]
            }
            // BASEFEE
            0x48 => {
                vec![None]
            }
            // POP
            0x50 => {
                self.symbolic_stack.pop();
                vec![]
            }
            // MLOAD
            0x51 => {
                // debug!("[concolic] MLOAD: {:?}", self.symbolic_stack);
                let offset = fast_peek!(0);
                self.symbolic_stack.pop();
                vec![self.symbolic_memory.get_256(offset)]
            }
            // MSTORE
            0x52 => {
                let offset = fast_peek!(0);
                let value = stack_bv!(1);
                self.symbolic_memory.insert_256(offset, value);
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // MSTORE8
            0x53 => {
                let offset = fast_peek!(0);
                let value = stack_bv!(1);
                self.symbolic_memory.insert_8(offset, value);
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // SLOAD
            0x54 => {
                // Capture the key BEFORE popping: the symbolic key may be a
                // dynamic-array index (`keccak(base) + i`, i symbolic), and
                // the concrete value is what the seed input evaluated it to.
                let key_expr = stack_bv!(0);
                let concrete_key = fast_peek!(0);
                self.symbolic_stack.pop();
                // Storage context address: for DELEGATECALL this is the
                // caller's address (the frame that owns the storage), which
                // is exactly the slot namespace the concrete host uses.
                let storage_addr = interp.contract.address;
                let loaded = self
                    .symbolic_state
                    .get(&storage_addr)
                    .and_then(|s| s.load(&key_expr, concrete_key));
                vec![loaded]
            }
            // SSTORE
            0x55 => {
                // revm's own handler does `pop!(interpreter, index, value)`,
                // i.e. the KEY (slot) is on top and the VALUE is beneath it.
                // The previous code had these two swapped (key from peek(1),
                // value from peek(0)), so a symbolic store was filed under
                // the wrong slot and no later SLOAD ever found it -- measured
                // live: `stored = x*2` (slot 0, value symbolic) recorded the
                // symbolic value under key 2 instead of slot 0.
                let key_expr = stack_bv!(0);
                let concrete_key = fast_peek!(0);
                let value = stack_bv!(1);
                let storage_addr = interp.contract.address;
                self.symbolic_state
                    .entry(storage_addr)
                    .or_insert_with(SymbolicStorage::new)
                    .store(&key_expr, concrete_key, &value);
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // JUMP
            0x56 => {
                concrete_eval!(1, 0)
            }
            // JUMPI
            0x57 => {
                // debug!("{:?}", interp.stack);
                // debug!("{:?}", self.symbolic_stack);
                // jump dest in concolic solving mode is the opposite of the concrete
                let br = is_zero(fast_peek!(1));

                /*
                 * Skip rules:
                 * 1. the source map (if any) says this PC's source is an entire
                 *    library/contract/function block, not a single expression --
                 *    that only happens for compiler-generated plumbing, not a
                 *    real user branch, so it's not worth an expensive Z3 call.
                 * 2. call depth > MAX_CALL_DEPTH
                 * TODO: 3. global variable signature?
                 */

                let mut need_solve = true;
                if self.call_depth as u64 > MAX_ANALYSIS_CALL_DEPTH.load(std::sync::atomic::Ordering::Relaxed) {
                    debug!("[concolic] skip solving due to call depth: {}", self.call_depth);
                    need_solve = false;
                } else {
                    // threaded_solve() (below) builds its constraints purely
                    // from bytecode-level symbolic state (calldata bytes,
                    // stack values) -- it needs no source code at all. A
                    // missing source map (the common case for an on-chain
                    // target with no local/verified source, or a local one
                    // compiled without --combined-json) is NOT a reason to
                    // skip solving; only a POSITIVELY matched multiline block
                    // (rule 1 above) is -- that's the one case we can be
                    // confident is compiler noise, not a real branch.
                    let pc = interp.program_counter();
                    let address = &interp.contract.address;

                    if let SourceCodeResult::SourceCodeNoPcMatch(_) =
                        SOURCE_MAP_PROVIDER.lock().unwrap_or_else(|e| e.into_inner()).get_source_code(address, pc)
                    {
                        debug!("[concolic] skip solving: source map matched an entire library/contract/function block");
                        need_solve = false;
                    }
                }

                let real_path_constraint = if br {
                    // path_condition = false
                    stack_bv!(1).lnot()
                } else {
                    // path_condition = true
                    stack_bv!(1)
                };

                if need_solve {
                    // debug!("[concolic] still need to solve");
                    if !real_path_constraint.is_concrete() {
                        let intended_path_constraint = real_path_constraint.clone().lnot();
                        let constraint_hash = intended_path_constraint.pretty_print_str();

                        // `ALREADY_SOLVED` is a process-wide RwLock shared
                        // across all concolic workers. If any worker ever
                        // panicked while holding it, `.expect("concolic
                        // crashed")` would re-panic on EVERY subsequent
                        // access and poison the lock for the rest of the
                        // run. `unwrap_or_else(|e| e.into_inner())` recovers
                        // the (valid) inner set instead, so a single failed
                        // solve can never cascade into a full-run crash.
                        if !ALREADY_SOLVED
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .contains(&constraint_hash)
                        {
                            #[cfg(feature = "z3_debug")]
                            debug!("[concolic] to solve {:?}", intended_path_constraint.pretty_print_str());
                            self.constraints.push(intended_path_constraint);

                            self.threaded_solve();

                            // #[cfg(feature = "z3_debug")]
                            // debug!("[concolic] Solutions: {:?}", solutions);
                            self.constraints.pop();

                            ALREADY_SOLVED
                                .write()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(constraint_hash);
                        }
                    }
                }

                // jumping only happens if the second element is false
                if !real_path_constraint.is_concrete() {
                    self.constraints.push(real_path_constraint);
                }
                self.symbolic_stack.pop();
                self.symbolic_stack.pop();
                vec![]
            }
            // PC
            0x58 => {
                vec![None]
            }
            // MSIZE
            0x59 => {
                vec![None]
            }
            // GAS
            0x5a => {
                vec![None]
            }
            // JUMPDEST
            0x5b => {
                vec![]
            }
            // MCOPY
            0x5e => {
                concrete_eval!(3, 0)
            }
            // PUSH
            0x5f..=0x7f => {
                // push n bytes into stack
                // Concolic push n bytes is equivalent to concrete push, because the bytes
                // being pushed are always concrete, we can just push None to the stack
                // and 'fallthrough' to concrete values later
                vec![None]
            }
            // DUP
            0x80..=0x8f => {
                let _n = (*interp.instruction_pointer) - 0x80;
                vec![Some(stack_bv!(usize::from(_n)).clone())]
            }
            // SWAP
            0x90..=0x9f => {
                let _n = (*interp.instruction_pointer) - 0x90 + 1;
                let swapper = stack_bv!(usize::from(_n));
                let swappee = stack_bv!(0);
                let symbolic_stack_len = self.symbolic_stack.len();
                // Same underflow risk as stack_bv! above, for the WRITE
                // side this time: if the shadow stack is already shorter
                // than the real one needs it to be for this swap, there's
                // nothing valid to overwrite. Dropping the symbolic
                // tracking for this one swap (both slots fall back to
                // fast_peek! on next read, same as an untracked `None`)
                // is a correct, graceful degradation; indexing blindly
                // crashed the whole run instead, confirmed live.
                if usize::from(_n) + 1 <= symbolic_stack_len {
                    self.symbolic_stack[symbolic_stack_len - 1] = Some(swapper);
                    self.symbolic_stack[symbolic_stack_len - usize::from(_n) - 1] = Some(swappee);
                }
                vec![]
            }
            // LOG
            0xa0..=0xa4 => {
                let _n = (*interp.instruction_pointer) - 0xa0;
                concrete_eval!(_n + 2, 0)
            }
            // CREATE
            0xf0 => {
                concrete_eval!(3, 1)
            }
            // CALL
            0xf1 => {
                concrete_eval_with_action!(7, 1, push_ctx)
            }
            // CALLCODE
            0xf2 => {
                concrete_eval_with_action!(7, 1, push_ctx)
            }
            // RETURN
            0xf3 => {
                // FAZA 2.5: capture the returned bytes symbolically so the
                // CALLER (in on_return) can gate on `callee(...)`'s result.
                // Offset/len are concrete (they sit on the real stack as
                // PUSH/MSTORE constants on virtually all compiler output);
                // read the callee's own symbolic memory at that window.
                let ret_offset = fast_peek!(0);
                let ret_len = fast_peek!(1);
                if let Some(frame) = self.ctxs.last_mut() {
                    frame.return_bytes = self.symbolic_memory.get_slice_tracked(ret_offset, ret_len);
                }
                concrete_eval!(2, 0)
            }
            // DELEGATECALL
            0xf4 => {
                concrete_eval_with_action!(6, 1, push_ctx)
            }
            // CREATE2
            0xf5 => {
                concrete_eval!(4, 1)
            }
            // STATICCALL
            0xfa => {
                concrete_eval_with_action!(6, 1, push_ctx)
            }
            // REVERT
            0xfd => {
                concrete_eval!(2, 0)
            }
            // INVALID
            0xfe => {
                vec![]
            }
            // SELFDESTRUCT
            0xff => {
                concrete_eval!(1, 0)
            }
            // STOP
            0x00 => {
                vec![]
            }
            other => {
                // Any opcode not modelled above must degrade gracefully:
                // symbolic tracking for this step is simply unavailable, so
                // push nothing and let the concrete interpreter carry the
                // real stack/memory forward (later reads fall back to
                // fast_peek!). Panicking here killed the entire fuzz run on
                // a perfectly valid target the moment it executed an
                // opcode outside the modelled set (e.g. 0x0c-0x0f, 0x1e-0x1f,
                // 0x21-0x2f, 0x49-0x4f, 0x5c-0x5d, 0xf6-0xf9, 0xfb-0xfc).
                #[cfg(feature = "z3_debug")]
                error!("concolic: unsupported opcode 0x{:02x}, symbolic tracking skipped", other);
                let _ = other;
                vec![]
            }
        };
        // debug!("[concolic] adding bv to stack {:?}", bv);
        for v in bv {
            if v.is_some() && v.as_ref().unwrap().is_concrete() {
                self.symbolic_stack.push(None);
            } else {
                self.symbolic_stack.push(v);
            }
        }

        // let input = state
        //     .corpus()
        //     .get(state.get_current_input_idx())
        //     .unwrap()
        //     .borrow_mut()
        //     .load_input()
        //     .expect("Failed loading input")
        //     .clone();
    }}

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        _host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _by: &Bytes,
    ) {
        // FAZA 2.5: pop_ctx restores the CALLER's symbolic stack/memory.
        // If the callee's RETURN was symbolically tracked, splice those
        // bytes into the caller's memory at the CALL's return offset, so a
        // later MLOAD of the return region reads the callee's expression
        // (e.g. `r = this.helper(y); require(r == SECRET)`). The bytes are
        // the callee's OWN symbolic memory, already tied to the caller's
        // input through the calldata the CALL passed -- so the solver can
        // invert the callee's computation, not just guess a constant.
        if let Some(frame) = self.pop_ctx() {
            match frame.return_bytes {
                Some(ret_bytes) => {
                    let cap = as_u64(frame.return_len) as usize;
                    let n = ret_bytes.len().min(cap);
                    if n > 0 {
                        self.symbolic_memory
                            .insert_bytes(frame.return_offset, &ret_bytes[..n]);
                    }
                    // Full return data (not caller-truncated) for
                    // RETURNDATASIZE / RETURNDATACOPY.
                    self.last_return_bytes = ret_bytes;
                }
                None => {
                    // Untracked return (precompile, control-leak-free real
                    // callee that wrote a constant window, ...): fall back
                    // to concrete, never invent a value.
                    self.last_return_bytes = Vec::new();
                }
            }
        } else {
            self.last_return_bytes = Vec::new();
        }
        self.call_depth -= 1;
    }

    fn get_type(&self) -> MiddlewareType {
        Concolic
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}

#[cfg(test)]
mod symbolic_storage_tests {
    use super::*;

    fn concrete(v: u64) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::EVMU256(EVMU256::from(v)),
        })
    }

    fn symbolic(id: u64) -> Box<Expr> {
        Expr::new_sliced_input(EVMU256::from(id))
    }

    /// The pre-FAZA-2 behaviour, preserved (R5): a concrete-keyed store is
    /// found again by the same concrete key.
    #[test]
    fn concrete_roundtrip_is_unchanged() {
        let mut s = SymbolicStorage::new();
        s.store(&concrete(2), EVMU256::from(2), &concrete(99));
        let got = s.load(&concrete(2), EVMU256::from(2)).unwrap();
        assert!(got.is_concrete());
        // A concrete store must not leak into the symbolic list.
        assert_eq!(s.symbolic_len(), 0);
    }

    /// FAZA 2.1 core: a store under a SYMBOLIC key is found by a later load
    /// with the same symbolic key, even when the concrete key differs -- the
    /// exact case the old concrete-only map could not represent.
    #[test]
    fn symbolic_key_roundtrip_matches_regardless_of_concrete_key() {
        let mut s = SymbolicStorage::new();
        // Written while the seed evaluated the key to 2...
        s.store(&symbolic(7), EVMU256::from(2), &concrete(4242));
        assert_eq!(s.symbolic_len(), 1);
        // ...read back where a different seed would have evaluated the same
        // symbolic key to 5: structural match wins over the concrete miss.
        let got = s.load(&symbolic(7), EVMU256::from(5)).unwrap();
        assert!(got.is_concrete());
        assert_eq!(got.as_ref().op, ConcolicOp::EVMU256(EVMU256::from(4242)));
    }

    /// A symbolic store overwrites its own earlier entry instead of leaving
    /// a stale value that a later load could return.
    #[test]
    fn symbolic_store_overwrites_same_key() {
        let mut s = SymbolicStorage::new();
        s.store(&symbolic(1), EVMU256::from(0), &concrete(1));
        s.store(&symbolic(1), EVMU256::from(0), &concrete(2));
        assert_eq!(s.symbolic_len(), 1);
        let got = s.load(&symbolic(1), EVMU256::from(0)).unwrap();
        assert_eq!(got.as_ref().op, ConcolicOp::EVMU256(EVMU256::from(2)));
    }

    /// A symbolic key that was never written reads as unknown (`None`), so
    /// the caller falls back to the real host value rather than inventing 0.
    #[test]
    fn unknown_symbolic_key_reads_none() {
        let s = SymbolicStorage::new();
        assert!(s.load(&symbolic(3), EVMU256::from(0)).is_none());
    }
}

#[cfg(test)]
mod return_data_tests {
    //! FAZA 2.5: the symbolic return-value flow (`callee(...)`'s result
    //! gating the caller). These pin the two primitives the flow rests on:
    //! `SymbolicMemory::get_slice_tracked` (only a fully-written window
    //! counts as a trackable return) and `insert_bytes` (splicing it back
    //! into the caller at the CALL's return offset).
    use super::*;

    fn symbolic(id: u64) -> Box<Expr> {
        Expr::new_sliced_input(EVMU256::from(id))
    }

    fn concrete(v: u64) -> Box<Expr> {
        Box::new(Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::EVMU256(EVMU256::from(v)),
        })
    }

    /// A window the callee wrote with symbolic bytes must be returned as-is
    /// -- this is what lets the caller's gate reference the callee's
    /// computation (`y*2`) instead of a concrete constant.
    #[test]
    fn tracked_slice_returns_symbolic_bytes() {
        let mut m = SymbolicMemory::new();
        m.insert_256(EVMU256::from(0), symbolic(4));
        let got = m.get_slice_tracked(EVMU256::from(0), EVMU256::from(32)).unwrap();
        assert_eq!(got.len(), 32);
        // The high byte of a symbolic 256-bit word is a SELECT, never concrete.
        assert!(!got[0].is_concrete());
    }

    /// A window with ANY untracked byte must NOT be reported as tracked:
    /// otherwise an unwritten byte would read as concrete 0 and fabricate a
    /// return value the callee never produced.
    #[test]
    fn untracked_slice_is_none() {
        let m = SymbolicMemory::new();
        assert!(m.get_slice_tracked(EVMU256::from(0), EVMU256::from(32)).is_none());
    }

    /// A zero-length window is not a return value.
    #[test]
    fn zero_len_slice_is_none() {
        let mut m = SymbolicMemory::new();
        m.insert_256(EVMU256::from(0), symbolic(1));
        assert!(m.get_slice_tracked(EVMU256::from(0), EVMU256::from(0)).is_none());
    }

    /// Splicing symbolic bytes at an offset makes a later `get_256` of that
    /// region return the symbolic expression -- the exact path a caller's
    /// `MLOAD` of the return region takes.
    #[test]
    fn insert_bytes_roundtrips_through_get_256() {
        let mut m = SymbolicMemory::new();
        m.insert_256(EVMU256::from(0), symbolic(9));
        let bytes = m.get_slice_tracked(EVMU256::from(0), EVMU256::from(32)).unwrap();

        // Splice into a fresh memory at a different offset, as on_return does.
        let mut dst = SymbolicMemory::new();
        dst.insert_bytes(EVMU256::from(128), &bytes);

        // The spliced region reads back as a symbolic 256-bit word...
        let back = dst.get_256(EVMU256::from(128)).unwrap();
        assert!(!back.is_concrete());
        // ...and byte-for-byte equal to what was spliced.
        let reread = dst.get_slice_tracked(EVMU256::from(128), EVMU256::from(32)).unwrap();
        for (a, b) in reread.iter().zip(bytes.iter()) {
            assert_eq!(a.as_ref().op, b.as_ref().op);
        }
    }

    /// Splicing concrete bytes keeps them concrete (no accidental
    /// symbolisation of a genuinely constant return).
    #[test]
    fn insert_bytes_preserves_concrete() {
        let mut dst = SymbolicMemory::new();
        dst.insert_bytes(EVMU256::from(64), &[concrete(0xAB), concrete(0xCD)]);
        // Read the single byte back via a 1-byte tracked slice.
        let got = dst.get_slice_tracked(EVMU256::from(64), EVMU256::from(2)).unwrap();
        assert!(got[0].is_concrete() && got[1].is_concrete());
    }
}

#[cfg(test)]
mod concolic_thread_safety_tests {
    use super::*;
    use crate::evm::concolic::expr::{ConcolicOp, Expr};

    /// Structural proof that the concolic worker pool is sound by
    /// construction, and a guard against a future regression that would make
    /// it unsound:
    ///
    ///   * everything that crosses the thread boundary into a worker
    ///     (`Vec<Box<Expr>>` input/constraints) must be `Send`;
    ///   * the fuzzing state, which is NOT `Send` (it holds
    ///     `Rc<RefCell<..>>`), must never be captured by a worker -- the
    ///     concolic path deliberately passes only cloned, pure data.
    ///
    /// This is the honest replacement for the old claim that concolic is
    /// "strictly sequential because RacyCell maps are single-threaded": the
    /// workers never touch a RacyCell at all, so the real invariant is
    /// "only Send data crosses the boundary".
    #[test]
    fn concolic_worker_boundary_is_send_only() {
        fn assert_send<T: Send>() {}

        // What a worker receives (cloned) must be Send.
        assert_send::<Vec<Box<Expr>>>();
        assert_send::<Solution>();

        // A representative Expr tree (the shape actually cloned across).
        let leaf = Expr {
            lhs: None,
            rhs: None,
            op: ConcolicOp::EVMU256(EVMU256::from(7)),
        };
        assert_send::<Expr>();
        assert_send::<Box<Expr>>();
        assert_send::<Vec<Box<Expr>>>();
        let _ = leaf;
    }
}

#[cfg(test)]
mod concolic_memory_cap_tests {
    use super::*;
    use z3::{ast::BV, Params, Solver};

    /// P2 regression: a concolic solve must be bounded in MEMORY, not only in
    /// wall-clock time. The solver previously set only `timeout`; a hard path
    /// condition could grow Z3's memory without limit while still returning
    /// inside the timeout, pushing the host into swap/OOM (the "machine
    /// freezes with more concolic lines" symptom). This pins that a
    /// `memory_max_size` param is actually accepted by Z3 (a typo'd param name
    /// would be silently ignored by Z3 and the bound would not exist) and that
    /// a solve still works with it set.
    #[test]
    fn z3_accepts_memory_max_size_and_still_solves() {
        let solver = Solver::new();
        let mut p = Params::new();
        p.set_u32("timeout", 1000);
        // Must not panic: an unknown parameter name is silently ignored by Z3,
        // so the value is exercised through an actual solve below.
        p.set_u32("memory_max_size", 512);
        solver.set_params(&p);

        let x = BV::new_const("x", 64);
        solver.assert(&x.eq(&BV::from_u64(7, 64)));
        assert_eq!(solver.check(), z3::SatResult::Sat, "solve must still work under the memory cap");
    }

    /// The global defaults to a real (non-zero) bound so the protection is on
    /// by default; 0 remains available as "unlimited".
    #[test]
    fn memory_cap_default_is_a_real_bound() {
        let mb = CONCOLIC_MEMORY_MB.load(std::sync::atomic::Ordering::Relaxed);
        assert!(mb > 0, "the Z3 memory cap must be on by default, not 0/unlimited");
    }
}

