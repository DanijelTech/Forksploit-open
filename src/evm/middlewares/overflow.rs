use std::any;

use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::EVMFuzzState,
};

/// Tracks unchecked EVM arithmetic (raw `ADD`/`SUB`/`MUL` opcodes, i.e. code
/// compiled without Solidity 0.8's built-in overflow checks, or inside an
/// `unchecked { ... }` block) that wraps around. Since ForkSploit operates
/// black-box on bytecode, it cannot assume every target uses checked
/// arithmetic -- plenty of real deployed contracts (pre-0.8.0, or using
/// `unchecked` for gas) are still vulnerable to silent overflow/underflow.
///
/// This only records *that* a wraparound happened; `host.current_integer_overflow`
/// (and the `EVMState.integer_overflow` it gets merged into every execution,
/// see `vm.rs`) already existed in the codebase before this middleware did --
/// nothing else ever populated them. `IntegerOverflowOracle`
/// (`oracles/overflow.rs`) reads the merged set and reports a bug for any
/// entry that survived to a non-reverted transaction.
#[derive(Clone, Debug, Default)]
pub struct IntegerOverflowTracer;

impl IntegerOverflowTracer {
    pub fn new() -> Self {
        Self
    }
}

impl<SC> Middleware<SC> for IntegerOverflowTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        let op = *interp.instruction_pointer;
        let (overflowed, name): (bool, &'static str) = match op {
            0x01 => {
                // ADD
                let a = interp.stack.peek(0).unwrap();
                let b = interp.stack.peek(1).unwrap();
                (a.overflowing_add(b).1, "ADD")
            }
            0x02 => {
                // MUL
                let a = interp.stack.peek(0).unwrap();
                let b = interp.stack.peek(1).unwrap();
                (a.overflowing_mul(b).1, "MUL")
            }
            0x03 => {
                // SUB (EVM semantics: top - second == underflow if second > top)
                let a = interp.stack.peek(0).unwrap();
                let b = interp.stack.peek(1).unwrap();
                (a.overflowing_sub(b).1, "SUB")
            }
            _ => return,
        };
        if overflowed {
            host.current_integer_overflow
                .insert((interp.contract.address, interp.program_counter(), name));
        }
    }}

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::IntegerOverflow
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
