use std::any;

use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{convert_u256_to_h160, EVMFuzzState},
};

const DELEGATECALL_OP: u8 = 0xf4;

/// Records every DELEGATECALL's (caller, pc, target) so `DelegatecallTargetOracle`
/// can check whether the target address was derived directly from the
/// transaction's own calldata (i.e. attacker-controlled), independent of the
/// campaign-long "how many distinct targets" tracking in
/// `delegatecall.rs`/`DelegatecallInjectionOracle`. This catches it in a
/// single transaction instead of needing enough fuzzing history to cross a
/// threshold.
#[derive(Clone, Debug, Default)]
pub struct DelegatecallTargetTracer;

impl DelegatecallTargetTracer {
    pub fn new() -> Self {
        Self
    }
}

impl<SC> Middleware<SC> for DelegatecallTargetTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        if *interp.instruction_pointer != DELEGATECALL_OP {
            return;
        }
        let target = convert_u256_to_h160(interp.stack.peek(1).unwrap());
        host.current_delegatecall_targets_seen
            .insert((interp.contract.address, interp.program_counter(), target));
    }}

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::DelegatecallTarget
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
