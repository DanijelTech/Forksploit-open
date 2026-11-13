use std::any;

use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::EVMFuzzState,
};

const ORIGIN_OP: u8 = 0x32;

/// Detects the classic `tx.origin` phishing bypass: a contract reads
/// `ORIGIN` while it is being called THROUGH an intermediary (its immediate
/// caller, i.e. `msg.sender`, is not the same account as `tx.origin`), and
/// execution still proceeds.
///
/// This is the exact shape of the real-world exploit: the legitimate
/// account (`tx.origin`) gets tricked into calling an attacker's contract,
/// which then calls into the victim; any `require(tx.origin == owner)`-style
/// check in the victim still passes because `tx.origin` is unchanged all the
/// way down the call chain, even though the IMMEDIATE caller is the
/// attacker's contract, not the real owner. A legitimate, directly-called
/// `tx.origin` check never triggers this (there, `msg.sender == tx.origin`
/// by definition -- no intermediary).
///
/// Simpler than the other call-based trackers: both signals (`ORIGIN` read,
/// caller-vs-origin mismatch) are available in the same `on_step`, so no
/// `on_return` correlation or per-frame state is needed at all.
#[derive(Clone, Debug, Default)]
pub struct TxOriginTracer;

impl TxOriginTracer {
    pub fn new() -> Self {
        Self
    }
}

impl<SC> Middleware<SC> for TxOriginTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        if *interp.instruction_pointer != ORIGIN_OP {
            return;
        }

        if interp.contract.caller != host.env.tx.caller {
            host.current_tx_origin_checks
                .insert((interp.contract.address, interp.program_counter()));
        }
    }}

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::TxOrigin
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
