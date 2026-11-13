use std::any;

use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::EVMFuzzState,
};

const CALL_OP: u8 = 0xf1;
const CALLCODE_OP: u8 = 0xf2;
const DELEGATECALL_OP: u8 = 0xf4;
const STATICCALL_OP: u8 = 0xfa;
const SSTORE_OP: u8 = 0x55;

/// Detects generic storage-slot collisions, most commonly seen in
/// upgradeable proxies: a slot that gets written to BOTH "natively" (by the
/// currently-executing contract's own code, e.g. a proxy's admin-management
/// logic) AND from inside a DELEGATECALL frame (i.e. the implementation
/// contract wrote to it, landing in the proxy's storage because
/// DELEGATECALL shares the caller's storage context). That dual write
/// pattern on the exact same slot is strong evidence the proxy's and the
/// implementation's storage layouts overlap.
///
/// Unlike `ProxyIntegrityOracle`'s storage-collision check (which only
/// watches the two standardized EIP-1967 slots), this watches EVERY slot,
/// so it also catches non-standard / legacy proxy slot conventions -- at
/// the cost of needing a per-frame "are we currently inside a delegatecall"
/// stack, tracked here via `on_step`/`on_return` correlation (the same
/// technique validated for `EcrecoverZeroTracer`, generalized to a stack
/// since calls can nest).
#[derive(Clone, Debug, Default)]
pub struct StorageCollisionTracer {
    // true if the call frame we just entered was a DELEGATECALL
    delegatecall_stack: Vec<bool>,
}

impl StorageCollisionTracer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<SC> Middleware<SC> for StorageCollisionTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        let op = *interp.instruction_pointer;

        if matches!(op, CALL_OP | CALLCODE_OP | DELEGATECALL_OP | STATICCALL_OP) {
            self.delegatecall_stack.push(op == DELEGATECALL_OP);
            return;
        }

        if op != SSTORE_OP {
            return;
        }

        let is_delegated = self.delegatecall_stack.last().copied().unwrap_or(false);
        let slot = interp.stack.peek(0).unwrap();
        let key = (interp.contract.address, slot);

        let entry = host.slot_write_contexts.entry(key).or_insert((false, false));
        if is_delegated {
            entry.1 = true;
        } else {
            entry.0 = true;
        }

        if entry.0 && entry.1 {
            host.current_storage_collisions.insert(key);
        }
    }}

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        _host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _ret: &bytes::Bytes,
    ) {
        self.delegatecall_stack.pop();
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::StorageCollision
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
