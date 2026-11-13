use std::any;

use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::EVMFuzzState,
};

const SSTORE_OP: u8 = 0x55;

/// Detects SWC-124 (Write to Arbitrary Storage Location): an `SSTORE` whose
/// slot argument is a value that came straight from this transaction's own
/// calldata (see `host.rs`'s extended 0x35 CALLDATALOAD handling, which now
/// also populates `current_calldata_words` -- every raw 32-byte word, not
/// just address-shaped ones). Deliberately does NOT flag the normal, safe
/// `mapping[key] = value` pattern: that compiles to
/// `sstore(keccak256(key . base_slot), value)`, so the slot on the stack is
/// a KECCAK256 digest, never the raw calldata word itself. Only a slot that
/// matches a calldata word VERBATIM is flagged -- the shape of a
/// deliberately low-level `assembly { sstore(slot, value) }` with an
/// attacker-supplied slot index (e.g. the 2017 Parity multisig library
/// pattern, where calling a public function with a crafted slot argument
/// let anyone overwrite the library's own owner slot).
#[derive(Clone, Debug, Default)]
pub struct ArbitraryStorageWriteTracer;

impl ArbitraryStorageWriteTracer {
    pub fn new() -> Self {
        Self
    }
}

impl<SC> Middleware<SC> for ArbitraryStorageWriteTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        if *interp.instruction_pointer != SSTORE_OP {
            return;
        }
        let slot = interp.stack.peek(0).unwrap();
        if host.current_calldata_words.contains(&slot) {
            host.current_arbitrary_storage_writes
                .insert((interp.contract.address, interp.program_counter(), slot));
        }
    }}

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::ArbitraryStorageWrite
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
