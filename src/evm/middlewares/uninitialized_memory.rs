use std::{any, collections::HashSet};

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::EVMFuzzState,
};

const MLOAD: u8 = 0x51;
const MSTORE: u8 = 0x52;
const MSTORE8: u8 = 0x53;
const CALLDATACOPY: u8 = 0x37;
const CODECOPY: u8 = 0x39;
const EXTCODECOPY: u8 = 0x3c;
const RETURNDATACOPY: u8 = 0x3e;
const CALL: u8 = 0xf1;
const CALLCODE: u8 = 0xf2;
const CREATE: u8 = 0xf0;
const CREATE2: u8 = 0xf5;
const DELEGATECALL: u8 = 0xf4;
const STATICCALL: u8 = 0xfa;

/// Tracks which 32-byte memory words have been written (via `MSTORE`/
/// `MSTORE8`/`*COPY` opcodes, or copied in from a sub-call's return data)
/// within the *current call frame* -- memory is always fresh per frame
/// (unlike storage, it is never shared, not even across DELEGATECALL), so a
/// stack of per-frame write-sets is pushed on every CALL-family opcode and
/// popped on `on_return`.
///
/// `MLOAD` from a word never written in the current frame is recorded as a
/// candidate "uninitialized memory read". Note this is a heuristic, not a
/// hard vulnerability: the EVM deterministically zero-fills unwritten
/// memory (unlike e.g. C, there is no "random garbage" to read), so this
/// mainly flags code that may be relying on a value it never actually set
/// -- a logic-bug smell worth a human look, not a guaranteed exploit.
#[derive(Clone, Debug, Default)]
pub struct UninitializedMemoryTracer {
    written_words: Vec<HashSet<usize>>,
    pending_out_region: Vec<(usize, usize)>,
}

impl UninitializedMemoryTracer {
    pub fn new() -> Self {
        Self::default()
    }

    fn mark_range(&mut self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        if self.written_words.is_empty() {
            self.written_words.push(HashSet::new());
        }
        let frame = self.written_words.last_mut().unwrap();
        let start_word = offset / 32;
        let end_word = (offset + len - 1) / 32;
        for w in start_word..=end_word {
            frame.insert(w);
        }
    }
}

impl<SC> Middleware<SC> for UninitializedMemoryTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        let op = *interp.instruction_pointer;

        if self.written_words.is_empty() {
            self.written_words.push(HashSet::new());
        }

        match op {
            MLOAD => {
                let offset: Result<usize, _> = interp.stack.peek(0).unwrap().try_into();
                if let Ok(offset) = offset {
                    let word = offset / 32;
                    let frame = self.written_words.last().unwrap();
                    if !frame.contains(&word) {
                        host.current_uninitialized_memory_reads
                            .insert((interp.contract.address, interp.program_counter()));
                    }
                }
            }
            MSTORE => {
                if let Ok(offset) = TryInto::<usize>::try_into(interp.stack.peek(0).unwrap()) {
                    self.mark_range(offset, 32);
                }
            }
            MSTORE8 => {
                if let Ok(offset) = TryInto::<usize>::try_into(interp.stack.peek(0).unwrap()) {
                    self.mark_range(offset, 1);
                }
            }
            CALLDATACOPY | CODECOPY | RETURNDATACOPY => {
                let offset: Result<usize, _> = interp.stack.peek(0).unwrap().try_into();
                let len: Result<usize, _> = interp.stack.peek(2).unwrap().try_into();
                if let (Ok(offset), Ok(len)) = (offset, len) {
                    self.mark_range(offset, len);
                }
            }
            EXTCODECOPY => {
                let offset: Result<usize, _> = interp.stack.peek(1).unwrap().try_into();
                let len: Result<usize, _> = interp.stack.peek(3).unwrap().try_into();
                if let (Ok(offset), Ok(len)) = (offset, len) {
                    self.mark_range(offset, len);
                }
            }
            CALL | CALLCODE => {
                let out_offset = interp.stack.peek(5).unwrap().try_into().unwrap_or(0usize);
                let out_len = interp.stack.peek(6).unwrap().try_into().unwrap_or(0usize);
                self.pending_out_region.push((out_offset, out_len));
                self.written_words.push(HashSet::new());
            }
            DELEGATECALL | STATICCALL => {
                let out_offset = interp.stack.peek(4).unwrap().try_into().unwrap_or(0usize);
                let out_len = interp.stack.peek(5).unwrap().try_into().unwrap_or(0usize);
                self.pending_out_region.push((out_offset, out_len));
                self.written_words.push(HashSet::new());
            }
            CREATE | CREATE2 => {
                self.pending_out_region.push((0, 0));
                self.written_words.push(HashSet::new());
            }
            _ => {}
        }
    }}

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        _host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        ret: &Bytes,
    ) {
        self.written_words.pop();
        if let Some((out_offset, out_len)) = self.pending_out_region.pop() {
            let copy_len = ret.len().min(out_len);
            self.mark_range(out_offset, copy_len);
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::UninitializedMemory
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
