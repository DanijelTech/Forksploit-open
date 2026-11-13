use std::any;

use libafl::schedulers::Scheduler;
use revm_interpreter::{CallScheme, Interpreter};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::EVMFuzzState,
};

/// Detects the classic "unchecked low-level call()" footgun: a plain
/// `CALL`/`CALLCODE` whose sub-call FAILED, in a transaction that
/// nonetheless completed successfully overall -- i.e. nothing downstream
/// noticed or acted on that failure.
///
/// Mechanism: `FuzzHost::call()` stashes the `CallScheme` and success of the
/// call that's about to return into `host.last_call_scheme`/
/// `host.last_call_success` right before invoking middlewares' `on_return`
/// (`on_return` itself is only given the return bytes, not that context).
/// This middleware just reads those two fields.
///
/// **Heuristic, not proof** (documented like `uninitialized_memory.rs`'s
/// equivalent caveat): an initial version of this tracker additionally
/// required the opcode immediately after the call to be `POP` (the success
/// flag discarded right away), to approximate "and nobody even looked at
/// it." That turned out to not work against real solc codegen: a plain
/// `.call(...)` is compiled through solc's shared ABI-decode helper
/// (`CALL; SWAP2; POP; POP; RETURNDATASIZE; ...`), so the success flag is
/// never adjacent to a bare `POP` even when the Solidity source never reads
/// it -- the discard (if any) happens much later, after the helper returns,
/// and telling that apart from a legitimate `if (!success) { ...without
/// reverting... }` would need real data-flow tracking across jumps, not
/// just opcode adjacency. So this only checks "the sub-call failed, yet the
/// overall transaction still succeeded." That means a contract that
/// deliberately checks the result and handles a failure gracefully
/// (without reverting) will also trigger this -- a known, accepted
/// precision tradeoff of a purely dynamic check. Not included in
/// `high_confidence` for that reason.
#[derive(Clone, Debug, Default)]
pub struct UncheckedCallTracer;

impl UncheckedCallTracer {
    pub fn new() -> Self {
        Self
    }
}

impl<SC> Middleware<SC> for UncheckedCallTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, _interp: &mut Interpreter, _host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {}

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _ret: &bytes::Bytes,
    ) {
        let is_plain_call = matches!(host.last_call_scheme, CallScheme::Call | CallScheme::CallCode);
        if is_plain_call && !host.last_call_success {
            host.current_unchecked_call
                .insert((interp.contract.address, interp.program_counter()));
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::UncheckedCall
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
