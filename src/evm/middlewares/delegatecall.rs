use std::any;

use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{convert_u256_to_h160, EVMFuzzState},
};

// If a single (caller, pc) DELEGATECALL callsite is observed targeting more
// than this many *distinct* addresses across the whole campaign, the target
// is considered attacker-controlled rather than a fixed, trusted
// implementation address. Kept low because the fuzzer's address mutator
// favors a small pool of "interesting" addresses (deployer, callers,
// generated contracts) rather than exploring the full address space -- a
// legitimate upgradeable proxy's delegatecall target realistically never
// changes more than once or twice within one campaign either way.
const DELEGATECALL_INJECTION_THRESHOLD: usize = 3;

/// Tracks DELEGATECALL targets per callsite to flag attacker-controlled
/// delegatecall injection (e.g. a proxy whose implementation address is
/// read from attacker-influenced calldata/storage instead of a fixed slot).
/// This is corruption of the *caller's own* storage/identity via an
/// unbounded delegatecall target -- a different, generally more dangerous
/// variant of the existing `current_arbitrary_calls` unbounded-target
/// tracking in `host.rs`, which only covers `CallScheme::Call`, not
/// `DelegateCall`.
#[derive(Clone, Debug, Default)]
pub struct DelegatecallInjectionTracer;

impl DelegatecallInjectionTracer {
    pub fn new() -> Self {
        Self
    }
}

impl<SC> Middleware<SC> for DelegatecallInjectionTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        if *interp.instruction_pointer != 0xf4 {
            // DELEGATECALL
            return;
        }
        let target = convert_u256_to_h160(interp.stack.peek(1).unwrap());
        let caller = interp.contract.address;
        let pc = interp.program_counter();

        let targets = host.pc_to_delegatecall_targets.entry((caller, pc)).or_default();
        targets.insert(target);

        if targets.len() > DELEGATECALL_INJECTION_THRESHOLD {
            host.current_delegatecall_injections.insert((caller, pc));
        }
    }}

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::DelegatecallInjection
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
