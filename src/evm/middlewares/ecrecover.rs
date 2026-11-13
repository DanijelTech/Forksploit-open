use std::any;

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{convert_u256_to_h160, EVMAddress, EVMFuzzState},
};

const STATICCALL_OP: u8 = 0xfa;
const CALL_OP: u8 = 0xf1;

fn ecrecover_address() -> EVMAddress {
    let mut bytes = [0u8; 20];
    bytes[19] = 1;
    EVMAddress::from_slice(&bytes)
}

/// Detects the classic "unchecked ecrecover(0)" bug: a contract calls the
/// `ecrecover` precompile (address `0x...01`) with a garbage/invalid
/// signature, which per the EVM spec makes it return the zero address, and
/// the caller's transaction succeeds anyway instead of reverting on
/// `signer == address(0)`. This is especially dangerous when an
/// `owner`/`signer` state variable was never initialized (still zero),
/// since *any* invalid signature then satisfies `ecrecover(...) == owner`.
///
/// Implementation: `on_step` notes when a STATICCALL/CALL is about to
/// target the ecrecover precompile; the *very next* `on_return` is
/// guaranteed to be that same call's result, since precompiles have no
/// bytecode of their own and thus cannot make nested calls that would
/// otherwise intervene between the two hooks.
#[derive(Clone, Debug, Default)]
pub struct EcrecoverZeroTracer {
    pending: Option<(EVMAddress, usize)>,
}

impl EcrecoverZeroTracer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<SC> Middleware<SC> for EcrecoverZeroTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, _host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) { unsafe {
        let op = *interp.instruction_pointer;
        let addr_stack_idx = match op {
            STATICCALL_OP => 1,
            CALL_OP => 1,
            _ => return,
        };
        let target = convert_u256_to_h160(interp.stack.peek(addr_stack_idx).unwrap());
        if target == ecrecover_address() {
            self.pending = Some((interp.contract.address, interp.program_counter()));
        }
    }}

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        ret: &Bytes,
    ) {
        if let Some((caller, pc)) = self.pending.take() {
            // revm's ecrecover precompile returns an EMPTY result when `v`/`r`/`s`
            // fail the basic range check (see revm-precompile's secp256k1.rs), and
            // 32 zero bytes when the range check passes but the EC math itself
            // fails to recover a key. Solidity's `ecrecover(...)` wrapper treats
            // both as `address(0)`.
            let is_zero_address = ret.is_empty() || (ret.len() == 32 && ret.iter().all(|b| *b == 0));
            if is_zero_address {
                host.current_ecrecover_zero.insert((caller, pc));
            }
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::EcrecoverZero
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}
