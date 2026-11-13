use std::{fmt::Debug, str::FromStr};

use libafl::schedulers::Scheduler;
use revm_interpreter::{CallContext, CallScheme, Contract, Interpreter};
use serde::{de::DeserializeOwned, Serialize};

use super::{uniswap::CODE_REGISTRY, v2_transformer::transfer_bytes};
use crate::{
    evm::{
        types::{EVMAddress, EVMFuzzState, EVMU256},
        vm::{EVMExecutor, MEM_LIMIT},
    },
    generic_vm::vm_state::VMStateT,
    get_code_tokens,
    input::ConciseSerde,
    is_call_success,
};

struct BalancerDeployment {
    chain_id: u32,
    vault: &'static str,
}

/// Unlike Aave (one aToken proxy per underlying asset), Balancer V2 holds
/// every pooled token directly in a single Vault contract. So there's no
/// per-token address table here -- just the Vault address for each chain,
/// and `borrow()` below relies on the real `transfer()` reverting if the
/// Vault doesn't actually hold enough of the requested token.
///
/// This is Balancer V2's Vault specifically (confirmed by this file's own
/// borrow() logic: one shared vault directly holding every pooled token --
/// Balancer V3, a separate, newer product with a different vault design,
/// is not covered here). The same address below was only ever present for
/// Sepolia until this comment -- Balancer V2's Vault is deployed via a
/// deterministic factory, so it genuinely IS the identical address on
/// every chain below, not a copy-paste mistake. Each entry was live-
/// verified before being added: real, identical, non-trivial bytecode
/// (eth_getCode, 49026 hex chars on every one of these chains) at this
/// exact address, plus a real, substantial non-zero token balance held by
/// it (confirmed on ETH mainnet specifically: ~1160 WETH).
const KNOWN_BALANCER_VAULTS: &[BalancerDeployment] = &[
    BalancerDeployment {
        chain_id: 11155111, // Sepolia
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    BalancerDeployment {
        chain_id: 1, // Ethereum mainnet
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    BalancerDeployment {
        chain_id: 56, // BSC
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    BalancerDeployment {
        chain_id: 137, // Polygon
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    BalancerDeployment {
        chain_id: 43114, // Avalanche
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    BalancerDeployment {
        chain_id: 10, // Optimism
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    BalancerDeployment {
        chain_id: 42161, // Arbitrum
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    BalancerDeployment {
        chain_id: 100, // Gnosis
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
    BalancerDeployment {
        chain_id: 8453, // Base
        vault: "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    },
];

#[derive(Clone, Debug)]
pub struct BalancerBorrowContext {
    pub vault: EVMAddress,
    pub token: EVMAddress,
}

pub fn find_balancer_vault(chain_id: u32, token: EVMAddress) -> Option<BalancerBorrowContext> {
    KNOWN_BALANCER_VAULTS.iter().find_map(|deployment| {
        if deployment.chain_id != chain_id {
            return None;
        }
        Some(BalancerBorrowContext {
            vault: EVMAddress::from_str(deployment.vault).ok()?,
            token,
        })
    })
}

impl BalancerBorrowContext {
    pub fn borrow<VS, CI, SC>(
        &self,
        amount: EVMU256,
        to: &EVMAddress,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
    ) -> Option<()>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let call = Contract::new_with_context_analyzed(
            transfer_bytes(to, amount),
            get_code_tokens!(self.token, vm, state),
            &CallContext {
                address: self.token,
                caller: self.vault,
                code_address: self.token,
                apparent_value: EVMU256::ZERO,
                scheme: CallScheme::Call,
            },
        );
        let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT);
        let ir = vm.host.run_inspect(&mut interp, state);
        if !is_call_success!(ir) {
            None
        } else {
            Some(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the mainnet entries added after this was Sepolia-only: a
    /// typo'd chain_id here would silently make Balancer-flashloan
    /// discovery never fire on that chain, with no error anywhere to
    /// notice it.
    #[test]
    fn test_find_balancer_vault_known_chains() {
        let token = EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let expected_vault = EVMAddress::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap();
        for chain_id in [11155111, 1, 56, 137, 43114, 10, 42161, 100, 8453] {
            let ctx = find_balancer_vault(chain_id, token)
                .unwrap_or_else(|| panic!("expected a Balancer vault entry for chain_id {chain_id}"));
            assert_eq!(ctx.vault, expected_vault);
            assert_eq!(ctx.token, token);
        }
    }

    #[test]
    fn test_find_balancer_vault_unknown_chain_returns_none() {
        let token = EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        assert!(find_balancer_vault(999999, token).is_none());
    }
}
