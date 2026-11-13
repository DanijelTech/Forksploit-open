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

/// A real, verified (not guessed -- see the aave-dao/aave-address-book
/// lookup done live before this was written) Aave V3 asset on a given
/// chain id: its underlying ERC20 and the aToken contract that actually
/// holds the pooled liquidity depositors supplied (Aave's `Pool` contract
/// itself does not hold the underlying balance; each aToken does).
struct AaveAsset {
    chain_id: u32,
    underlying: &'static str,
    a_token: &'static str,
}

/// Deliberately a small, hardcoded, easy-to-extend table rather than a
/// live `Pool.getReservesList()` query -- this is step 1 of teaching the
/// fuzzer to borrow from Aave during its OWN discovery/simulation (not
/// just reproduce an already-found bug for real, which
/// `onchain_scripts/aave_flashloan_runner.py` already does). Extending
/// this to other assets/chains, or to a dynamic on-chain lookup, is a
/// follow-up.
///
/// The 5 ETH mainnet entries below were NOT taken from any address list
/// (a pasted candidate list was checked against this live source first
/// and every single one of its aToken addresses turned out wrong --
/// including one that wasn't even valid hex). Each was derived directly
/// from the real Aave V3 Pool contract itself
/// (`0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2`, confirmed live: real
/// bytecode, a proxy exposing `getReservesList()` which returned 67 real
/// reserves starting with WETH/wstETH/WBTC/USDC/DAI/LINK), via
/// `getReserveData(asset)` -- the aTokenAddress field (word 8 of the
/// packed struct) -- then cross-checked by confirming each aToken
/// genuinely holds a large non-zero real balance of its own underlying
/// (e.g. the WETH aToken held ~397,565 WETH at verification time).
const KNOWN_AAVE_ASSETS: &[AaveAsset] = &[
    // Sepolia (11155111), DAI -- https://sepolia.etherscan.io/address/0xFF34B3d4Aee8ddCd6F9AFFFB6Fe49bD371b8a357
    AaveAsset {
        chain_id: 11155111,
        underlying: "0xFF34B3d4Aee8ddCd6F9AFFFB6Fe49bD371b8a357",
        a_token: "0x29598b72eb5CeBd806C5dCD549490FdA35B13cD8",
    },
    // Ethereum mainnet (1), WETH
    AaveAsset {
        chain_id: 1,
        underlying: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        a_token: "0x4d5f47Fa6A74757f35C14fD3a6Ef8E3C9BC514E8",
    },
    // Ethereum mainnet (1), USDC
    AaveAsset {
        chain_id: 1,
        underlying: "0xA0b86991c6218b36c1d19D4A2e9Eb0cE3606eB48",
        a_token: "0x98C23E9d8f34FEFb1B7BD6a91B7FF122F4e16F5c",
    },
    // Ethereum mainnet (1), DAI
    AaveAsset {
        chain_id: 1,
        underlying: "0x6B175474E89094C44Da98b954EEdeac495271d0F",
        a_token: "0x018008bfb33d285247a21d44e50697654f754e63",
    },
    // Ethereum mainnet (1), USDT
    AaveAsset {
        chain_id: 1,
        underlying: "0xdAC17F958D2ee523a2206206994597C13D831Ec7",
        a_token: "0x23878914EFE38d27C4D67Ab83ed1b93A74D4086a",
    },
    // Ethereum mainnet (1), WBTC
    AaveAsset {
        chain_id: 1,
        underlying: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        a_token: "0x5Ee5bf7ae06D1Be5997A1A72006FE6C607eC6DE8",
    },
    // BSC (56), Polygon (137), Arbitrum (42161), and Optimism (10) below:
    // same derivation method as the ETH mainnet entries above (real Pool
    // address's own getReservesList()/getReserveData(asset), aToken =
    // word 8 of the packed struct), each cross-checked by confirming the
    // aToken holds a large non-zero real balance of its own underlying at
    // verification time. The Pool address genuinely IS the same
    // 0x794a61358D6845594F94dc1DB02A252b5b4814aD on Polygon/Arbitrum/
    // Optimism (confirmed live on each chain separately, not assumed from
    // one match) -- Aave V3's deployer reuses it deterministically, same
    // as several of these very aTokens (DAI/WETH/the older "bridged"
    // USDC all share one identical address across these three chains
    // too). Arbitrum/Optimism each have TWO real USDC reserves (a legacy
    // bridged one and Circle's native one, confirmed via symbol() on
    // both); the native one is used below since it now holds materially
    // more real liquidity on both chains.
    //
    // BSC (56), WBNB
    AaveAsset {
        chain_id: 56,
        underlying: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
        a_token: "0x9B00a09492a626678E5A3009982191586c444Df9",
    },
    // BSC (56), USDT
    AaveAsset {
        chain_id: 56,
        underlying: "0x55d398326f99059fF775485246999027B3197955",
        a_token: "0xA9251ca9DE909CB71783723713B21E4233fbf1B1",
    },
    // BSC (56), USDC
    AaveAsset {
        chain_id: 56,
        underlying: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
        a_token: "0x00901a076785e0906d1028c7d6372d247bEc7D61",
    },
    // Polygon (137), DAI
    AaveAsset {
        chain_id: 137,
        underlying: "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063",
        a_token: "0x82E64f49Ed5EC1bC6e43dAd4FC8Af9bb3A2312EE",
    },
    // Polygon (137), USDC
    AaveAsset {
        chain_id: 137,
        underlying: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
        a_token: "0x625E7708f30cA75bfd92586e17077590C60eb4cD",
    },
    // Polygon (137), WETH
    AaveAsset {
        chain_id: 137,
        underlying: "0x7ceB23fD6bC0adD59E62ac25578270cff1b9f619",
        a_token: "0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8",
    },
    // Polygon (137), WBTC
    AaveAsset {
        chain_id: 137,
        underlying: "0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6",
        a_token: "0x078f358208685046a11C85e8ad32895DED33A249",
    },
    // Arbitrum (42161), DAI
    AaveAsset {
        chain_id: 42161,
        underlying: "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1",
        a_token: "0x82E64f49Ed5EC1bC6e43dAd4FC8Af9bb3A2312EE",
    },
    // Arbitrum (42161), WETH
    AaveAsset {
        chain_id: 42161,
        underlying: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
        a_token: "0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8",
    },
    // Arbitrum (42161), USDC (native)
    AaveAsset {
        chain_id: 42161,
        underlying: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        a_token: "0x724dc807b04555b71ed48a6896B6F41593b8C637",
    },
    // Optimism (10), DAI
    AaveAsset {
        chain_id: 10,
        underlying: "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1",
        a_token: "0x82E64f49Ed5EC1bC6e43dAd4FC8Af9bb3A2312EE",
    },
    // Optimism (10), WETH
    AaveAsset {
        chain_id: 10,
        underlying: "0x4200000000000000000000000000000000000006",
        a_token: "0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8",
    },
    // Optimism (10), USDC (native)
    AaveAsset {
        chain_id: 10,
        underlying: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
        a_token: "0x38d693cE1dF5AaDF7bC62595A37D667aD57922e5",
    },
];

#[derive(Clone, Debug)]
pub struct AaveBorrowContext {
    pub underlying: EVMAddress,
    pub a_token: EVMAddress,
}

/// Looks up whether `token` is a known Aave V3 underlying asset on the
/// chain being fuzzed (identified by `chain_id`, e.g. 11155111 for
/// Sepolia -- see `ChainConfig::get_chain_id_for_borrow`).
pub fn find_aave_asset(chain_id: u32, token: EVMAddress) -> Option<AaveBorrowContext> {
    KNOWN_AAVE_ASSETS.iter().find_map(|asset| {
        if asset.chain_id != chain_id {
            return None;
        }
        let underlying = EVMAddress::from_str(asset.underlying).ok()?;
        if underlying != token {
            return None;
        }
        Some(AaveBorrowContext {
            underlying,
            a_token: EVMAddress::from_str(asset.a_token).ok()?,
        })
    })
}

impl AaveBorrowContext {
    /// Credits `to` with `amount` of the underlying asset, exactly the
    /// same way `UniswapPairContext::initial_transfer` credits a buyer:
    /// a REAL, simulated `transfer(to, amount)` call against the asset's
    /// own real bytecode, with the CALLER set to the aToken address that
    /// genuinely holds the pooled liquidity on the forked chain. If the
    /// aToken doesn't actually have `amount` available, the real
    /// transfer() logic reverts on its own -- the same natural "capped by
    /// real liquidity" behavior a Uniswap pair already has, no separate
    /// balance check needed.
    ///
    /// This does not model repayment at all (same simplification the
    /// existing Uniswap "buy" already makes for swap atomicity): for
    /// DISCOVERY purposes, the premium is an acceptable rounding error,
    /// not something enforced mid-simulation. A bug found this way is
    /// then verified to actually survive a REAL atomic borrow+repay by
    /// `onchain_scripts/aave_flashloan_runner.py` before anyone trusts it.
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
            get_code_tokens!(self.underlying, vm, state),
            &CallContext {
                address: self.underlying,
                caller: self.a_token,
                code_address: self.underlying,
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

    /// Guards the BSC/Polygon/Arbitrum/Optimism entries added after this
    /// was ETH-mainnet-and-Sepolia-only: a typo'd chain_id or underlying
    /// address here would silently make Aave-flashloan discovery never
    /// fire for that asset, with no error anywhere to notice it.
    #[test]
    fn test_find_aave_asset_known_mainnet_chains() {
        let cases: [(u32, &str, &str); 7] = [
            (56, "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "0x9B00a09492a626678E5A3009982191586c444Df9"), // BSC WBNB
            (56, "0x55d398326f99059fF775485246999027B3197955", "0xA9251ca9DE909CB71783723713B21E4233fbf1B1"), // BSC USDT
            (137, "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", "0x82E64f49Ed5EC1bC6e43dAd4FC8Af9bb3A2312EE"), // Polygon DAI
            (137, "0x7ceB23fD6bC0adD59E62ac25578270cff1b9f619", "0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8"), // Polygon WETH
            (42161, "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8"), // Arbitrum WETH
            (42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "0x724dc807b04555b71ed48a6896B6F41593b8C637"), // Arbitrum native USDC
            (10, "0x4200000000000000000000000000000000000006", "0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8"), // Optimism WETH
        ];
        for (chain_id, underlying, expected_a_token) in cases {
            let token = EVMAddress::from_str(underlying).unwrap();
            let ctx = find_aave_asset(chain_id, token)
                .unwrap_or_else(|| panic!("expected an Aave asset entry for chain_id {chain_id}, token {underlying}"));
            assert_eq!(ctx.underlying, token);
            assert_eq!(ctx.a_token, EVMAddress::from_str(expected_a_token).unwrap());
        }
    }

    #[test]
    fn test_find_aave_asset_unknown_token_returns_none() {
        let token = EVMAddress::from_str("0x0000000000000000000000000000000000000001").unwrap();
        assert!(find_aave_asset(56, token).is_none());
    }
}
