use std::{cell::RefCell, rc::Rc, str::FromStr, sync::Arc};

use bytes::Bytes;

use super::{
    uniswap::CODE_REGISTRY,
    weth_transformer::WethContext,
    v2_transformer::UniswapPairContext,
    PairContextTy,
    PathContext,
    TokenContext,
    UniswapInfo,
};
use crate::evm::{
    onchain::{endpoints::{OnChainConfig, PairData}, ChainConfig},
    types::{EVMAddress, EVMU256},
};

/// A Uniswap-V2-shaped DEX factory this module knows how to query directly
/// on-chain, bypassing DanyTech's own pairs-all.infra.danytech indexing
/// service entirely (see module doc below for why that matters).
struct V2FactoryConfig {
    chain_id: u32,
    /// The Factory contract (exposes `getPair(address,address)`).
    factory: &'static str,
    /// The chain's wrapped-native/base token to look for a direct pair
    /// against (this module only finds a *direct* pair with this one
    /// token -- no multi-hop routing).
    base_token: &'static str,
    /// Swap fee in basis points out of 10000 (e.g. 30 = 0.3%, the
    /// standard, un-modified Uniswap V2 fee). Most V2 forks keep this
    /// unchanged; verify against the actual Pair contract's source if a
    /// given fork is known to differ.
    pool_fee_bps: usize,
    /// The key `get_uniswap_info()` (tokens/mod.rs) uses to look up the
    /// SAME fee/router info, for the PairData-shaped path produced by
    /// `fetch_pegged_pair_data_onchain` below (the TokenContext-shaped
    /// path above sets `pool_fee_bps` directly instead and never touches
    /// this). Must be one of that function's known keys or it panics --
    /// added "etcswapv2_etc" there since nothing else covered ETC.
    src_exact: &'static str,
}

/// Every entry below was verified live, directly on-chain, the same way as
/// ETC's (not copied from docs/memory without checking): the factory has
/// real bytecode, `allPairsLength()` returns a realistic pair count, and
/// `getPair(base_token, some_well_known_token)` resolves to a real pair
/// contract whose `getReserves()` is non-zero. Still only single-hop
/// (direct pairing with `base_token`) -- the reach of this module hasn't
/// changed, only how many chains it covers.
///
/// - ETC (chain 61): ETCswap V2 Factory `0x0307cd...`, 104 pairs at
///   verification time. WETC `0x1953ca...` has real bytecode, `symbol()`
///   decodes to "WETC".
/// - ETH (chain 1): Uniswap V2 Factory `0x5C69bE...` (the original,
///   canonical deployment), 526,387 pairs. `getPair(WETH, USDC)` resolved
///   to the well-known WETH/USDC pair with real, non-zero reserves.
/// - BSC (chain 56): PancakeSwap V2 Factory `0xcA143C...`, 3,577,549
///   pairs. `getPair(WBNB, USDT)` resolved to a real, non-zero-reserve
///   pair.
/// - Polygon (chain 137): QuickSwap V2 Factory `0x575737...` (a
///   byte-for-byte Uniswap V2 fork -- its bytecode's embedded revert
///   strings still literally say "UniswapV2: ..."), 135,690 pairs.
///   `getPair(WMATIC, USDC)` resolved to a real, non-zero-reserve pair.
/// - Arbitrum (chain 42161): SushiSwap V2 Factory `0xc35DAD...`, 32,938
///   pairs. `getPair(WETH, USDC.e)` resolved to a real, non-zero-reserve
///   pair.
/// - Celo (chain 42220): Ubeswap V2 Factory `0x62d5b8...`, 882 pairs.
///   `allPairs(0)` returned a pair with token0 == the real, verified CELO
///   address (bytecode + `symbol()` both confirmed) and non-zero
///   `getReserves()`.
const KNOWN_V2_FACTORIES: &[V2FactoryConfig] = &[
    V2FactoryConfig {
        chain_id: 61, // Ethereum Classic
        factory: "0x0307cd3D7DA98A29e6Ed0D2137be386Ec1e4Bc9C",
        base_token: "0x1953cab0E5bFa6D4a9BaD6E05fD46C1CC6527a5a", // WETC
        pool_fee_bps: 30,
        src_exact: "etcswapv2_etc",
    },
    V2FactoryConfig {
        chain_id: 1, // Ethereum mainnet
        factory: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        base_token: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
        pool_fee_bps: 30,
        src_exact: "uniswapv2_eth",
    },
    V2FactoryConfig {
        chain_id: 56, // BNB Smart Chain
        factory: "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
        base_token: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", // WBNB
        pool_fee_bps: 25, // PancakeSwap V2's own fee, not the Uniswap-default 30
        src_exact: "pancakeswapv2_bsc",
    },
    V2FactoryConfig {
        chain_id: 137, // Polygon
        factory: "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32",
        base_token: "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", // WMATIC
        pool_fee_bps: 30,
        src_exact: "quickswapv2_polygon",
    },
    V2FactoryConfig {
        chain_id: 42161, // Arbitrum One
        factory: "0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
        base_token: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", // WETH
        pool_fee_bps: 30,
        src_exact: "sushiswapv2_arb",
    },
    V2FactoryConfig {
        chain_id: 42220, // Celo
        factory: "0x62d5b84bE28a183aBB507E125B384122D2C25fAE",
        base_token: "0x471EcE3750Da237f93B8E339c536989b8978a438", // CELO
        pool_fee_bps: 30,
        src_exact: "ubeswapv2_celo",
    },
];

/// Raw result of a Factory+Pair query, shared by both
/// `fetch_pegged_pair_onchain` (TokenContext-shaped, used by Flashloan)
/// and `fetch_pegged_pair_data_onchain` (PairData-shaped, used as
/// OnChainConfig::get_pair's fallback) so the actual `eth_call` sequence
/// -- `getPair`, `token0`, `getReserves` -- exists exactly once.
struct OnchainPairLookup {
    pair: EVMAddress,
    token0: EVMAddress,
    reserve0: EVMU256,
    reserve1: EVMU256,
}

fn lookup_pair_onchain(
    chain: &mut dyn ChainConfig,
    factory: EVMAddress,
    base_token: EVMAddress,
    token_address: EVMAddress,
) -> Option<OnchainPairLookup> {
    if token_address == base_token {
        // The token itself IS the chain's base token -- not this
        // function's job (that's what TokenContext::is_weth / the
        // "pegged_weth" PairData src cover instead).
        return None;
    }

    // getPair(address,address) -- selector 0xe6a43905
    let mut call_data = vec![0xe6, 0xa4, 0x39, 0x05];
    call_data.extend_from_slice(&[0u8; 12]);
    call_data.extend_from_slice(token_address.as_slice());
    call_data.extend_from_slice(&[0u8; 12]);
    call_data.extend_from_slice(base_token.as_slice());
    let pair_result = chain.eth_call(factory, Bytes::from(call_data));
    if pair_result.len() < 32 {
        return None;
    }
    let pair = EVMAddress::from_slice(&pair_result[12..32]);
    if pair == EVMAddress::zero() {
        // Factory has no such pair registered at all.
        return None;
    }

    // token0() -- selector 0x0dfe1681
    let token0_result = chain.eth_call(pair, Bytes::from(vec![0x0d, 0xfe, 0x16, 0x81]));
    if token0_result.len() < 32 {
        return None;
    }
    let token0 = EVMAddress::from_slice(&token0_result[12..32]);

    // getReserves() -- selector 0x0902f1ac, returns (uint112, uint112, uint32)
    let reserves_result = chain.eth_call(pair, Bytes::from(vec![0x09, 0x02, 0xf1, 0xac]));
    if reserves_result.len() < 64 {
        return None;
    }
    let reserve0 = EVMU256::from_be_slice(&reserves_result[0..32]);
    let reserve1 = EVMU256::from_be_slice(&reserves_result[32..64]);
    if reserve0 == EVMU256::ZERO || reserve1 == EVMU256::ZERO {
        // Pair exists but is drained/never seeded -- nothing real to borrow.
        return None;
    }

    Some(OnchainPairLookup {
        pair,
        token0,
        reserve0,
        reserve1,
    })
}

/// Finds a *direct* pair between `token_address` and a chain's known base
/// token by calling the real Factory and Pair contracts over RPC --
/// `getPair`, `token0`, `getReserves` -- instead of asking a third-party
/// indexing service.
///
/// Why this exists: `fetch_uniswap_path` (uniswap.rs, via `find_path_onchain`)
/// and `OnChainConfig::get_pair` (endpoints.rs) used to get their routes from
/// `https://pairs-all.infra.danytech`, a service owned and operated by the
/// upstream DanyTech project, not this one. That service is no longer called
/// anywhere in this codebase, under any condition -- not as a first attempt,
/// not as a fallback. It was the service responsible for 3 of this project's
/// own persistently-failing tests (it returns malformed/empty responses for
/// some queries, and was observed fully down -- Cloudflare 522 -- while this
/// was being removed). It also never indexed Ethereum Classic at all -- ETC
/// is not a chain DanyTech's own infra was ever built to support -- so
/// discovery-time borrowing there would have stayed broken regardless of
/// chain config, even if ETC had a real Aave/Balancer-equivalent lending
/// protocol (it doesn't -- checked both official docs and on-chain; the only
/// "Aave"/"Balancer"-named tokens on ETC are unrelated/unverified, not the
/// real protocols).
///
/// This only covers the single-hop, directly-paired-with-base-token case
/// (no multi-hop routing through intermediate pairs, unlike the old
/// subgraph-based version) -- but that's the common case for "does this token have any
/// real DEX liquidity at all", and needs zero third-party infrastructure.
/// The chain's own wrapped-native/base token address, if `chain_id` is one
/// `KNOWN_V2_FACTORIES` covers -- a real, independently useful fact on its
/// own (not just a helper for `fetch_pegged_pair_onchain` below). Used to
/// seed the fuzzer's caller/address pools with a REAL token address for
/// this chain (see `evm_fuzzer.rs`): confirmed live that a fresh DEX
/// factory's `createPair(tokenA, tokenB)` never gets called with two
/// valid, distinct token addresses by random mutation alone (astronomically
/// unlikely to guess two specific 160-bit values), so coverage of that
/// whole code path -- and any pair ever getting created in the simulation
/// -- plateaus indefinitely without some real address to start from.
pub fn known_base_token(chain_id: u32) -> Option<EVMAddress> {
    let cfg = KNOWN_V2_FACTORIES.iter().find(|f| f.chain_id == chain_id)?;
    EVMAddress::from_str(cfg.base_token).ok()
}

pub fn fetch_pegged_pair_onchain(chain: &mut Box<dyn ChainConfig>, token_address: EVMAddress) -> Option<TokenContext> {
    let chain_id = chain.get_chain_id_for_borrow();
    let cfg = KNOWN_V2_FACTORIES.iter().find(|f| f.chain_id == chain_id)?;
    let factory = EVMAddress::from_str(cfg.factory).ok()?;
    let base_token = EVMAddress::from_str(cfg.base_token).ok()?;
    let lookup = lookup_pair_onchain(chain.as_mut(), factory, base_token, token_address)?;

    let side: u8 = if lookup.token0 == token_address { 0 } else { 1 };

    // Register real bytecode for the pair and the base token so the
    // simulated transfer() calls in v2_transformer.rs can execute against
    // them later.
    let pair_code = chain.get_contract_code_analyzed(lookup.pair, false);
    let base_code = chain.get_contract_code_analyzed(base_token, false);
    CODE_REGISTRY.lock().unwrap().insert(lookup.pair, pair_code);
    CODE_REGISTRY.lock().unwrap().insert(base_token, base_code);

    let inner = UniswapPairContext {
        pair_address: lookup.pair,
        in_token_address: token_address,
        next_hop: base_token,
        side,
        uniswap_info: Arc::new(UniswapInfo {
            pool_fee: cfg.pool_fee_bps,
            router: None,
        }),
        initial_reserves: (lookup.reserve0, lookup.reserve1),
    };

    let path = PathContext {
        route: vec![
            PairContextTy::Uniswap(Rc::new(RefCell::new(inner))),
            PairContextTy::Weth(Rc::new(RefCell::new(WethContext { weth_address: base_token }))),
        ],
    };

    Some(TokenContext {
        swaps: vec![path],
        is_weth: false,
        weth_address: base_token,
        aave_borrow: None,
        balancer_borrow: None,
    })
}

/// Same on-chain lookup as `fetch_pegged_pair_onchain` above, but shaped
/// as the lower-level `PairData` that `OnChainConfig::get_pair()`
/// (endpoints.rs) used to get from DanyTech's subgraph -- this is now
/// that function's ONLY source of pairs, not a fallback, so `get_pair`/
/// `fetch_uniswap_path` (uniswap.rs), not just Flashloan, never touch
/// DanyTech at all. `interface: "uniswapv2"` and the two `src` values
/// used below (`"pegged"`, `"lp"`) are exact strings uniswap.rs pattern-
/// matches on (see its `with_paths`'s `match pair.src.as_str()`) --
/// anything else panics or is silently mishandled, so these aren't
/// free-form labels. Critically, `"pegged"` additionally asserts
/// `pair.next == basic_info.weth` downstream -- so ONLY the entry for
/// the chain's actual base/WETH-equivalent token may use it; every other
/// intermediate token below uses `"lp"` instead (an ordinary pair, nothing
/// pegged about it), or that assertion panics.
///
/// Checks the queried token against the chain's base/WETH-equivalent
/// token (from `KNOWN_V2_FACTORIES`) AND every other well-known pegged
/// token this chain already has in `get_pegged_token()` (USDC, DAI,
/// USDT, WBTC, ...) -- not just the one base token. This is what
/// actually lets `uniswap.rs`'s existing `get_all_hops`/`dfs`
/// (`MAX_HOPS=2`) multi-hop structure find anything beyond a single
/// direct-to-base hop: that traversal code already existed, but with
/// only one candidate checked per token, it could never discover an
/// intermediate pair (token -> USDC, say) to traverse through in the
/// first place.
///
/// Needs real `decimals()` for both tokens (two more `eth_call`s per
/// candidate) on top of what `lookup_pair_onchain` already fetches,
/// since `PairData` carries them and downstream liquidity comparisons
/// divide by `10^decimals`. A failed decimals() call skips that one
/// candidate (no guessed/default decimals) -- same "don't fabricate
/// data" standard as the zero-reserves check in `lookup_pair_onchain`;
/// it does not abort the other candidates.
pub fn fetch_pegged_pair_data_onchain(chain: &mut OnChainConfig, token: &str) -> Vec<PairData> {
    let Some(cfg) = KNOWN_V2_FACTORIES.iter().find(|f| f.chain_id == chain.chain_id) else {
        return vec![];
    };
    let Ok(token_address) = EVMAddress::from_str(token) else {
        return vec![];
    };
    let Ok(factory) = EVMAddress::from_str(cfg.factory) else {
        return vec![];
    };
    let Ok(weth) = EVMAddress::from_str(cfg.base_token) else {
        return vec![];
    };

    let mut candidates: Vec<EVMAddress> = vec![weth];
    for addr_str in chain.get_pegged_token().values() {
        if let Ok(addr) = EVMAddress::from_str(addr_str) {
            if !candidates.contains(&addr) {
                candidates.push(addr);
            }
        }
    }

    // decimals() -- selector 0x313ce567
    fn decimals_of(chain: &mut OnChainConfig, addr: EVMAddress) -> Option<u32> {
        let result = chain.eth_call(addr, Bytes::from(vec![0x31, 0x3c, 0xe5, 0x67]));
        if result.len() < 32 {
            return None;
        }
        Some(EVMU256::from_be_slice(&result[0..32]).as_limbs()[0] as u32)
    }

    let mut results = vec![];
    for base_token in candidates {
        let Some(lookup) = lookup_pair_onchain(chain, factory, base_token, token_address) else {
            continue;
        };
        let token1 = if lookup.token0 == token_address { base_token } else { token_address };
        let (Some(decimals_0), Some(decimals_1)) = (decimals_of(chain, lookup.token0), decimals_of(chain, token1)) else {
            continue;
        };
        let in_ = if lookup.token0 == token_address { 0 } else { 1 };
        results.push(PairData {
            src: if base_token == weth { "pegged" } else { "lp" }.to_string(),
            in_,
            pair: format!("{:?}", lookup.pair).to_lowercase(),
            in_token: token.to_lowercase(),
            next: format!("{:?}", base_token).to_lowercase(),
            interface: "uniswapv2".to_string(),
            src_exact: cfg.src_exact.to_string(),
            initial_reserves_0: lookup.reserve0,
            initial_reserves_1: lookup.reserve1,
            decimals_0,
            decimals_1,
            token0: format!("{:?}", lookup.token0).to_lowercase(),
            token1: format!("{:?}", token1).to_lowercase(),
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::onchain::endpoints::{
        Chain::{ARBITRUM, BSC, CELO, ETC, ETH, POLYGON},
        OnChainConfig,
    };

    /// Builds a config pinned a small margin behind the chain's own
    /// current head, instead of a hardcoded historical block: every
    /// public RPC this project defaults to (bsc-rpc.publicnode.com
    /// confirmed directly, live, while writing this test -- see the
    /// commit this test shipped in) now refuses `eth_call` at a block
    /// more than roughly a few hundred thousand blocks behind head with
    /// "Archive requests require a personal token" -- a paywall that
    /// didn't exist when this project's OLDER tests pinned fixed historical
    /// blocks (those still "pass" today only because they assert nothing
    /// about the RPC response). Staying near head avoids that paywall
    /// entirely and never goes stale.
    fn fresh_config(chain: crate::evm::onchain::endpoints::Chain) -> Box<dyn ChainConfig> {
        let mut probe = OnChainConfig::new(chain, 0);
        probe.set_latest_block_number();
        let latest = u64::from_str_radix(probe.block_number.trim_start_matches("0x"), 16)
            .expect("RPC returned a malformed latest block number");
        // Margin matters in BOTH directions, confirmed live while writing
        // this test: too small (e.g. 0-2) risks a backend-replica-lag
        // "block not found" on publicnode's load-balanced backends, but
        // Polygon's publicnode specifically paywalls ANY eth_call pinned
        // more than ~100 blocks behind head ("Archive requests require a
        // personal token" starting at margin=100, still free at margin=80
        // -- almost certainly bor/geth's default 128-block non-archive
        // state retention). BSC/ETH/Arbitrum's endpoints tolerate a much
        // deeper margin, but 20 stays safely within ALL four chains'
        // windows, so one shared constant works everywhere.
        Box::new(OnChainConfig::new(chain, latest.saturating_sub(20)))
    }

    /// Same as `fresh_config`, but returns the concrete `OnChainConfig`
    /// `fetch_pegged_pair_data_onchain`/`get_pair` need directly (they
    /// take `&mut OnChainConfig`, not `&mut dyn ChainConfig`).
    fn fresh_onchain_config(chain: crate::evm::onchain::endpoints::Chain) -> OnChainConfig {
        let mut probe = OnChainConfig::new(chain, 0);
        probe.set_latest_block_number();
        let latest = u64::from_str_radix(probe.block_number.trim_start_matches("0x"), 16)
            .expect("RPC returned a malformed latest block number");
        OnChainConfig::new(chain, latest.saturating_sub(20))
    }

    #[test]
    fn test_fetch_pegged_pair_onchain_eth() {
        let mut chain = fresh_config(ETH);
        // USDC -- real, long-established direct pair against WETH on
        // Uniswap V2 mainnet (factory 0x5C69bE..., live-verified
        // separately: allPairsLength in the hundreds of thousands).
        let token = EVMAddress::from_str("0xA0b86991c6218b36c1d19D4A2e9Eb0cE3606eB48").unwrap();
        let ctx = fetch_pegged_pair_onchain(&mut chain, token).expect("expected a real WETH/USDC pair on ETH mainnet");
        assert!(!ctx.swaps.is_empty());
        assert_eq!(ctx.weth_address, EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap());
    }

    #[test]
    fn test_fetch_pegged_pair_onchain_bsc() {
        let mut chain = fresh_config(BSC);
        // USDT -- real, long-established direct pair against WBNB on
        // PancakeSwap V2 (factory 0xcA143C...).
        let token = EVMAddress::from_str("0x55d398326f99059fF775485246999027B3197955").unwrap();
        let ctx = fetch_pegged_pair_onchain(&mut chain, token).expect("expected a real WBNB/USDT pair on BSC");
        assert!(!ctx.swaps.is_empty());
        assert_eq!(ctx.weth_address, EVMAddress::from_str("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c").unwrap());
    }

    #[test]
    fn test_fetch_pegged_pair_onchain_polygon() {
        let mut chain = fresh_config(POLYGON);
        // Bridged USDC -- real, long-established direct pair against
        // WMATIC on QuickSwap V2 (factory 0x575737..., a byte-for-byte
        // Uniswap V2 fork).
        let token = EVMAddress::from_str("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174").unwrap();
        let ctx = fetch_pegged_pair_onchain(&mut chain, token).expect("expected a real WMATIC/USDC pair on Polygon");
        assert!(!ctx.swaps.is_empty());
        assert_eq!(ctx.weth_address, EVMAddress::from_str("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270").unwrap());
    }

    #[test]
    fn test_fetch_pegged_pair_onchain_arbitrum() {
        let mut chain = fresh_config(ARBITRUM);
        // USDC.e -- real, long-established direct pair against WETH on
        // SushiSwap V2 (factory 0xc35DAD...).
        let token = EVMAddress::from_str("0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8").unwrap();
        let ctx = fetch_pegged_pair_onchain(&mut chain, token).expect("expected a real WETH/USDC.e pair on Arbitrum");
        assert!(!ctx.swaps.is_empty());
        assert_eq!(ctx.weth_address, EVMAddress::from_str("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1").unwrap());
    }

    #[test]
    fn test_fetch_pegged_pair_onchain_celo() {
        let mut chain = fresh_config(CELO);
        // Found live via Ubeswap V2's own allPairs(0) (not a
        // from-memory/guessed address -- a guessed cUSD address was
        // confirmed wrong, missing a hex digit, while verifying this
        // chain): a real pair with CELO as token0 and non-zero reserves.
        let token = EVMAddress::from_str("0x765de816845861e75a25fca122bb6898b8b1282a").unwrap();
        let ctx = fetch_pegged_pair_onchain(&mut chain, token).expect("expected a real CELO pair on Celo (Ubeswap V2)");
        assert!(!ctx.swaps.is_empty());
        assert_eq!(ctx.weth_address, EVMAddress::from_str("0x471EcE3750Da237f93B8E339c536989b8978a438").unwrap());
    }

    #[test]
    fn test_fetch_pegged_pair_onchain_etc() {
        // This test was missing entirely until now -- the module doc
        // above and README.md both claimed ETC had the same "live
        // verified, permanent regression test" coverage as every other
        // chain in KNOWN_V2_FACTORIES, but no #[test] for it actually
        // existed. Found live against a real, fully-synced local ETC
        // node (core-geth, chain id 61, verified byte-for-byte against
        // a public ETC RPC): ETCswap V2 Factory's allPairs(2) is a real
        // WETC/DAI pair with non-zero reserves (~0.43 WETC / ~85 DAI at
        // discovery time).
        let mut chain = fresh_config(ETC);
        let dai = EVMAddress::from_str("0x2c78f1b70CCf63CdEE49F9233e9fAa99D43AA07E").unwrap();
        let ctx = fetch_pegged_pair_onchain(&mut chain, dai).expect("expected a real WETC/DAI pair on ETC mainnet (ETCswap V2)");
        assert!(!ctx.swaps.is_empty());
        assert_eq!(ctx.weth_address, EVMAddress::from_str("0x1953cab0E5bFa6D4a9BaD6E05fD46C1CC6527a5a").unwrap());
    }

    #[test]
    fn test_fetch_pegged_pair_data_onchain_checks_multiple_candidates() {
        // CAKE -- live-verified (via direct PancakeSwap Factory getPair
        // calls, not assumed) to have REAL direct pairs against BOTH
        // WBNB and USDT on PancakeSwap V2. Before this test was written,
        // fetch_pegged_pair_data_onchain only ever checked the ONE base
        // token (WBNB), so it could only ever return a single PairData
        // no matter how many other real pairs a token actually had --
        // which meant uniswap.rs's existing get_all_hops/dfs multi-hop
        // structure (MAX_HOPS=2) had nothing to traverse beyond one direct
        // hop, even though the traversal code itself was already there.
        // Checking every well-known pegged token (not just the one base
        // token) is what actually unlocks it. This asserts the on-chain
        // mechanism itself returns multiple real entries; it is not a
        // test of the DFS traversal logic in uniswap.rs.
        let mut chain = fresh_onchain_config(BSC);
        let cake = "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82";
        let pairs = fetch_pegged_pair_data_onchain(&mut chain, cake);
        assert!(
            pairs.len() >= 2,
            "expected at least 2 real candidate pairs (WBNB and USDT) for CAKE, got {}: {:?}",
            pairs.len(),
            pairs
        );
        let next_tokens: Vec<String> = pairs.iter().map(|p| p.next.clone()).collect();
        assert!(
            next_tokens.contains(&"0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c".to_string()),
            "expected a WBNB pair among {:?}",
            next_tokens
        );
        assert!(
            next_tokens.contains(&"0x55d398326f99059ff775485246999027b3197955".to_string()),
            "expected a USDT pair among {:?}",
            next_tokens
        );
        // Exactly one candidate (the true base/WETH-equivalent token) may
        // be labeled "pegged" -- see this function's own doc for why the
        // rest must be "lp" instead.
        assert_eq!(pairs.iter().filter(|p| p.src == "pegged").count(), 1);
    }
}
