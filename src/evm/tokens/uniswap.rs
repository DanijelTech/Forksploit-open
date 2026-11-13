use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    str::FromStr,
    sync::{Arc, Mutex},
};

use itertools::Itertools;
use lazy_static::lazy_static;
use revm_primitives::Bytecode;
use tracing::{debug, error, info, warn};

use super::{
    get_uniswap_info,
    v2_transformer::UniswapPairContext,
    weth_transformer::WethContext,
    PathContext,
    TokenContext,
};
use crate::evm::{
    onchain::{endpoints::PairData, ChainConfig},
    tokens::v3_transformer::UniswapV3PairContext,
    types::{EVMAddress, EVMU256},
};

pub struct Info {
    routes: Vec<Vec<PairData>>,
    basic_info: BasicInfo,
}

pub struct BasicInfo {
    weth: String,
    is_weth: bool,
}

const MAX_HOPS: u32 = 2; // Assuming the value of MAX_HOPS

lazy_static! {
    pub static ref CODE_REGISTRY: Mutex<HashMap<EVMAddress, Bytecode>> = Mutex::new(HashMap::new());
}

pub fn fetch_uniswap_path(chain: &mut Box<dyn ChainConfig>, token_address: EVMAddress) -> TokenContext {
    let token = format!("{:?}", token_address);
    let info: Info = find_path_onchain(chain, &token);

    let basic_info = info.basic_info;
    if basic_info.weth.is_empty() {
        warn!("failed to find weth address");
        return TokenContext::default();
    }
    // FAZA 6.1: the weth address comes from the onchain path API; an
    // unparseable value yields an empty token context instead of panicking.
    let weth = match EVMAddress::from_str(&basic_info.weth) {
        Ok(w) => w,
        Err(e) => {
            warn!("failed to parse weth address '{}': {e}", basic_info.weth);
            return TokenContext::default();
        }
    };
    let is_weth = basic_info.is_weth;

    let routes: Vec<Vec<PairData>> = info.routes;

    macro_rules! register_code {
        ($addr: expr) => {
            CODE_REGISTRY
                .lock()
                .unwrap()
                .insert($addr, chain.get_contract_code_analyzed($addr, false));
        };
    }

    let paths_parsed = routes
        .iter()
        .map(|pairs| {
            let mut path_parsed: PathContext = Default::default();

            macro_rules! _gen_v2_pair_context {
                ($pair: expr) => {{
                    // FAZA 6.1: addresses come from the onchain path API; a
                    // pair with any unparseable address is skipped instead of
                    // panicking.
                    match (
                        EVMAddress::from_str($pair.pair.as_str()),
                        EVMAddress::from_str($pair.next.as_str()),
                        EVMAddress::from_str($pair.in_token.as_str()),
                    ) {
                        (Ok(pair_address), Ok(next_hop), Ok(in_token_address)) => {
                            let inner = UniswapPairContext {
                                pair_address,
                                next_hop,
                                side: $pair.in_ as u8,
                                uniswap_info: Arc::new(get_uniswap_info($pair.src_exact.as_str())),
                                initial_reserves: ($pair.initial_reserves_0, $pair.initial_reserves_1),
                                in_token_address,
                            };
                            register_code!(inner.next_hop);
                            Some(inner)
                        }
                        _ => {
                            warn!("skipping uniswap pair with unparseable address(es): {:?}", $pair);
                            None
                        }
                    }
                }};
            }

            macro_rules! gen_v2_pair_context {
                ($pair: expr) => {{
                    if let Some(inner) = _gen_v2_pair_context!($pair) {
                        path_parsed.route.push(super::PairContextTy::Uniswap(Rc::new(RefCell::new(inner))));
                    }
                }};
            }

            macro_rules! gen_v3_pair_context {
                ($pair: expr) => {{
                    if let (Ok(pair_address), Some(inner)) = (
                        EVMAddress::from_str($pair.pair.as_str()),
                        _gen_v2_pair_context!($pair),
                    ) {
                        let fee = chain.get_v3_fee(pair_address);
                        register_code!(inner.next_hop);
                        let v3 = Rc::new(RefCell::new(UniswapV3PairContext { fee, inner }));
                        path_parsed.route.push(super::PairContextTy::UniswapV3(v3));
                    }
                }};
            }

            pairs.iter().for_each(|pair| match pair.src.as_str() {
                "lp" => {
                    if pair.interface == "uniswapv2" {
                        gen_v2_pair_context!(pair);
                    } else if pair.interface == "uniswapv3" {
                        gen_v3_pair_context!(pair);
                    } else {
                        warn!("skipping unknown interface '{}'", pair.interface);
                    }
                }
                "pegged" => {
                    if pair.interface == "uniswapv2" {
                        gen_v2_pair_context!(pair);
                    } else if pair.interface == "uniswapv3" {
                        gen_v3_pair_context!(pair);
                    } else {
                        warn!("skipping unknown interface '{}'", pair.interface);
                    }
                    // FAZA 6.1: `pair.next` is external; skip the Weth hop if
                    // it is not a parseable address.
                    match EVMAddress::from_str(pair.next.as_str()) {
                        Ok(weth_address) => {
                            path_parsed
                                .route
                                .push(super::PairContextTy::Weth(Rc::new(RefCell::new(WethContext { weth_address }))));
                        }
                        Err(e) => warn!("skipping pegged Weth hop, bad address '{}': {e}", pair.next),
                    }
                }
                "pegged_weth" => {
                    // FAZA 6.1: `pair.in_token` is external; skip on a bad address.
                    match EVMAddress::from_str(pair.in_token.as_str()) {
                        Ok(weth_address) => {
                            register_code!(weth_address);
                            let inner = Rc::new(RefCell::new(WethContext { weth_address }));
                            path_parsed.route.push(super::PairContextTy::Weth(inner));
                        }
                        Err(e) => warn!("skipping pegged_weth hop, bad address '{}': {e}", pair.in_token),
                    }
                }
                other => warn!("skipping unknown swap path source '{}'", other),
            });
            for pair in &path_parsed.route {
                if let super::PairContextTy::UniswapV3(inner) = pair {
                    // FAZA 6.1: a v3 pair without a router simply registers no
                    // code instead of panicking.
                    if let Some(router) = inner.borrow().inner.uniswap_info.router {
                        register_code!(router);
                    }
                }
            }

            path_parsed
        })
        .collect();

    TokenContext {
        swaps: paths_parsed,
        is_weth,
        weth_address: weth,
        // Populated separately by Flashloan::get_token_context, which
        // calls this function and then layers the Aave/Balancer lookups
        // on top -- this function only knows about Uniswap-style paths.
        aave_borrow: None,
        balancer_borrow: None,
    }
}

fn get_pair(chain: &mut Box<dyn ChainConfig>, token: &str, is_pegged: bool) -> Vec<PairData> {
    let token = token.to_lowercase();
    info!("fetching pairs for {token}");
    if token == chain.get_weth() {
        debug!("token {} is weth, returning empty pairs", token);
        return vec![];
    }
    let pegged_tokens = chain.get_pegged_token();
    let mut pairs = chain.get_pair(token.as_str(), is_pegged || pegged_tokens.values().contains(&token));

    // println!("original pairs: {:?}", pairs,);
    // println!("token: {:?}", token,);

    for pair in &mut pairs {
        add_reserve_info(chain, pair);
    }
    pairs.sort_by(|a, b| {
        let a = get_liquidity_cmp(a);
        let b = get_liquidity_cmp(b);
        b.cmp(&a)
    });

    if pairs.len() > 3 {
        pairs = pairs[0..3].to_vec();
    }
    // println!("pairs: {:?}", pairs);
    pairs
}

fn get_all_hops(
    chain: &mut Box<dyn ChainConfig>,
    token: &str,
    hop: u32,
    known: &mut HashSet<String>,
) -> HashMap<String, Vec<PairData>> {
    known.insert(token.to_string());

    if hop > MAX_HOPS {
        return HashMap::new();
    }

    let mut hops: HashMap<String, Vec<PairData>> = HashMap::new();
    hops.insert(token.to_string(), get_pair(chain, token, false));

    let pegged_tokens = chain.get_pegged_token();

    for i in hops.clone().get(token).unwrap() {
        if pegged_tokens.values().any(|v| v == &i.next) || known.contains(&i.next) {
            continue;
        }
        let next_hops = get_all_hops(chain, &i.next, hop + 1, known);
        hops.extend(next_hops);
    }

    hops
}

fn get_pegged_next_hop(chain: &mut Box<dyn ChainConfig>, token: &str) -> Option<PairData> {
    if token == chain.get_weth() {
        return Some(PairData {
            src: "pegged_weth".to_string(),
            in_: 0,
            next: "".to_string(),
            pair: "".to_string(),
            initial_reserves_0: EVMU256::ZERO,
            initial_reserves_1: EVMU256::ZERO,
            src_exact: "".to_string(),
            decimals_0: 0,
            decimals_1: 0,
            token0: "".to_string(),
            in_token: token.to_string(),
            interface: "weth".to_string(),
            token1: "".to_string(),
        });
    }

    let pairs = get_pair(chain, token, true);
    debug!(%token, ?pairs, "get_pair (pegged)");
    let mut peg_info = match pairs.first() {
        Some(p) => p.clone(),
        None => {
            error!("no pegged pair found for {token}, consider setting env <ETH_RPC_URL>");
            return None;
        }
    };

    add_reserve_info(chain, &mut peg_info);

    Some(PairData {
        src: "pegged".to_string(),
        ..peg_info.clone()
    })
}

/// returns whether the pair is significant
fn add_reserve_info(chain: &mut Box<dyn ChainConfig>, pair_data: &mut PairData) {
    if pair_data.interface == "uniswapv2" {
        let reserves = chain.fetch_reserve(&pair_data.pair);
        if let Some((r0, r1)) = reserves {
            let parsed = hex::decode(&r0)
                .ok()
                .and_then(|b| EVMU256::try_from_be_slice(&b))
                .zip(hex::decode(&r1).ok().and_then(|b| EVMU256::try_from_be_slice(&b)));
            match parsed {
                Some((v0, v1)) => {
                    pair_data.initial_reserves_0 = v0;
                    pair_data.initial_reserves_1 = v1;
                }
                None => {
                    error!("malformed reserve data for pair {}: r0={}, r1={}", pair_data.pair, r0, r1);
                }
            }
        }
    }
    if pair_data.interface == "uniswapv3" {
        let addrs = EVMAddress::from_str(&pair_data.token0)
            .ok()
            .zip(EVMAddress::from_str(&pair_data.token1).ok())
            .zip(EVMAddress::from_str(&pair_data.pair).ok());
        match addrs {
            Some(((t0, t1), lp)) => {
                pair_data.initial_reserves_0 = chain.get_token_balance(t0, lp);
                pair_data.initial_reserves_1 = chain.get_token_balance(t1, lp);
            }
            None => {
                error!(
                    "malformed v3 pair addresses: token0={}, token1={}, pair={}",
                    pair_data.token0, pair_data.token1, pair_data.pair
                );
            }
        }
    }
}

fn get_liquidity_cmp(pair_data: &PairData) -> EVMU256 {
    let reserves_0 = pair_data.initial_reserves_0;
    let reserves_1 = pair_data.initial_reserves_1;

    // bypass for incorrect decimal implementation

    if pair_data.in_ == 0 {
        let min_r0 = if pair_data.decimals_0 == 0 {
            EVMU256::ZERO
        } else {
            EVMU256::from(10).pow(EVMU256::from(pair_data.decimals_0 - 1))
        };

        if min_r0 == EVMU256::ZERO {
            return EVMU256::ZERO;
        }
        reserves_0 / min_r0
    } else {
        let min_r1 = if pair_data.decimals_1 == 0 {
            EVMU256::ZERO
        } else {
            EVMU256::from(10).pow(EVMU256::from(pair_data.decimals_1 - 1))
        };

        if min_r1 == EVMU256::ZERO {
            return EVMU256::ZERO;
        }

        reserves_1 / min_r1
    }
}

fn with_info(routes: Vec<Vec<PairData>>, token: &str, weth: &str) -> Info {
    Info {
        routes,
        basic_info: BasicInfo {
            weth: weth.to_string(),
            is_weth: token == weth,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn dfs(
    chain: &mut Box<dyn ChainConfig>,
    token: &str,
    path: &mut Vec<PairData>,
    visited: &mut HashSet<String>,
    pegged_tokens: &HashMap<String, String>,
    hops: &HashMap<String, Vec<PairData>>,
    routes: &mut Vec<Vec<PairData>>,
) {
    if pegged_tokens.values().any(|v| v == token) {
        if let Some(hop) = get_pegged_next_hop(chain, token) {
            let mut new_path = path.clone();
            new_path.push(hop);
            routes.push(new_path);
        }
        return;
    }
    visited.insert(token.to_string());
    if !hops.contains_key(token) {
        return;
    }
    for hop in hops.get(token).unwrap() {
        if visited.contains(&hop.next) {
            continue;
        }
        path.push(hop.clone());
        dfs(chain, &hop.next, path, visited, pegged_tokens, hops, routes);
        path.pop();
    }
}

fn find_path_onchain(chain: &mut Box<dyn ChainConfig>, token: &str) -> Info {
    let pegged_tokens = chain.get_pegged_token();
    let weth = chain.get_weth();

    if pegged_tokens.values().any(|v| v == token) {
        let routes = match get_pegged_next_hop(chain, token) {
            Some(hop) => vec![vec![hop]],
            None => vec![],
        };
        return with_info(routes, token, &weth);
    }

    let mut known: HashSet<String> = HashSet::new();
    let hops = get_all_hops(chain, token, 0, &mut known);

    let mut routes: Vec<Vec<PairData>> = vec![];

    dfs(
        chain,
        token,
        &mut vec![],
        &mut HashSet::new(),
        &pegged_tokens,
        &hops,
        &mut routes,
    );

    with_info(routes, token, &weth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::{
        onchain::endpoints::{
            Chain::{BSC, ETH},
            OnChainConfig,
        },
        types::EVMAddress,
    };

    #[test]
    fn test_get_pegged_next_hop() {
        let mut config: Box<dyn ChainConfig> = Box::new(OnChainConfig::new(BSC, 22055611));
        let token = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c";
        let v = get_pegged_next_hop(&mut config, token).unwrap();
        assert!(v.src == "pegged_weth");
    }

    #[test]
    fn test_get_all_hops() {
        let mut config: Box<dyn ChainConfig> = Box::new(OnChainConfig::new(BSC, 22055611));
        let mut known: HashSet<String> = HashSet::new();
        let v: HashMap<String, Vec<PairData>> =
            get_all_hops(&mut config, "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", 0, &mut known);
        assert!(!v.is_empty());
    }

    /// Builds a config pinned a small margin behind the chain's own
    /// current head. The fixed historical blocks these tests used to pin
    /// (ETH 19021411, BSC 22055611) now hit "Archive requests require a
    /// personal token" on the default public RPCs for any eth_call-based
    /// lookup that far behind head (confirmed live 2026-10-28 -- same
    /// paywall documented on onchain_pair_discovery.rs's own test
    /// helper). Recent state needs no archive access on any of these
    /// providers.
    fn fresh_config(chain: crate::evm::onchain::endpoints::Chain) -> Box<dyn ChainConfig> {
        let mut probe = OnChainConfig::new(chain, 0);
        probe.set_latest_block_number();
        let latest = u64::from_str_radix(probe.block_number.trim_start_matches("0x"), 16)
            .expect("RPC returned a malformed latest block number");
        Box::new(OnChainConfig::new(chain, latest.saturating_sub(20)))
    }

    #[test]
    fn test_get_pair() {
        let mut config = fresh_config(ETH);
        let v = get_pair(&mut config, "0x06450dEe7FD2Fb8E39061434BAbCFC05599a6Fb8", false);
        assert!(!v.is_empty());
        for p in v {
            println!("pair: {:?}", p);
        }
    }

    #[test]
    fn test_fetch_uniswap_path() {
        let mut config = fresh_config(BSC);
        let v = fetch_uniswap_path(
            &mut config,
            EVMAddress::from_str("0xcff086ead392ccb39c49ecda8c974ad5238452ac").unwrap(),
        );
        assert!(!v.swaps.is_empty());
        assert!(!v.weth_address.is_zero());
    }

    #[test]
    fn test_fetch_uniswap_path_wbnb() {
        let mut config: Box<dyn ChainConfig> = Box::new(OnChainConfig::new(BSC, 22055611));
        let v = fetch_uniswap_path(
            &mut config,
            EVMAddress::from_str("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c").unwrap(),
        );
        assert!(!v.swaps.is_empty());
        assert!(!v.weth_address.is_zero());
    }
}
