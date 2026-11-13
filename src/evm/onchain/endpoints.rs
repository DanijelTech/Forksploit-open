use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    env,
    fmt::Debug,
    hash::{Hash, Hasher},
    io::{Read, Write},
    os::unix::net::UnixStream,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use reqwest::{blocking, header::HeaderMap};
use retry::{delay::Fixed, retry_with_index, OperationResult};
use revm_interpreter::analysis::to_analysed;
use revm_primitives::{Bytecode, B160};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use super::ChainConfig;
use crate::{
    cache::{Cache, FileSystemCache},
    evm::{
        tokens::TokenContext,
        types::{EVMAddress, EVMU256},
    },
};

// Hard ceiling on the block gas limit the fuzzer simulates against, and on
// any tx gas limit the Python signing path will ever produce. ETC mainnet's
// real block gasLimit fluctuates (8,000,000 in most blocks, 8,007,811 in
// others); a trace valid only at the higher value is un-includable on-chain
// the moment it drops back, so nothing above this is ever treated as
// executable. Mirrors gas_utils.MAX_GAS_LIMIT on the Python side.
pub const MAX_BLOCK_GAS_LIMIT: u64 = 8_000_000;

/// PHASE 6.1: why a JSON-RPC response could not be turned into a `result`.
/// Every variant is a recoverable error, never a panic -- a malformed,
/// empty, `null`, or error-carrying response from an external node must
/// surface as a typed error the caller can log/retry, not take the fuzzer
/// down.
#[derive(Debug)]
pub enum RpcResponseError {
    /// The body was not valid JSON (empty, truncated, `null`-only text, ...).
    Malformed(String),
    /// A well-formed JSON-RPC error object (e.g. rate limit, bad params).
    Rpc(Value),
    /// Valid JSON with neither a `result` nor an `error` field.
    MissingResult,
}

impl std::fmt::Display for RpcResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcResponseError::Malformed(m) => write!(f, "malformed JSON-RPC response: {}", m),
            RpcResponseError::Rpc(e) => write!(f, "RPC error response: {}", e),
            RpcResponseError::MissingResult => {
                write!(f, "response has neither a result nor an error field")
            }
        }
    }
}

/// Turn a raw JSON-RPC response body into its `result`, or a typed error.
/// Deliberately total: an empty string, `null`, wrong hex, a JSON-RPC
/// error object, or a body with no `result` all return `Err`, never panic.
/// Kept free of `self`/network so it is directly unit-testable.
pub fn parse_rpc_response(resp: &str) -> std::result::Result<Value, RpcResponseError> {
    let json: Value = serde_json::from_str(resp)
        .map_err(|e| RpcResponseError::Malformed(e.to_string()))?;
    // A JSON-RPC body is always an object. A bare `null`, array, string or
    // number parses as valid JSON but is not a usable response -- reject it
    // as malformed rather than reporting a misleading "missing result".
    if !json.is_object() {
        return Err(RpcResponseError::Malformed(format!(
            "response is not a JSON object: {}",
            json
        )));
    }
    match json.get("result") {
        Some(result) => Ok(result.clone()),
        None => match json.get("error") {
            Some(err) => Err(RpcResponseError::Rpc(err.clone())),
            None => Err(RpcResponseError::MissingResult),
        },
    }
}

/// Build the blocking HTTP client used for every RPC call. Returns a typed
/// error instead of `.expect()`-panicking: TLS/backend initialisation is an
/// external, environment-dependent failure, so it must be reportable.
fn build_http_client(timeout_secs: u64) -> Result<blocking::Client> {
    blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| anyhow!("failed to create HTTP client: {}", e))
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub enum Chain {
    ETH,
    GOERLI,
    SEPOLIA,
    BSC,
    CHAPEL,
    POLYGON,
    MUMBAI,
    FANTOM,
    AVALANCHE,
    OPTIMISM,
    ARBITRUM,
    GNOSIS,
    BASE,
    CELO,
    ZKEVM,
    ZkevmTestnet,
    BLAST,
    LINEA,
    LOCAL,
    IOTEX,
    SCROLL,
    VANA,
    STORY,
    ETC,
    MORDOR,
}

pub trait PriceOracle: Debug {
    // ret0: price = int(original_price x 10^5)
    // ret1: decimals of the token
    fn fetch_token_price(&mut self, token_address: EVMAddress) -> Option<(u32, u32)>;
}

impl FromStr for Chain {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "eth" | "mainnet" => Ok(Self::ETH),
            "goerli" => Ok(Self::GOERLI),
            "sepolia" => Ok(Self::SEPOLIA),
            "bsc" => Ok(Self::BSC),
            "chapel" => Ok(Self::CHAPEL),
            "polygon" => Ok(Self::POLYGON),
            "mumbai" => Ok(Self::MUMBAI),
            "fantom" => Ok(Self::FANTOM),
            "avalanche" => Ok(Self::AVALANCHE),
            "optimism" => Ok(Self::OPTIMISM),
            "arbitrum" => Ok(Self::ARBITRUM),
            "gnosis" => Ok(Self::GNOSIS),
            "base" => Ok(Self::BASE),
            "celo" => Ok(Self::CELO),
            "zkevm" => Ok(Self::ZKEVM),
            "zkevm_testnet" => Ok(Self::ZkevmTestnet),
            "blast" => Ok(Self::BLAST),
            "linea" => Ok(Self::LINEA),
            "local" => Ok(Self::LOCAL),
            "iotex" => Ok(Self::IOTEX),
            "scroll" => Ok(Self::SCROLL),
            "vana" => Ok(Self::VANA),
            "story" => Ok(Self::STORY),
            "etc" | "ethereumclassic" | "ethereum_classic" => Ok(Self::ETC),
            "mordor" => Ok(Self::MORDOR),
            _ => Err(()),
        }
    }
}

impl Chain {
    pub fn new_with_rpc_url(rpc_url: &str) -> Result<Self> {
        let client = blocking::Client::new();
        let body = json!({
            "method": "eth_chainId",
            "params": [],
            "id": 1,
            "jsonrpc": "2.0"
        })
        .to_string();

        let resp: Value = if rpc_url.starts_with("http://") || rpc_url.starts_with("https://") {
            // HTTP request
            let response = client
                .post(rpc_url)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send()?;
            response.json::<Value>()?
        } else if rpc_url.starts_with("/") || rpc_url.starts_with("./") || rpc_url.starts_with("../") {
            // IPC request
            let mut stream = UnixStream::connect(rpc_url)?;
            stream.write_all(body.as_bytes())?;

            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            serde_json::from_str(&response)?
        } else {
            return Err(anyhow!("Unsupported URL scheme: {}", rpc_url));
        };

        let chain_id = resp
            .get("result")
            .and_then(|result| result.as_str())
            .and_then(|result| u64::from_str_radix(result.trim_start_matches("0x"), 16).ok())
            .ok_or_else(|| anyhow!("Failed to parse chain id from response: {}", rpc_url))?;

        unsafe {
            env::set_var("ETH_RPC_URL", rpc_url);
        }

        Ok(match chain_id {
            1 => Self::ETH,
            5 => Self::GOERLI,
            11155111 => Self::SEPOLIA,
            56 => Self::BSC,
            97 => Self::CHAPEL,
            137 => Self::POLYGON,
            80001 => Self::MUMBAI,
            250 => Self::FANTOM,
            43114 => Self::AVALANCHE,
            10 => Self::OPTIMISM,
            42161 => Self::ARBITRUM,
            100 => Self::GNOSIS,
            8453 => Self::BASE,
            42220 => Self::CELO,
            1101 => Self::ZKEVM,
            1442 => Self::ZkevmTestnet,
            81457 => Self::BLAST,
            59144 => Self::LINEA,
            4689 => Self::IOTEX,
            534352 => Self::SCROLL,
            1480 => Self::VANA,
            1514 => Self::STORY,
            // 61 (ETC) and 63 (Mordor) were both missing from this match
            // entirely until now -- `Chain::ETC` itself worked fine via
            // `--chain etc`, but this specific match (chain-id inference
            // from a bare RPC URL, used by `new_with_rpc_url` for
            // Foundry's `createSelectFork("https://...")` cheatcode) had
            // no way to recognize either chain from its RPC alone.
            61 => Self::ETC,
            63 => Self::MORDOR,
            31337 => Self::LOCAL,
            _ => return Err(anyhow!("Unknown chain id: {}", chain_id)),
        })
    }

    pub fn get_chain_id(&self) -> u32 {
        match self {
            Chain::ETH => 1,
            Chain::GOERLI => 5,
            Chain::SEPOLIA => 11155111,
            Chain::BSC => 56,
            Chain::CHAPEL => 97,
            Chain::POLYGON => 137,
            Chain::MUMBAI => 80001,
            Chain::FANTOM => 250,
            Chain::AVALANCHE => 43114,
            Chain::OPTIMISM => 10,
            Chain::ARBITRUM => 42161,
            Chain::GNOSIS => 100,
            Chain::BASE => 8453,
            Chain::CELO => 42220,
            Chain::ZKEVM => 1101,
            Chain::ZkevmTestnet => 1442,
            Chain::BLAST => 81457,
            Chain::LINEA => 59144,
            Chain::IOTEX => 4689,
            Chain::SCROLL => 534352,
            Chain::VANA => 1480,
            Chain::STORY => 1514,
            Chain::ETC => 61,
            Chain::MORDOR => 63,
            Chain::LOCAL => 31337,
        }
    }

    pub fn to_lowercase(&self) -> String {
        match self {
            Chain::ETH => "eth",
            Chain::GOERLI => "goerli",
            Chain::SEPOLIA => "sepolia",
            Chain::BSC => "bsc",
            Chain::CHAPEL => "chapel",
            Chain::POLYGON => "polygon",
            Chain::MUMBAI => "mumbai",
            Chain::FANTOM => "fantom",
            Chain::AVALANCHE => "avalanche",
            Chain::OPTIMISM => "optimism",
            Chain::ARBITRUM => "arbitrum",
            Chain::GNOSIS => "gnosis",
            Chain::BASE => "base",
            Chain::CELO => "celo",
            Chain::ZKEVM => "zkevm",
            Chain::ZkevmTestnet => "zkevm_testnet",
            Chain::BLAST => "blast",
            Chain::LINEA => "linea",
            Chain::LOCAL => "local",
            Chain::IOTEX => "iotex",
            Chain::SCROLL => "scroll",
            Chain::VANA => "vana",
            Chain::STORY => "story",
            Chain::ETC => "etc",
            Chain::MORDOR => "mordor",
        }
        .to_string()
    }

    pub fn get_chain_rpc(&self) -> String {
        // Deliberately unconditional for every chain, not just ETH --
        // matches the standard cast/forge convention where ETH_RPC_URL
        // means "the RPC to use", regardless of which chain it's actually
        // for (new_with_rpc_url, used by the createSelectFork cheatcode,
        // relies on exactly this to let a Foundry setup script fork from
        // an arbitrary custom RPC for any chain). See the "Running Tests"
        // note in CLAUDE.md: because of this, setting ETH_RPC_URL to run
        // one chain's test against a specific node also redirects every
        // OTHER chain's tests in the same run -- run cross-chain test
        // batches separately instead of combining them under one override.
        if let Ok(url) = env::var("ETH_RPC_URL") {
            return url;
        }
        match self {
            // Verified live 2026-11-01: eth.merkle.io (the previous
            // default) actively rate-limits anonymous requests
            // ("Rate limit exceeded" on eth_chainId, not even a cold-start
            // fluke -- reproduced on a fresh request after a 5s pause).
            // publicnode's Ethereum endpoint is free, no-key-required, and
            // confirmed serving real eth_chainId/eth_call results. ETH is
            // one of this project's two most-used chains (the other being
            // ETC) -- a flaky default here is the highest-impact one to
            // fix.
            Chain::ETH => "https://ethereum-rpc.publicnode.com",
            Chain::GOERLI => "https://rpc.ankr.com/eth_goerli",
            // rpc.ankr.com/eth_sepolia now requires an API key (verified
            // 2026-10-24: returns "Unauthorized" without one) -- publicnode
            // is a free, no-key-required public endpoint, verified reliable
            // during an actual Sepolia staging run this session.
            Chain::SEPOLIA => "https://ethereum-sepolia.publicnode.com",
            Chain::BSC => "https://bsc-rpc.publicnode.com",
            Chain::CHAPEL => "https://rpc.ankr.com/bsc_testnet_chapel",
            // Verified live 2026-10-28: polygon.llamarpc.com (the previous
            // default) fails to resolve via DNS entirely in this
            // environment -- not a rate limit, the host is simply
            // unreachable. publicnode's Polygon endpoint is free,
            // no-key-required, and confirmed serving real eth_call results
            // (QuickSwap V2 factory queries, added to
            // onchain_pair_discovery.rs's KNOWN_V2_FACTORIES table).
            Chain::POLYGON => "https://polygon-bor-rpc.publicnode.com",
            Chain::MUMBAI => "https://rpc-mumbai.maticvigil.com/",
            // Verified live 2026-11-01: rpc.ankr.com/fantom now returns
            // "Unauthorized: You must authenticate your request with an
            // API key" for anonymous requests, same ankr free-tier
            // tightening already hit arbitrum/sepolia. Fantom's own
            // official public RPC needs no key.
            Chain::FANTOM => "https://rpc.fantom.network",
            // Verified live 2026-11-01: rpc.ankr.com/avalanche now requires
            // an API key, same as fantom above. Avalanche's own official
            // public RPC needs no key.
            Chain::AVALANCHE => "https://api.avax.network/ext/bc/C/rpc",
            // Verified live 2026-11-01: rpc.ankr.com/optimism now requires
            // an API key, same as fantom/avalanche above -- despite an
            // earlier comment here (and in onchain_scripts/chains.py)
            // claiming this was already fixed, it was NOT actually applied
            // to this match arm; only the Python-side default was updated.
            // Optimism's own official public RPC needs no key.
            Chain::OPTIMISM => "https://mainnet.optimism.io",
            // Verified live 2026-10-28: rpc.ankr.com/arbitrum (the previous
            // default) now returns "Unauthorized: You must authenticate
            // your request with an API key" for anonymous requests --
            // ankr tightened its free tier since this default was chosen.
            // Arbitrum's own official public RPC needs no key and is
            // confirmed serving real eth_call results (SushiSwap V2
            // factory queries).
            Chain::ARBITRUM => "https://arb1.arbitrum.io/rpc",
            // Verified live 2026-11-01: rpc.ankr.com/gnosis now requires an
            // API key, same pattern as fantom/avalanche/optimism above.
            // Gnosis Chain's own official public RPC needs no key.
            Chain::GNOSIS => "https://rpc.gnosischain.com",
            // Verified live 2026-11-01: developer-access-mainnet.base.org
            // (the previous default) fails DNS resolution entirely --
            // dead/decommissioned, not a rate limit. Base's own official
            // public RPC needs no key and is confirmed serving real
            // eth_chainId results.
            Chain::BASE => "https://mainnet.base.org",
            // Verified live 2026-11-01: rpc.ankr.com/celo still works
            // without a key -- unlike the other rpc.ankr.com/* defaults
            // audited the same day, this one was NOT found broken, so it
            // is deliberately left unchanged (no evidence-free "fix").
            Chain::CELO => "https://rpc.ankr.com/celo",
            // Verified live 2026-11-01: rpc.ankr.com/polygon_zkevm now
            // returns "API key is not allowed to access blockchain" for
            // anonymous requests. zkevm-rpc.com is the chain's own
            // official public endpoint, no key required.
            Chain::ZKEVM => "https://zkevm-rpc.com",
            Chain::ZkevmTestnet => "https://rpc.ankr.com/polygon_zkevm_testnet",
            // Verified live 2026-11-01: rpc.ankr.com/blast now requires a
            // key, same pattern as the other ankr defaults audited the
            // same day. Blast's own official public RPC needs no key.
            Chain::BLAST => "https://rpc.blast.io",
            // Verified live 2026-11-01: rpc.ankr.com/linea now requires a
            // key, same pattern as above. Linea's own official public RPC
            // needs no key.
            Chain::LINEA => "https://rpc.linea.build",
            // Verified live 2026-11-01: rpc.ankr.com/iotex still works
            // without a key -- left unchanged, same reasoning as celo
            // above.
            Chain::IOTEX => "https://rpc.ankr.com/iotex",
            // Verified live 2026-11-01: rpc.ankr.com/scroll now requires a
            // key, same pattern as blast/linea above. Scroll's own
            // official public RPC needs no key.
            Chain::SCROLL => "https://rpc.scroll.io",
            Chain::VANA => "https://rpc.vana.org",
            Chain::STORY => "https://mainnet.storyrpc.io",
            // Verified live 2026-11-01. The previous default,
            // etcdesktop.com (verified 2026-10-28), stopped responding
            // with real data (eth_blockNumber returns 0x0, every block
            // query returns null) -- exactly the public-endpoint rot its
            // own comment warned about. geth-at.etc-network.info
            // confirmed working instead: correct chain id (0x3d/61),
            // consistent eth_getCode at a pinned recent block (3
            // consecutive calls), AND at a block ~1,000,000 behind tip
            // (it's a full archive node, better than the endpoint it
            // replaces). The ETC Cooperative's own recommendation is
            // still to pick a real-time-monitored endpoint from
            // chainlist.org rather than hardcode one forever, since
            // public endpoints come and go -- revisit if this one stops
            // responding too.
            Chain::ETC => "https://geth-at.etc-network.info",
            // Mordor is ETC's real, live testnet (chain id 63, not to be
            // confused with the separate, deprecated "Morden" testnet,
            // chain id 62). Verified live 2026-10-29: eth_chainId returns
            // 0x3f (63) and eth_blockNumber returns a real, current,
            // advancing block -- the ETC Cooperative's own current
            // endpoint, moved here from an older one in 2023.
            Chain::MORDOR => "https://rpc.mordor.etccooperative.org",
            Chain::LOCAL => "http://localhost:8545",
        }
        .to_string()
    }

    pub fn get_chain_etherscan_base(&self) -> String {
        match self {
            Chain::ETH => "https://api.etherscan.io/v2/api",
            Chain::GOERLI => "https://api-goerli.etherscan.io/api",
            Chain::SEPOLIA => "https://api.etherscan.io/v2/api",
            Chain::BSC => "https://api.etherscan.io/v2/api",
            Chain::CHAPEL => "https://api.etherscan.io/v2/api",
            Chain::POLYGON => "https://api.etherscan.io/v2/api",
            Chain::MUMBAI => "https://mumbai.polygonscan.com/api",
            Chain::FANTOM => "https://api.etherscan.io/v2/api",
            Chain::AVALANCHE => "https://api.etherscan.io/v2/api",
            Chain::OPTIMISM => "https://api.etherscan.io/v2/api",
            Chain::ARBITRUM => "https://api.etherscan.io/v2/api",
            Chain::GNOSIS => "https://api.etherscan.io/v2/api",
            Chain::BASE => "https://api.etherscan.io/v2/api",
            Chain::CELO => "https://api.etherscan.io/v2/api",
            Chain::ZKEVM => "https://api.etherscan.io/v2/api",
            Chain::ZkevmTestnet => "https://api.etherscan.io/v2/api",
            Chain::BLAST => "https://api.etherscan.io/v2/api",
            Chain::LINEA => "https://api.etherscan.io/v2/api",
            Chain::LOCAL => "http://localhost:8080/abi/",
            Chain::IOTEX => "https://babel-api.mainnet.IoTeX.io",
            Chain::SCROLL => "https://api.etherscan.io/v2/api",
            Chain::VANA => "https://api.vanascan.io/api/v2",
            Chain::STORY => "https://www.storyscan.xyz/api/v2",
            // Ethereum Classic has no Etherscan coverage -- Blockscout is
            // the chain's actual explorer (mainnet + Mordor testnet).
            // Verified live 2026-10-28 against a real verified contract
            // (0x3a01eE0406C1a6fe4eBEB1d1FC4b9790452Dd3F7) -- the response
            // shape matches blockscout_fetch_abi_uncached() exactly.
            Chain::ETC => "https://etc.blockscout.com/api/v2",
            // Same Blockscout coverage as ETC mainnet, just the Mordor
            // instance -- verified live 2026-10-29 (real stats response,
            // not an error page).
            Chain::MORDOR => "https://etc-mordor.blockscout.com/api/v2",
        }
        .to_string()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PairData {
    pub src: String,
    pub in_: i32,
    pub pair: String,
    pub in_token: String,
    pub next: String,
    pub interface: String,
    pub src_exact: String,
    pub initial_reserves_0: EVMU256,
    pub initial_reserves_1: EVMU256,
    pub decimals_0: u32,
    pub decimals_1: u32,
    pub token0: String,
    pub token1: String,
}

#[derive(Deserialize)]
pub struct GetPairResponse {
    pub data: GetPairResponseData,
}

#[derive(Deserialize)]
pub struct GetPairResponseData {
    pub p0: Vec<GetPairResponseDataPair>,
    pub p1: Vec<GetPairResponseDataPair>,
}

#[derive(Deserialize)]
pub struct GetPairResponseDataPair {
    pub id: String,
    pub token0: GetPairResponseDataPairToken,
    pub token1: GetPairResponseDataPairToken,
}

#[derive(Deserialize)]
pub struct GetPairResponseDataPairToken {
    pub decimals: String,
    pub id: String,
}

#[derive(Clone, Default)]
pub struct OnChainConfig {
    pub endpoint_url: String,
    pub client: reqwest::blocking::Client,
    pub chain_id: u32,
    pub block_number: String,
    pub timestamp: Option<String>,
    pub coinbase: Option<String>,
    pub gaslimit: Option<String>,
    pub block_hash: Option<String>,
    /// Never-panicking fallback returned by `fetch_blk_hash` in the
    /// impossible case `block_hash` is still unset -- so a caller never
    /// sees an `unwrap()` on external state.
    block_hash_fallback: String,

    pub etherscan_api_key: Vec<String>,
    pub etherscan_base: String,

    pub chain_name: String,

    balance_cache: HashMap<EVMAddress, EVMU256>,
    pair_cache: HashMap<EVMAddress, Vec<PairData>>,
    slot_cache: HashMap<(EVMAddress, EVMU256), EVMU256>,
    code_cache: HashMap<EVMAddress, String>,
    code_cache_analyzed: HashMap<EVMAddress, Bytecode>,
    price_cache: HashMap<EVMAddress, Option<(u32, u32)>>,
    abi_cache: HashMap<EVMAddress, Option<String>>,
    storage_dump_cache: HashMap<EVMAddress, Option<Arc<HashMap<EVMU256, EVMU256>>>>,
    uniswap_path_cache: HashMap<EVMAddress, TokenContext>,
    rpc_cache: FileSystemCache,
}

impl Debug for OnChainConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnChainConfig")
            .field("endpoint_url", &self.endpoint_url)
            .field("chain_id", &self.chain_id)
            .field("block_number", &self.block_number)
            .field("timestamp", &self.timestamp)
            .field("coinbase", &self.coinbase)
            .field("gaslimit", &self.gaslimit)
            .field("block_hash", &self.block_hash)
            .field("etherscan_api_key", &self.etherscan_api_key)
            .field("etherscan_base", &self.etherscan_base)
            .field("chain_name", &self.chain_name)
            .field("balance_cache", &self.balance_cache)
            .field("pair_cache", &self.pair_cache)
            .field("slot_cache", &self.slot_cache)
            .field("code_cache", &self.code_cache)
            .field("price_cache", &self.price_cache)
            .field("abi_cache", &self.abi_cache)
            .field("storage_dump_cache", &self.storage_dump_cache)
            .field("uniswap_path_cache", &self.uniswap_path_cache)
            .field("rpc_cache", &self.rpc_cache)
            .finish()
    }
}

impl ChainConfig for OnChainConfig {
    fn get_pair(&mut self, token: &str, _is_pegged: bool) -> Vec<PairData> {
        self.get_pair(token)
    }

    fn fetch_reserve(&self, pair: &str) -> Option<(String, String)> {
        self.fetch_reserve(pair)
    }

    fn get_contract_code_analyzed(&mut self, address: EVMAddress, force_cache: bool) -> Bytecode {
        self.get_contract_code_analyzed(address, force_cache)
    }

    fn get_v3_fee(&mut self, address: EVMAddress) -> u32 {
        self.get_v3_fee(address)
    }

    fn get_token_balance(&mut self, token: EVMAddress, address: EVMAddress) -> EVMU256 {
        self.get_token_balance(token, address)
    }

    fn get_weth(&self) -> String {
        let pegged_token = self.get_pegged_token();

        // PHASE 6.1: never `.unwrap()` a lookup into an external, possibly
        // empty map. The chain-name arm and the map contents are both
        // external data; a mismatch used to panic the fuzzer.
        let key = match self.chain_name.as_str() {
            "eth" | "arbitrum" | "scroll" => "WETH",
            "bsc" => "WBNB",
            "polygon" => "WMATIC",
            "vana" => "WVANA",
            "story" => "WIP",
            "etc" => "WETC",
            "local" => "ZERO",
            _ => {
                warn!("Unknown network");
                return "".to_string();
            }
        };
        match pegged_token.get(key) {
            Some(addr) => addr.to_string(),
            None => {
                error!("pegged-token map for chain '{}' has no '{}' entry", self.chain_name, key);
                "".to_string()
            }
        }
    }

    fn get_pegged_token(&self) -> HashMap<String, String> {
        match self.chain_name.as_str() {
            "eth" => [
                ("WETH", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                ("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                ("USDT", "0xdac17f958d2ee523a2206206994597c13d831ec7"),
                ("DAI", "0x6b175474e89094c44da98b954eedeac495271d0f"),
                ("WBTC", "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"),
                ("WMATIC", "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "bsc" => [
                ("WBNB", "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"),
                ("USDC", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"),
                ("USDT", "0x55d398326f99059ff775485246999027b3197955"),
                ("DAI", "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3"),
                ("WBTC", "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c"),
                ("WETH", "0x2170ed0880ac9a755fd29b2688956bd959f933f8"),
                ("BUSD", "0xe9e7cea3dedca5984780bafc599bd69add087d56"),
                ("CAKE", "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "polygon" => [
                ("WMATIC", "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"),
                ("USDC", "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"),
                ("USDT", "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"),
                ("DAI", "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"),
                ("WBTC", "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6"),
                ("WETH", "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "arbitrum" => [
                ("WETH", "0x82af49447d8a07e3bd95bd0d56f35241523fbab1"),
                ("WBTC", "0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f"),
                ("USDT", "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"),
                ("USDC.e", "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8"),
                ("USDC", "0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
                ("DAI", "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"),
                ("crvUSD", "0x498bf2b1e120fed3ad3d42ea2165e9b73f99c1e5"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "scroll" => [
                ("WETH", "0x5300000000000000000000000000000000000004"),
                ("WBTC", "0x3C1BCa5a656e69edCD0D4E36BEbb3FcDAcA60Cf1"),
                ("USDT", "0xf55BEC9cafDbE8730f096Aa55dad6D22d44099Df"),
                ("USDC", "0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4"),
                ("DAI", "0xcA77eB3fEFe3725Dc33bccB54eDEFc3D9f764f97"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "vana" => [
                ("WETH", "0x2F6F07CDcf3588944Bf4C42aC74ff24bF56e7590"),
                ("USDC.e", "0xF1815bd50389c46847f0Bda824eC8da914045D14"),
                ("WVANA", "0x00EDdD9621Fb08436d0331c149D1690909a5906d"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),

            "story" => [
                ("WETH", "0xBAb93B7ad7fE8692A878B95a8e689423437cc500"),
                ("uWETH", "0x28B931354098D6863817dFDce7A2D7c52B25d76a"),
                ("storyWETH", "0x2D08d948fC0BD2Db5411E8Ab3c49E0bB89A2B428"),
                ("USDC.e", "0xF1815bd50389c46847f0Bda824eC8da914045D14"),
                ("USDC", "0x49Fe4CbB645CfE997465CA9F70f03DD9c58d1acF"),
                ("storyUSDC", "0x968B9a5603ddEb2A78Aa08182BC44Ece1D9E5bf0"),
                ("uStoryUSDC", "0xa9651875651Ff7F303605C23EF5c20C8f7BE8266"),
                ("sdaiUSDC", "0x06578bE47CF7D19784A07DB64DCF95B84EE88671"),
                ("USDT", "0x6c9b999D33C612cCd8721b0e349adcAE151fcbBf"),
                ("bridgedUSDT", "0x674843C06FF83502ddb4D37c2E09C01cdA38cbc8"),
                ("WIP", "0x1514000000000000000000000000000000000000"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),

            // Verified live 2026-10-28 on-chain (see onchain_pair_discovery.rs's
            // own doc comment): real bytecode, symbol() decodes to "WETC".
            "etc" => [("WETC", "0x1953cab0E5bFa6D4a9BaD6E05fD46C1CC6527a5a")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),

            "local" => [("ZERO", "0x0000000000000000000000000000000000000000")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),

            _ => {
                warn!("[Flashloan] Network is not supported");
                HashMap::new()
            }
        }
    }

    fn get_chain_id_for_borrow(&self) -> u32 {
        self.chain_id
    }

    fn eth_call(&mut self, address: EVMAddress, calldata: Bytes) -> Bytes {
        self.eth_call(address, calldata)
    }
}

impl OnChainConfig {
    pub fn new(chain: Chain, block_number: u64) -> Self {
        Self::new_raw(
            chain.get_chain_rpc(),
            chain.get_chain_id(),
            block_number,
            chain.get_chain_etherscan_base(),
            chain.to_lowercase(),
        )
    }

    pub fn new_raw(
        endpoint_url: String,
        chain_id: u32,
        block_number: u64,
        etherscan_base: String,
        chain_name: String,
    ) -> Self {
        let mut s = Self {
            endpoint_url,
            // PHASE 6.1: prefer a timeout-configured client; if building it
            // fails (an environment/TLS problem, not external data), log and
            // fall back rather than `.expect()`-panicking during construction.
            client: match build_http_client(20) {
                Ok(c) => c,
                Err(e) => {
                    error!("{}; falling back to a default HTTP client", e);
                    reqwest::blocking::Client::new()
                }
            },
            chain_id,
            block_number: format!("0x{:x}", block_number),
            timestamp: None,
            coinbase: None,
            gaslimit: None,
            block_hash: None,
            block_hash_fallback: format!("0x{}", "0".repeat(64)),
            etherscan_api_key: vec![],
            etherscan_base,
            chain_name,
            rpc_cache: FileSystemCache::new("./cache"),
            ..Default::default()
        };
        if block_number == 0 {
            s.set_latest_block_number();
        }
        s
    }

    fn get(&self, url: String) -> Option<String> {
        let mut hasher = DefaultHasher::new();
        let key = format!("get_{}", url.as_str());
        key.hash(&mut hasher);
        let hash = hasher.finish().to_string();
        if let Ok(t) = self.rpc_cache.load(hash.as_str()) {
            return Some(t);
        }
        match retry_with_index(Fixed::from_millis(1000), |current_try| {
            if current_try > 5 {
                return OperationResult::Err("did not succeed within 3 tries".to_string());
            }
            match self.client.get(url.to_string()).headers(get_header()).send() {
                Ok(resp) => {
                    let text = resp.text();
                    match text {
                        Ok(t) => {
                            if t.contains("Max rate limit reached") {
                                debug!("Etherscan max rate limit reached, retrying...");
                                OperationResult::Retry("Rate limit reached".to_string())
                            } else {
                                OperationResult::Ok(t)
                            }
                        }
                        Err(e) => {
                            error!("{:?}", e);
                            OperationResult::Retry("failed to parse response".to_string())
                        }
                    }
                }
                Err(e) => {
                    error!("Error: {}", e);
                    OperationResult::Retry("failed to send request".to_string())
                }
            }
        }) {
            Ok(t) => {
                if !t.contains("error") {
                    if let Err(e) = self.rpc_cache.save(hash.as_str(), t.as_str()) {
                        warn!("could not persist RPC response to cache: {}", e);
                    }
                }

                Some(t)
            }
            Err(e) => {
                error!("Error: {}", e);
                None
            }
        }
    }

    #[allow(dead_code)] // kept for parity with `get`; no live caller yet
    fn post(&self, url: String, data: String) -> Option<String> {
        let mut hasher = DefaultHasher::new();
        let key = format!("post_{}_{}", url.as_str(), data.as_str());
        key.hash(&mut hasher);
        let hash = hasher.finish().to_string();
        if let Ok(t) = self.rpc_cache.load(hash.as_str()) {
            return Some(t);
        }
        match retry_with_index(Fixed::from_millis(100), |current_try| {
            if current_try > 3 {
                return OperationResult::Err("did not succeed within 3 tries".to_string());
            }
            match self
                .client
                .post(url.to_string())
                .header("Content-Type", "application/json")
                .headers(get_header())
                .body(data.to_string())
                .send()
            {
                Ok(resp) => {
                    let text = resp.text();
                    match text {
                        Ok(t) => OperationResult::Ok(t),
                        Err(e) => {
                            error!("{:?}", e);
                            OperationResult::Retry("failed to parse response".to_string())
                        }
                    }
                }
                Err(e) => {
                    error!("Error: {}", e);
                    OperationResult::Retry("failed to send request".to_string())
                }
            }
        }) {
            Ok(t) => {
                if !t.contains("error") {
                    if let Err(e) = self.rpc_cache.save(hash.as_str(), t.as_str()) {
                        warn!("could not persist RPC response to cache: {}", e);
                    }
                }
                Some(t)
            }
            Err(e) => {
                error!("Error: {}", e);
                None
            }
        }
    }

    pub fn set_latest_block_number(&mut self) {
        let resp = self._request("eth_blockNumber".to_string(), "[]".to_string());
        let block_number = resp.as_ref().and_then(|v| v.as_str());
        match block_number {
            Some(block_number) => {
                self.block_number = block_number.to_string();
                match EVMU256::from_str_radix(block_number.trim_start_matches("0x"), 16) {
                    Ok(bn) => debug!("latest block number is {}", bn),
                    Err(e) => error!("malformed block number '{}' in RPC response: {}", block_number, e),
                }
            }
            None => {
                // Confirmed live 2026-11-01: an unreachable/not-yet-started
                // RPC (e.g. a local node the user hasn't started yet) hits
                // this path and used to `panic!` with a Rust backtrace --
                // right after already logging the exact same message
                // cleanly above. There's no way to usefully continue
                // without a known latest block, but a raw panic looks
                // like a crash/bug report rather than the clear
                // "check your RPC URL" diagnostic it actually is. Exit
                // cleanly instead; the error! above already told the user
                // what's wrong.
                error!(
                    "fail to get latest block number from RPC response: {:?}, is the RPC URL correct?",
                    resp
                );
                std::process::exit(1);
            }
        }
    }

    pub fn add_etherscan_api_key(&mut self, key: String) {
        self.etherscan_api_key.push(key);
    }

    pub fn fetch_blk_hash(&mut self) -> &String {
        if self.block_hash.is_none() {
            self.block_hash = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push(']');
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res.as_ref().and_then(|res| res["hash"].as_str()) {
                    Some(blk_hash) => Some(blk_hash.to_string()),
                    None => {
                        error!(
                            "fail to find block hash in RPC response ({:?}), falling back to zero hash",
                            res
                        );
                        Some(format!("0x{}", "0".repeat(64)))
                    }
                }
            }
        }
        // Defensive: the block above always sets it, but never unwrap on a
        // value derived from an external response.
        return self
            .block_hash
            .as_ref()
            .unwrap_or(&self.block_hash_fallback);
    }

    pub fn fetch_storage_dump(&mut self, address: EVMAddress) -> Option<Arc<HashMap<EVMU256, EVMU256>>> {
        if let Some(storage) = self.storage_dump_cache.get(&address) {
            storage.clone()
        } else {
            let storage = self.fetch_storage_dump_uncached(address);
            self.storage_dump_cache.insert(address, storage.clone());
            storage
        }
    }

    pub fn fetch_storage_dump_uncached(&mut self, address: EVMAddress) -> Option<Arc<HashMap<EVMU256, EVMU256>>> {
        let resp = {
            let blk_hash = self.fetch_blk_hash();
            let mut params = String::from("[");
            params.push_str(&format!("\"{}\",", blk_hash));
            params.push_str("0,");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str("\"\",");
            params.push_str("1000000000000000");
            params.push(']');
            self._request("debug_storageRangeAt".to_string(), params)
        };

        match resp {
            Some(resp) => {
                let mut map = HashMap::new();
                let kvs = match resp["storage"].as_object() {
                    Some(kvs) => kvs,
                    None => {
                        error!("malformed debug_storageRangeAt response, missing 'storage' object: {:?}", resp);
                        return None;
                    }
                };
                if kvs.is_empty() {
                    return None;
                }
                for (_, v) in kvs.iter() {
                    let (key, value) = match (v["key"].as_str(), v["value"].as_str()) {
                        (Some(key), Some(value)) => (key, value),
                        _ => {
                            error!("malformed storage entry in debug_storageRangeAt response: {:?}", v);
                            continue;
                        }
                    };
                    let (key, value) = match (
                        EVMU256::from_str_radix(key.trim_start_matches("0x"), 16),
                        EVMU256::from_str_radix(value.trim_start_matches("0x"), 16),
                    ) {
                        (Ok(key), Ok(value)) => (key, value),
                        _ => {
                            error!("malformed hex key/value in debug_storageRangeAt response: {} / {}", key, value);
                            continue;
                        }
                    };
                    map.insert(key, value);
                }
                Some(Arc::new(map))
            }
            None => None,
        }
    }

    pub fn fetch_abi_uncached(&self, address: EVMAddress) -> Option<String> {
        if self.is_blockscout_api() {
            return self.blockscout_fetch_abi_uncached(address);
        }

        // IoTeX's `etherscan_base` (get_chain_etherscan_base) is actually
        // its plain JSON-RPC URL, not a real Etherscan-shaped explorer API
        // -- there was never a working one wired in. Confirmed live
        // 2026-11-01: the resulting request returns the RPC's own plain-
        // text health-check string ("IoTeX RPC endpoint is ready."),
        // which fails JSON parsing below and safely falls through to
        // EVMole decompilation anyway (not a crash) -- but only after 3
        // guaranteed-futile retries with 1s sleeps between them, wasting
        // ~2s on every single IoTeX run for nothing. iotexscan.io/api
        // (the chain's real explorer) was tried as a replacement and
        // confirmed live to NOT actually implement the Etherscan
        // module/action protocol either (returns "Missing or invalid
        // action" even for basic account/balance). Short-circuit instead
        // of guessing at another unverified URL.
        if self.chain_name == "iotex" {
            return None;
        }

        #[cfg(feature = "no_etherscan")]
        {
            return None;
        }

        let endpoint = if self.etherscan_base.contains("/v2/api") {
            format!(
                "{}?chainid={}&module=contract&action=getabi&address={:?}&format=json&apikey={}",
                self.etherscan_base,
                self.chain_id,
                address,
                if !self.etherscan_api_key.is_empty() {
                    self.etherscan_api_key[rand::random::<usize>() % self.etherscan_api_key.len()].clone()
                } else {
                    "".to_string()
                }
            )
        } else {
            format!(
                "{}?module=contract&action=getabi&address={:?}&format=json&apikey={}",
                self.etherscan_base,
                address,
                if !self.etherscan_api_key.is_empty() {
                    self.etherscan_api_key[rand::random::<usize>() % self.etherscan_api_key.len()].clone()
                } else {
                    "".to_string()
                }
            )
        };

        info!("fetching abi from {}", endpoint);
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }

            let resp = match self.get(endpoint.clone()) {
                Some(resp) => resp,
                None => continue, // Request failed, retry
            };

            let json: Value = match serde_json::from_str(&resp) {
                Ok(json) => json,
                Err(_) => continue, // JSON parse error, retry
            };

            let status_ok = json["status"].as_str() == Some("1");
            let message_ok = json["message"].as_str() == Some("OK");
            if !status_ok || !message_ok {
                continue; // status/message not OK, retry
            }

            let result = match json["result"].as_str() {
                Some(result) => result,
                None => continue, // result field missing or invalid, retry
            };

            if result == "Contract source code not verified" {
                return None;
            }

            // debug!("abi fetched: {}", result);
            return Some(result.to_string());
        }

        error!("failed to fetch abi from {} after 3 attempts", endpoint);
        None
    }

    fn blockscout_fetch_abi_uncached(&self, address: EVMAddress) -> Option<String> {
        let endpoint = format!("{}/smart-contracts/{:?}", self.etherscan_base, address);

        // info!(">> {}", endpoint);
        match self.get(endpoint.clone()) {
            Some(resp) => match serde_json::from_str::<Value>(&resp) {
                Ok(json) => {
                    // info!("<< {}", json);
                    json.get("abi").map(|abi| abi.to_string())
                }
                Err(_) => {
                    error!("Failed to parse JSON response from Blockscout API");
                    None
                }
            },
            None => {
                error!("Failed to fetch ABI from Blockscout API: {}", endpoint);
                None
            }
        }
    }

    fn is_blockscout_api(&self) -> bool {
        match self.chain_name.as_str() {
            "vana" | "story" | "etc" | "mordor" => true,
            _ => false,
        }
    }

    pub fn fetch_abi(&mut self, address: EVMAddress) -> Option<String> {
        if let Some(cached) = self.abi_cache.get(&address) {
            return cached.clone();
        }
        let abi = self.fetch_abi_uncached(address);
        self.abi_cache.insert(address, abi.clone());
        abi
    }

    pub fn _request(&self, method: String, params: String) -> Option<Value> {
        let data = format!(
            "{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
            method, params, self.chain_id
        );

        // Handling HTTP request
        if self.endpoint_url.starts_with("http://") || self.endpoint_url.starts_with("https://") {
            let client = match build_http_client(10) {
                Ok(c) => c,
                Err(e) => {
                    error!("{}", e);
                    return None;
                }
            };

            // A JSON-RPC error response (e.g. a free/shared endpoint's rate
            // limit) has no "result" field, same as it looks for a request
            // that's genuinely fine but has nothing to return. Those two
            // cases used to be indistinguishable here -- an error silently
            // became `None`, which every caller treats as "zero"/"absent"
            // instead of "the RPC failed, this call learned nothing real".
            // Retrying a few times with backoff turns a transient rate
            // limit into a real answer instead of a wrong one.
            let result = retry_with_index(Fixed::from_millis(500), |current_try| {
                if current_try > 5 {
                    return OperationResult::Err("RPC request did not succeed within 5 tries".to_string());
                }
                debug!(">> {} {}", self.endpoint_url, data);
                let resp = match client
                    .post(&self.endpoint_url)
                    .header("Content-Type", "application/json")
                    .body(data.clone())
                    .send()
                    .ok()
                    .and_then(|resp| resp.text().ok())
                {
                    Some(resp) => resp,
                    None => return OperationResult::Retry("failed to send/read RPC request".to_string()),
                };
                debug!("<< {}", resp);

                match parse_rpc_response(&resp) {
                    Ok(result) => OperationResult::Ok(result),
                    // A rate limit / transient RPC error is worth retrying.
                    Err(RpcResponseError::Rpc(_)) => {
                        OperationResult::Retry(format!("RPC error response: {}", resp))
                    }
                    Err(e) => OperationResult::Retry(format!("{} ({})", e, resp)),
                }
            });

            return match result {
                Ok(value) => Some(value),
                Err(e) => {
                    error!("RPC request {} {} to {} failed: {}", method, params, self.endpoint_url, e);
                    None
                }
            };
        }
        // Handling IPC request
        else if self.endpoint_url.starts_with("/") ||
            self.endpoint_url.starts_with("./") ||
            self.endpoint_url.starts_with("../")
        {
            match UnixStream::connect(&self.endpoint_url) {
                Ok(mut socket) => {
                    if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(10))) {
                        error!("Failed to set IPC read timeout: {}", e);
                    }
                    if let Err(e) = socket.set_write_timeout(Some(Duration::from_secs(5))) {
                        error!("Failed to set IPC write timeout: {}", e);
                    }

                    if let Err(e) = socket.write_all(data.as_bytes()) {
                        error!("Failed to write to IPC stream: {}", e);
                        return None;
                    }

                    let mut response = String::new();
                    let mut buffer = [0; 4096];
                    let timeout = Duration::from_secs(10);
                    let start_time = Instant::now();

                    while start_time.elapsed() < timeout {
                        match socket.read(&mut buffer) {
                            Ok(0) => {
                                error!("No data read from IPC stream; the stream might have been closed.");
                                return None;
                            }
                            Ok(n) => {
                                response.push_str(&String::from_utf8_lossy(&buffer[..n]));
                                if response.contains("\n") {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                            Err(e) => {
                                error!("Failed to read from IPC stream: {}", e);
                                return None;
                            }
                        }
                    }

                    if start_time.elapsed() >= timeout {
                        error!("Timeout reached while reading from the IPC stream.");
                        return None;
                    }

                    serde_json::from_str(&response)
                        .ok()
                        .and_then(|json: Value| json.get("result").cloned())
                }
                Err(e) => {
                    error!("IPC connection failed: {}", e);
                    return None;
                }
            }
        } else {
            error!("Unsupported URL scheme: {}", self.endpoint_url);
            None
        }
    }

    fn _request_with_id(&self, method: String, params: String, id: u8) -> Option<Value> {
        let data = format!(
            "{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
            method, params, id
        );

        // Handling HTTP request
        if self.endpoint_url.starts_with("http://") || self.endpoint_url.starts_with("https://") {
            let client = match build_http_client(10) {
                Ok(c) => c,
                Err(e) => {
                    error!("{}", e);
                    return None;
                }
            };

            return client
                .post(&self.endpoint_url)
                .header("Content-Type", "application/json")
                .body(data)
                .send()
                .ok()
                .and_then(|resp| resp.text().ok())
                .and_then(|resp| serde_json::from_str(&resp).ok())
                .and_then(|json: Value| json.get("result").cloned());
        }
        // Handling IPC request
        else if self.endpoint_url.starts_with("/") ||
            self.endpoint_url.starts_with("./") ||
            self.endpoint_url.starts_with("../")
        {
            match UnixStream::connect(&self.endpoint_url) {
                Ok(mut socket) => {
                    if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(10))) {
                        error!("Failed to set IPC read timeout: {}", e);
                    }
                    if let Err(e) = socket.set_write_timeout(Some(Duration::from_secs(5))) {
                        error!("Failed to set IPC write timeout: {}", e);
                    }

                    if let Err(e) = socket.write_all(data.as_bytes()) {
                        error!("Failed to write to IPC stream: {}", e);
                        return None;
                    }

                    let mut response = String::new();
                    let mut buffer = [0; 4096];
                    let timeout = Duration::from_secs(10);
                    let start_time = Instant::now();

                    while start_time.elapsed() < timeout {
                        match socket.read(&mut buffer) {
                            Ok(0) => {
                                error!("No data read from IPC stream; the stream might have been closed.");
                                return None;
                            }
                            Ok(n) => {
                                response.push_str(&String::from_utf8_lossy(&buffer[..n]));
                                if response.contains("\n") {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                            Err(e) => {
                                error!("Failed to read from IPC stream: {}", e);
                                return None;
                            }
                        }
                    }

                    if start_time.elapsed() >= timeout {
                        error!("Timeout reached while reading from the IPC stream.");
                        return None;
                    }

                    serde_json::from_str(&response)
                        .ok()
                        .and_then(|json: Value| json.get("result").cloned())
                }
                Err(e) => {
                    error!("IPC connection failed: {}", e);
                    return None;
                }
            }
        } else {
            error!("Unsupported URL scheme: {}", self.endpoint_url);
            None
        }
    }

    pub fn get_balance(&mut self, address: EVMAddress) -> EVMU256 {
        if self.balance_cache.contains_key(&address) {
            return self.balance_cache[&address];
        }

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"{}\"", self.block_number));
            params.push(']');
            let resp = self._request("eth_getBalance".to_string(), params);
            match resp.as_ref().and_then(|resp| resp.as_str()) {
                Some(balance) => balance.to_string(),
                None => {
                    error!("malformed eth_getBalance response for {:?}: {:?}", address, resp);
                    "".to_string()
                }
            }
        };
        let balance = EVMU256::from_str(&resp_string).unwrap_or_else(|e| {
            error!("fail to parse balance '{}' for {:?}: {}", resp_string, address, e);
            EVMU256::ZERO
        });
        info!("balance of {address:?} at {} is {balance}", self.block_number);
        self.balance_cache.insert(address, balance);
        balance
    }

    pub fn eth_call(&mut self, address: EVMAddress, calldata: Bytes) -> Bytes {
        let call = format!(
            "\"from\": null,\"to\":\"{:?}\",\"data\":\"0x{}\"",
            address,
            hex::encode(calldata.to_vec())
        );
        let wrapped_call = format!("[{{{}}},\"{}\"]", call, self.block_number);
        // println!("wrapped_call: {}", wrapped_call);
        let resp_string = {
            let resp = self._request("eth_call".to_string(), wrapped_call);
            match resp.as_ref().and_then(|resp| resp.as_str()) {
                Some(res) => res.to_string(),
                None => {
                    error!("malformed eth_call response for {:?}: {:?}", address, resp);
                    "".to_string()
                }
            }
        };
        match hex::decode(resp_string.trim_start_matches("0x")) {
            Ok(bytes) => Bytes::from(bytes),
            Err(e) => {
                error!("malformed hex in eth_call response for {:?}: '{}': {}", address, resp_string, e);
                Bytes::new()
            }
        }
    }

    pub fn get_token_balance(&mut self, token: EVMAddress, address: EVMAddress) -> EVMU256 {
        let data = format!("70a08231000000000000000000000000{:x}", address);
        let calldata = match hex::decode(&data) {
            Ok(bytes) => Bytes::from(bytes),
            Err(e) => {
                error!("could not encode balanceOf calldata for {:?}: {}", address, e);
                return EVMU256::ZERO;
            }
        };
        let balance = self.eth_call(token, calldata);
        EVMU256::from_be_slice(&balance)
    }

    pub fn get_v3_fee(&mut self, address: EVMAddress) -> u32 {
        let data = "ddca3f43".to_string();
        let calldata = match hex::decode(&data) {
            Ok(bytes) => Bytes::from(bytes),
            Err(e) => {
                error!("could not encode v3-fee calldata for {:?}: {}", address, e);
                return 0;
            }
        };
        let fee = self.eth_call(address, calldata);
        if fee.len() < 32 {
            error!("malformed eth_call result for v3 fee of {:?}: {:?}", address, fee);
            return 0;
        }
        u32::from_be_bytes([fee[28], fee[29], fee[30], fee[31]])
    }

    pub fn fetch_blk_timestamp(&mut self) -> EVMU256 {
        if self.timestamp.is_none() {
            self.timestamp = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push(']');
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res.as_ref().and_then(|res| res["timestamp"].as_str()) {
                    Some(blk_timestamp) => Some(blk_timestamp.to_string()),
                    None => {
                        error!("fail to find block timestamp in RPC response ({:?}), falling back to 0", res);
                        Some("0x0".to_string())
                    }
                }
            }
        }
        // PHASE 6.1: the field is always set just above, but never unwrap an
        // Option that mirrors external RPC state.
        match self.timestamp.as_deref() {
            Some(ts) => EVMU256::from_str(ts).unwrap_or_else(|e| {
                error!("fail to parse block timestamp '{ts}': {e}");
                EVMU256::ZERO
            }),
            None => {
                error!("block timestamp unavailable, using 0");
                EVMU256::ZERO
            }
        }
    }

    pub fn fetch_blk_coinbase(&mut self) -> EVMAddress {
        if self.coinbase.is_none() {
            self.coinbase = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push(']');
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res.as_ref().and_then(|res| res["miner"].as_str()) {
                    Some(blk_coinbase) => Some(blk_coinbase.to_string()),
                    None => {
                        error!("fail to find block coinbase in RPC response ({:?}), falling back to zero address", res);
                        Some(format!("0x{}", "0".repeat(40)))
                    }
                }
            }
        }
        match self.coinbase.as_deref() {
            Some(cb) => EVMAddress::from_str(cb).unwrap_or_else(|e| {
                error!("fail to parse block coinbase '{cb}': {e}");
                EVMAddress::default()
            }),
            None => {
                error!("block coinbase unavailable, using zero address");
                EVMAddress::default()
            }
        }
    }

    pub fn fetch_blk_gaslimit(&mut self) -> EVMU256 {
        if self.gaslimit.is_none() {
            self.gaslimit = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push(']');
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res.as_ref().and_then(|res| res["gasLimit"].as_str()) {
                    Some(blk_gaslimit) => Some(blk_gaslimit.to_string()),
                    None => {
                        error!("fail to find block gas limit in RPC response ({:?}), falling back to 0", res);
                        Some("0x0".to_string())
                    }
                }
            }
        }
        let parsed = match self.gaslimit.as_deref() {
            Some(gl) => EVMU256::from_str(gl).unwrap_or_else(|e| {
                error!("fail to parse block gas limit '{gl}': {e}");
                EVMU256::ZERO
            }),
            None => {
                error!("block gas limit unavailable, using 0");
                EVMU256::ZERO
            }
        };
        // Hard ceiling: never let the fuzzer's simulated block gas limit
        // exceed MAX_BLOCK_GAS_LIMIT. ETC mainnet's real block gasLimit
        // fluctuates (8,000,000 in most blocks, 8,007,811 in others), and
        // a trace simulated under the higher value can look executable
        // while being un-includable on-chain the moment it drops back.
        // Clamping here keeps the fuzzer from pursuing such traces.
        parsed.min(EVMU256::from(MAX_BLOCK_GAS_LIMIT))
    }

    pub fn get_contract_code(&mut self, address: EVMAddress, force_cache: bool) -> String {
        if self.code_cache.contains_key(&address) {
            return self.code_cache[&address].clone();
        }
        if force_cache {
            return "".to_string();
        }

        info!("eth_getCode 0x{}", hex::encode(address));

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"{}\"", self.block_number));
            // params.push_str("\"latest\"");
            params.push(']');
            let resp = self._request("eth_getCode".to_string(), params);
            match resp.as_ref().and_then(|resp| resp.as_str()) {
                Some(code) => code.to_string(),
                None => {
                    info!("empty or malformed code response for address 0x{:x}: {:?}", address, resp);
                    "".to_string()
                }
            }
        }
        .trim_start_matches("0x")
        .to_string();
        self.code_cache.insert(address, resp_string.clone());
        resp_string
    }

    pub fn get_contract_code_analyzed(&mut self, address: EVMAddress, force_cache: bool) -> Bytecode {
        if self.code_cache_analyzed.contains_key(&address) {
            return self.code_cache_analyzed[&address].clone();
        }

        let code = self.get_contract_code(address, force_cache);
        let code_bytes = match hex::decode(&code) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("fail to decode contract code for {:?} ('{}'): {}, treating as empty", address, code, e);
                Vec::new()
            }
        };
        let contract_code = to_analysed(Bytecode::new_raw(Bytes::from(code_bytes)));
        let contract_code = to_analysed(contract_code);
        self.code_cache_analyzed.insert(address, contract_code.clone());
        contract_code
    }

    pub fn get_contract_slot(&mut self, address: EVMAddress, slot: EVMU256, force_cache: bool) -> EVMU256 {
        if self.slot_cache.contains_key(&(address, slot)) {
            return self.slot_cache[&(address, slot)];
        }
        if force_cache {
            return EVMU256::ZERO;
        }

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"0x{:x}\",", slot));
            params.push_str(&format!("\"{}\"", self.block_number));
            params.push(']');
            let resp = self._request("eth_getStorageAt".to_string(), params);
            match resp.as_ref().and_then(|resp| resp.as_str()) {
                Some(slot_data) => slot_data.to_string(),
                None => {
                    error!("malformed eth_getStorageAt response for {:?}/{:?}: {:?}", address, slot, resp);
                    "".to_string()
                }
            }
        };

        let slot_suffix = resp_string.trim_start_matches("0x");

        if slot_suffix.is_empty() {
            self.slot_cache.insert((address, slot), EVMU256::ZERO);
            return EVMU256::ZERO;
        }
        let slot_value = hex::decode(slot_suffix)
            .ok()
            .and_then(|bytes| EVMU256::try_from_be_slice(&bytes))
            .unwrap_or_else(|| {
                error!("malformed slot value '{}' for {:?}/{:?}, treating as zero", slot_suffix, address, slot);
                EVMU256::ZERO
            });
        self.slot_cache.insert((address, slot), slot_value);
        slot_value
    }
}

impl OnChainConfig {
    /// Finds pairs for `token` entirely on-chain, against every
    /// known-pegged token on this chain (`onchain_pair_discovery.rs`'s
    /// KNOWN_V2_FACTORIES base token plus `get_pegged_token()`'s own
    /// list) -- direct `eth_call`s only, no third-party service of any
    /// kind. This used to call DanyTech's own
    /// `pairs-all.infra.danytech` subgraph first and only fall back to
    /// on-chain lookup if that failed; it no longer calls it at all,
    /// anywhere, under any condition. A chain not yet in
    /// KNOWN_V2_FACTORIES simply returns no pairs -- an honest "not
    /// covered yet", not a disguised dependency on infrastructure this
    /// project doesn't own.
    pub fn get_pair(&mut self, token: &str) -> Vec<PairData> {
        let token: String = token.to_lowercase();
        // Confirmed live 2026-11-01: the INSERT below already guarded
        // against a malformed `token` with `.unwrap_or_default()`, but
        // these two reads just above it still used a bare `.unwrap()` --
        // a caller passing anything that doesn't parse as an address
        // would panic here before ever reaching that existing fallback.
        // Mirror the same safe fallback (falls through to cache miss ->
        // on-chain lookup -> cached under the zero address, same as any
        // other cache-miss path, not a crash).
        let token_addr = EVMAddress::from_str(&token).unwrap_or_default();
        if self.pair_cache.contains_key(&token_addr) {
            return self.pair_cache[&token_addr].clone();
        }
        let pairs = crate::evm::tokens::onchain_pair_discovery::fetch_pegged_pair_data_onchain(self, &token);
        self.pair_cache.insert(token_addr, pairs.clone());
        info!(?pairs, "fetched {} pairs for {} (on-chain only)", pairs.len(), token);
        pairs
    }

    pub fn fetch_reserve(&self, pair: &str) -> Option<(String, String)> {
        let result = {
            let params = json!([{
            "to": pair,
            "data": "0x0902f1ac",
            "id": 1
        }, self.block_number]);
            debug!("fetching reserve for {pair} {}", self.block_number);
            let resp = self._request_with_id("eth_call".to_string(), params.to_string(), 1);
            match resp {
                Some(resp) => resp.to_string(),
                None => "".to_string(),
            }
        };

        if result.len() != 196 {
            let rpc = &self.endpoint_url;
            // This whole branch is already an "unexpected response"
            // diagnostic path -- a malformed `pair` on top of that used
            // to panic here (via a bare `.unwrap()`) while trying to log
            // extra context about a DIFFERENT problem. Fall back to the
            // zero address instead so a bad `pair` string degrades to a
            // confusing-but-harmless log line, not a second, compounding
            // crash.
            let pair_code = self
                .clone()
                .get_contract_code(B160::from_str(pair).unwrap_or_default(), true);
            info!("rpc: {rpc}, result: {result}, pair: {pair}, pair code: {pair_code}");
            info!("Unexpected RPC error, consider setting env <ETH_RPC_URL> ");
            return None;
        }

        let reserve1 = &result[3..67];
        let reserve2 = &result[67..131];

        Some((reserve1.into(), reserve2.into()))
    }
}

fn get_header() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authority", "etherscan.io".parse().unwrap());
    headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9".parse().unwrap());
    headers.insert("accept-language", "zh-CN,zh;q=0.9,en;q=0.8".parse().unwrap());
    headers.insert("cache-control", "max-age=0".parse().unwrap());
    headers.insert(
        "sec-ch-ua",
        "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\", \"Google Chrome\";v=\"108\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"macOS\"".parse().unwrap());
    headers.insert("sec-fetch-dest", "document".parse().unwrap());
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    headers.insert("sec-fetch-site", "none".parse().unwrap());
    headers.insert("sec-fetch-user", "?1".parse().unwrap());
    headers.insert("upgrade-insecure-requests", "1".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers
}

#[cfg(test)]
mod tests {
    use tracing::debug;

    use super::*;
    use crate::evm::{
        onchain::endpoints::Chain::{BSC, ETH},
        types::EVMAddress,
    };

    /// PHASE 6.1 / PHASE 6.3: a deliberately broken RPC response must never
    /// panic -- it must return a typed error. These are the exact shapes a
    /// real node can emit under load: an empty body, a literal `null`, a
    /// JSON-RPC error object, truncated JSON, and a body with neither
    /// `result` nor `error`.
    #[test]
    fn test_parse_rpc_response_never_panics_on_garbage() {
        // Empty / whitespace / literal null -> Malformed, not a panic.
        assert!(matches!(parse_rpc_response(""), Err(RpcResponseError::Malformed(_))));
        assert!(matches!(parse_rpc_response("   "), Err(RpcResponseError::Malformed(_))));
        assert!(matches!(parse_rpc_response("null"), Err(RpcResponseError::Malformed(_))));
        // Truncated JSON.
        assert!(matches!(
            parse_rpc_response("{\"result\": \"0x1\""),
            Err(RpcResponseError::Malformed(_))
        ));
        // A JSON-RPC error object (e.g. rate limit).
        assert!(matches!(
            parse_rpc_response("{\"error\":{\"code\":-32005,\"message\":\"rate limited\"}}"),
            Err(RpcResponseError::Rpc(_))
        ));
        // Valid JSON, no result and no error.
        assert!(matches!(
            parse_rpc_response("{\"jsonrpc\":\"2.0\",\"id\":1}"),
            Err(RpcResponseError::MissingResult)
        ));
    }

    #[test]
    fn test_parse_rpc_response_returns_result() {
        let v = parse_rpc_response("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x10\"}").unwrap();
        assert_eq!(v.as_str(), Some("0x10"));
        // A null result is still a successful parse (the call learned
        // "nothing", which callers already handle as absent).
        let v = parse_rpc_response("{\"result\":null}").unwrap();
        assert!(v.is_null());
    }

    /// PHASE 6.3 end-to-end proof: point a real `OnChainConfig` at a local
    /// socket that answers every request with a corrupted body (empty,
    /// truncated, and a JSON-RPC error in turn) and drive `_request` -- the
    /// same method every on-chain code path uses. It must return `None`
    /// (fail cleanly), never panic, for each malformed shape.
    #[test]
    fn test_request_with_corrupted_rpc_does_not_panic() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };

        let bodies: [&str; 3] = ["", "{\"result\": \"0x1\"", "{\"error\":{\"code\":-32005,\"message\":\"rate limited\"}}"];

        for body in bodies {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            let port = listener.local_addr().unwrap().port();
            let body_owned = body.to_string();
            let server = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_owned.len(),
                        body_owned
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
            });

            let config = OnChainConfig::new_raw(
                format!("http://127.0.0.1:{port}"),
                1,
                // Non-zero block number: a zero one makes `new_raw` resolve
                // "latest" over the wire, which would fail here for reasons
                // unrelated to what this test proves (it deliberately
                // `exit(1)`s when no latest block can be read).
                1,
                String::new(),
                "test".to_string(),
            );
            // The retry loop will hit this server once (it then answers
            // nothing more); the assertion that matters is simply that this
            // returns instead of panicking.
            let result = config._request("eth_blockNumber".to_string(), "[]".to_string());
            assert!(result.is_none(), "corrupted body {body:?} must yield None");
            let _ = server.join();
        }
    }

    #[test]
    fn test_onchain_config() {
        let config = OnChainConfig::new(BSC, 0);
        let v = config._request(
            "eth_getCode".to_string(),
            "[\"0x0000000000000000000000000000000000000000\", \"latest\"]".to_string(),
        );
        debug!("{:?}", v)
    }

    #[test]
    fn test_get_contract_slot() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config.get_contract_slot(
            EVMAddress::from_str("0xb486857fac4254a7ffb3b1955ee0c0a2b2ca75ab").unwrap(),
            EVMU256::from(3),
            false,
        );
        debug!("{:?}", v)
    }

    #[test]
    fn test_fetch_abi() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config.fetch_abi(EVMAddress::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap());
        debug!("{:?}", v)
    }

    #[test]
    fn test_mordor_chain_roundtrips() {
        // Pure, no network needed: guards the two chain-id matches
        // (Chain::get_chain_id and new_with_rpc_url's chain-id inference)
        // against ever silently drifting apart again, the way `61 =>
        // Self::ETC` was simply missing from the latter until this test
        // was added.
        assert_eq!(Chain::from_str("mordor").unwrap(), Chain::MORDOR);
        assert_eq!(Chain::MORDOR.get_chain_id(), 63);
        assert_eq!(Chain::ETC.get_chain_id(), 61);
    }

    #[test]
    fn test_new_with_rpc_url_infers_mordor() {
        // Live: confirms new_with_rpc_url's chain-id inference (used by
        // Foundry's createSelectFork("https://...") cheatcode) resolves
        // Mordor's real RPC to Chain::MORDOR, not "Unknown chain id: 63".
        let chain = Chain::new_with_rpc_url("https://rpc.mordor.etccooperative.org").unwrap();
        assert_eq!(chain, Chain::MORDOR);
    }

    #[test]
    fn test_get_balance() {
        let mut config = OnChainConfig::new(ETH, 18168677);
        let v = config.get_balance(EVMAddress::from_str("0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326").unwrap());
        debug!("{:?}", v);
        assert!(v == EVMU256::from(439351222497229612i64));
    }

    #[test]
    fn test_get_pair_pegged() {
        // Was pinned to a fixed historical block (22055611); bsc-rpc.
        // publicnode.com (the default BSC RPC) now paywalls eth_call this
        // far behind head ("Archive requests require a personal token",
        // confirmed live 2026-10-28 -- same class of issue documented on
        // onchain_pair_discovery.rs's test helper). This now hits that
        // fallback's own eth_call too, so it needs a reachable block the
        // same way.
        let mut config = OnChainConfig::new(BSC, 0);
        config.set_latest_block_number();
        let latest = u64::from_str_radix(config.block_number.trim_start_matches("0x"), 16).unwrap();
        let mut config = OnChainConfig::new(BSC, latest.saturating_sub(20));
        let v = config.get_pair("0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82");
        assert!(!v.is_empty() && v.len() < 10);
    }

    #[test]
    fn test_get_token_balance() {
        let mut config = OnChainConfig::new(BSC, 37381166);
        let v = config.get_token_balance(
            EVMAddress::from_str("0xfb5B838b6cfEEdC2873aB27866079AC55363D37E").unwrap(),
            EVMAddress::from_str("0xf977814e90da44bfa03b6295a0616a897441acec").unwrap(),
        );
        println!("{:?}", v);
    }

    #[test]
    fn get_v3_fee() {
        let mut config = OnChainConfig::new(BSC, 37381166);
        let v = config.get_v3_fee(EVMAddress::from_str("0x4f31fa980a675570939b737ebdde0471a4be40eb").unwrap());
        println!("{:?}", v);
    }

    // #[test]
    // fn test_fetch_token_price() {
    //     let mut config = OnChainConfig::new(BSC, 0);
    //     config.add_moralis_api_key(
    //         "ocJtTEZWOJZjYOMAQjRmWcHpvUdieMLJDAtUjycFNTdSxgFGofNJhdiRX0Kk1h1O".to_string(),
    //     );
    //     let v = config.fetch_token_price(
    //         EVMAddress::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4"
    // ).unwrap(),     );
    //     debug!("{:?}", v)
    // }
    //
    // #[test]
    // fn test_fetch_storage_all() {
    //     let mut config = OnChainConfig::new(BSC, 0);
    //     let v = config.fetch_storage_all(
    //         EVMAddress::from_str("0x2aB472b185787b665f334F12618254CaCA668e49"
    // ).unwrap(),     );
    //     debug!("{:?}", v)
    // }

    // #[test]
    // fn test_fetch_storage_dump() {
    //     let mut config = OnChainConfig::new(ETH, 0);
    //     let v = config
    //         .fetch_storage_dump(
    //
    // EVMAddress::from_str("0x3ea826a2724f3df727b64db552f3103192158c58").
    // unwrap(),         )
    //         .unwrap();

    //     let v0 = v.get(&EVMU256::from(0)).unwrap().clone();

    //     let slot_v = config.get_contract_slot(
    //         EVMAddress::from_str("0x3ea826a2724f3df727b64db552f3103192158c58"
    // ).unwrap(),         EVMU256::from(0),
    //         false,
    //     );

    //     assert_eq!(slot_v, v0);
    // }
}
