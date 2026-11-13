pub mod abi;
pub mod blaz;
pub mod bytecode_analyzer;
pub mod bytecode_iterator;
pub mod concolic;
pub mod config;
pub mod contract_utils;
pub mod corpus_initializer;
pub mod auto_setup;
pub mod cov_stage;
pub mod feedbacks;
pub mod host;
pub mod input;
pub mod middlewares;
pub mod minimizer;
pub mod multicore;
pub mod mutator;
pub mod onchain;
pub mod oracle;
pub mod oracles;
pub mod presets;
pub mod producers;
pub mod scheduler;
pub mod setup;
pub mod solution;
pub mod srcmap;
pub mod tokens;
pub mod types;
pub mod utils;
pub mod vm;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt,

    path::Path,
    rc::Rc,
    str::FromStr,
};

use blaz::{
    builder::{BuildJob, BuildJobResult},
    offchain_artifacts::OffChainArtifact,
    offchain_config::OffchainConfig,
};
use clap::Parser;
use config::{Config, StorageFetchingMode};
use contract_utils::ContractLoader;
use ethers::types::Transaction;
use input::{ConciseEVMInput, EVMInput};
use itertools::Itertools;
use onchain::endpoints::{Chain, OnChainConfig};
use oracles::{
    access_control::AccessControlOracle,
    arb_transfer::ArbitraryERC20TransferOracle,
    assert_violation::AssertViolationOracle,
    centralization_risk::CentralizationRiskOracle,
    curve_virtual_price::CurveVirtualPriceOracle,
    erc20::IERC20OracleFlashloan,
    erc4626::Erc4626ShareInflationOracle,
    eth_backing::EthBackingOracle,
    gas_stipend::GasStipendOracle,
    initializer_front_run::InitializerFrontRunOracle,
    nft_transfer::NftTransferOracle,
    precision_loss::PrecisionLossOracle,
    preview_rounding::PreviewRoundingOracle,
    price_feed_staleness::PriceFeedStalenessOracle,
    proxy_integrity::ProxyIntegrityOracle,
    proxy_upgrade_hijack::ProxyUpgradeHijackOracle,
    unbacked_mint::UnbackedMintOracle,
    forged_proof::ForgedProofOracle,
    transient_guard::TransientGuardOracle,
    revert_in_loop::RevertInLoopOracle,
    signature_malleability::SignatureMalleabilityOracle,
    signature_replay::SignatureReplayOracle,
    twap_manipulation::TwapManipulationOracle,
    v2_pair::PairBalanceOracle,
    weak_randomness::WeakRandomnessOracle,
    zero_address_setter::ZeroAddressSetterOracle,
};
use producers::erc20::ERC20Producer;
use revm_primitives::B160;
// use revm_primitives::ruint::aliases::B160;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, error, warn};
use types::{EVMAddress, EVMFuzzState, EVMU256};
use vm::EVMState;

use self::types::EVMQueueExecutor;
use crate::{
    fuzzers::evm_fuzzer::evm_fuzzer,
    oracle::{Oracle, Producer},
    state::FuzzState,
};

pub const PRESET_WETH: &str = "0x4200000000000000000000000000000000000006";

// Canonical EIP-1967 proxy storage slots. These are the single source of
// truth for the whole crate: every oracle and the proxy-expansion logic
// reference them instead of re-declaring their own copy. A hand-copied
// literal is exactly how the beacon/UUPS slots drifted wrong (a wrong slot
// read returns 0, indistinguishable from "not a proxy", so the failure was
// silent) -- one definition, guarded by
// `contract_utils::tests::test_proxy_slot_constants_match_keccak`, removes
// the whole duplication class.
//
//   implementation = keccak256("eip1967.proxy.implementation") - 1
//   admin          = keccak256("eip1967.proxy.admin") - 1
//   beacon         = keccak256("eip1967.proxy.beacon") - 1
pub const EIP1967_IMPLEMENTATION_SLOT: [u8; 32] = [
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d, 0xca, 0x3e, 0x20,
    0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
];
pub const EIP1967_ADMIN_SLOT: [u8; 32] = [
    0xb5, 0x31, 0x27, 0x68, 0x4a, 0x56, 0x8b, 0x31, 0x73, 0xae, 0x13, 0xb9, 0xf8, 0xa6, 0x01, 0x6e, 0x24, 0x3e, 0x63,
    0xb6, 0xe8, 0xee, 0x11, 0x78, 0xd6, 0xa7, 0x17, 0x85, 0x0b, 0x5d, 0x61, 0x03,
];

/// Resolve the number of concolic (Z3) worker threads from the CLI value.
///
/// Concolic solving runs on a bounded worker-thread pool: at most
/// `min(MAX_CONCOLIC_THREADS, cores)` solvers are live at once (see
/// `max_concolic_threads()`), and that ceiling is campaign-wide -- `--jobs N`
/// shares it rather than multiplying it. The historical default was
/// `num_cpus::get()`, which launched one solver per core and froze a 15-core
/// host; the cap keeps the pool parallel without oversubscribing.
///
/// A caller may request FEWER threads than the cap (`--concolic-num-threads`
/// 1 forces a single sequential solver); a request for more than the cap is
/// clamped to it, with a warning, since exceeding it is the exact
/// oversubscription this cap exists to prevent. `0`/unset means "use the cap".
fn resolve_concolic_num_threads(requested: usize) -> usize {
    let cap = crate::r#const::max_concolic_threads();
    if requested == 0 {
        return cap;
    }
    if requested > cap {
        warn!(
            "concolic: --concolic-num-threads {requested} clamped to {cap} \
             (min(MAX_CONCOLIC_THREADS, cores)); more parallel Z3 solvers oversubscribe the host"
        );
        return cap;
    }
    requested
}

/// Resolve the effective deployment-script string from the two CLI flags that
/// feed it.
///
/// `--deployment-script`/`-m` is the modern spelling; `--setup-file` is its
/// deprecated alias. Both used to be collapsed with an unconditional
/// `setup_file = deployment_script`, which silently discarded an explicitly
/// passed `--setup-file` whenever `--deployment-script` was left at its empty
/// default -- a user following the (still-printed) `--setup-file` help text got
/// a "Deployment script  not found" panic with no hint why.
///
/// Rules:
///   * both empty            -> "" (the caller infers the target type elsewhere)
///   * only `--setup-file`   -> that value (the deprecated flag still works)
///   * only `-m`             -> that value
///   * both, same value      -> that value
///   * both, different       -> `--deployment-script` wins (it is the documented
///     current spelling), but the conflict is returned so the caller can warn
///     instead of silently dropping one.
pub(crate) fn resolve_setup_file(setup_file: &str, deployment_script: &str) -> (String, bool) {
    let deprecated = setup_file.trim();
    let current = deployment_script.trim();
    match (deprecated.is_empty(), current.is_empty()) {
        (true, true) => (String::new(), false),
        (false, true) => (deprecated.to_string(), false),
        (true, false) => (current.to_string(), false),
        (false, false) => {
            let conflict = deprecated != current;
            (current.to_string(), conflict)
        }
    }
}

pub fn parse_constructor_args_string(input: String) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();

    if input.is_empty() {
        return map;
    }

    let pairs: Vec<&str> = input.split(';').collect();
    for pair in pairs {
        let key_value: Vec<&str> = pair.split(':').collect();
        if key_value.len() == 2 {
            let values: Vec<String> = key_value[1].split(',').map(|s| s.to_string()).collect();
            map.insert(key_value[0].to_string(), values);
        }
    }

    map
}

#[derive(Deserialize)]
struct Data {
    body: RPCCall,
}

#[derive(Deserialize)]
struct RPCCall {
    method: String,
    params: Option<serde_json::Value>,
}

/// CLI for ForkSploit for EVM smart contracts
#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None, trailing_var_arg = true, allow_hyphen_values = true)]
pub struct EvmArgs {
    /// Glob pattern / address to find contracts
    #[arg(short, long, default_value = "none")]
    target: String,

    #[arg(long, default_value = "false")]
    fetch_tx_data: bool,

    #[arg(long, default_value = "http://localhost:5001/data")]
    proxy_address: String,

    /// Constructor arguments for the contract, separated by semicolon.
    #[arg(long, default_value = "")]
    constructor_args: String,

    /// Target type (glob, address, anvil_fork, config, setup)
    /// (Default: Automatically infer from target)
    #[arg(long)]
    target_type: Option<String>,

    /// Onchain - Chain type
    /// (eth,goerli,sepolia,bsc,chapel,polygon,mumbai,fantom,avalanche,optimism,
    /// arbitrum,gnosis,base,celo,zkevm,zkevm_testnet,blast,linea,iotex,scroll,
    /// vana,story,etc,mordor,local)
    #[arg(short, long)]
    chain_type: Option<String>,

    /// Onchain - Block number (Default: 0 / latest)
    #[arg(long, short = 'b')]
    onchain_block_number: Option<u64>,

    /// Onchain Customize - RPC endpoint URL (Default: inferred from
    /// chain-type), Example: https://rpc.ankr.com/eth
    #[arg(long, short = 'u')]
    onchain_url: Option<String>,

    /// Onchain Customize - Chain ID (Default: inferred from chain-type)
    #[arg(long, short = 'i')]
    onchain_chain_id: Option<u32>,

    /// Onchain Customize - Block explorer URL (Default: inferred from
    /// chain-type), Example: https://api.etherscan.io/api
    #[arg(long, short = 'e')]
    onchain_explorer_url: Option<String>,

    /// Onchain Customize - Chain name (used as Moralis handle of chain)
    /// (Default: inferred from chain-type)
    #[arg(long, short = 'n')]
    onchain_chain_name: Option<String>,

    /// Onchain Etherscan API Key (Default: None)
    #[arg(long, short = 'k')]
    onchain_etherscan_api_key: Option<String>,

    /// Onchain which fetching method to use (dump, onebyone) (Default:
    /// onebyone)
    #[arg(long, default_value = "onebyone")]
    onchain_storage_fetching: String,

    /// Enable Concolic (Experimental)
    #[arg(long, default_value = "false")]
    concolic: bool,

    /// Support Treating Caller as Symbolically  (Experimental)
    #[arg(long, default_value = "false")]
    concolic_caller: bool,

    /// Time limit for concolic execution (ms) (Default: 1000, 0 for no limit)
    #[arg(long, default_value = "1000")]
    concolic_timeout: u32,

    /// Per-solve Z3 memory ceiling in MiB (Default: 2048, 0 = no limit).
    /// A hard path condition can make Z3 grow memory without bound while
    /// still returning inside --concolic-timeout; Z3 then returns `unknown`
    /// (treated as "couldn't solve this one") instead of exhausting host RAM.
    #[arg(long, default_value = "2048")]
    concolic_memory_mb: u32,

    /// Concolic (Z3) solver threads. Default 0 = the campaign-wide cap
    /// min(2, cores). A smaller value runs fewer solvers (1 = sequential);
    /// a larger one is clamped to the cap, since more concurrent Z3 solvers
    /// oversubscribe the host. --jobs N shares this cap, never multiplies it.
    #[arg(long, default_value = "0")]
    concolic_num_threads: usize,

    /// Enable flashloan
    #[arg(short, long, default_value = "false")]
    flashloan: bool,

    /// Panic when a typed_bug() is called (Default: false)
    #[arg(long, default_value = "false")]
    panic_on_bug: bool,

    /// Detectors enabled (all, high_confidence, ...). See `src/evm/oracles/` for what each one checks.
    /// (Default: all -- was "high_confidence" until a real session confirmed this caused a user to
    /// read "no bug found" under the default as "no bug exists" on a target whose only real finding
    /// (UncheckedCall) is deliberately excluded from "high_confidence" for its false-positive rate.
    /// Silently narrowing the search by default is a worse failure mode than an occasional false
    /// positive with full detector coverage -- pass --detectors high_confidence explicitly for the
    /// old, noise-reduced behavior.)
    #[arg(long, short, default_value = "all")]
    detectors: String, // <- internally this is known as oracles

    /// Path to a JSON file declaring user-written invariants to check after
    /// every transaction (see `src/evm/oracles/invariant.rs` for the
    /// format). Lets a target's OWN economic promise be expressed without
    /// writing a new Rust oracle -- the gap that otherwise leaves any
    /// economic bug outside the built-in fingerprints unchecked.
    #[arg(long)]
    invariants: Option<String>,

    /// Derive wiring preconditions (`setX(address)` links between the
    /// deployed contracts) automatically instead of requiring a hand-written
    /// `setup.json`. Only wiring is derived; value-moving seeds (mint /
    /// deposit) are deliberately NOT guessed -- see
    /// `src/evm/auto_setup.rs`. An explicit `setup.json` (or `--setup-file`)
    /// still wins if present.
    #[arg(long)]
    auto_setup: bool,

    /// Path to a JSON file holding a serialized EVMState (as produced by a
    /// replay/dump) to compare against when the `state_comparison` detector
    /// is used. If not set, the state comparison oracle is not activated
    /// even if `state_comparison` is listed in --detectors.
    #[arg(long)]
    state_comp_file: Option<String>,

    /// Matching style for state comparison oracle (Select from "Exact",
    /// "DesiredContain", "StateContain")
    #[arg(long, default_value = "Exact")]
    state_comp_matching: String,

    /// Replay?
    #[arg(long, short)]
    replay_file: Option<String>,

    /// Path of work dir, saves corpus, logs, and other stuffs
    #[arg(long, short, default_value = "work_dir")]
    work_dir: String,

    /// Write contract relationship to files
    #[arg(long, default_value = "false")]
    write_relationship: bool,

    /// Do not quit when a bug is found, continue find new bugs
    #[arg(long, default_value = "false")]
    run_forever: bool,

    /// How deep into a call chain sha3-bypass taint analysis and
    /// concolic/symbolic Z3 solving keep analyzing (nested proxies,
    /// multi-level reentrancy, flashloan callback chains routinely go
    /// deeper than the old hardcoded value of 3). Higher costs more,
    /// especially for Z3 solving.
    #[arg(long, default_value = "32")]
    max_call_depth: u64,

    /// random seed
    #[arg(long, default_value = "1667840158231589000")]
    seed: u64,

    /// Number of parallel fuzzing jobs (multi-core). Each job is a fully
    /// isolated OS process with its own work dir and seed -- NOT in-process
    /// threads. ForkSploit's fuzzing state (`EVMFuzzState`) holds
    /// `Rc<RefCell<..>>` and the coverage/cmp maps are process-global
    /// `RacyCell`s (`unsafe impl Sync`), so in-process threads would race;
    /// process isolation is the only sound way to use more than one core.
    /// 1 (default) keeps the historical single-process behaviour.
    #[arg(long, default_value = "1")]
    jobs: usize,

    /// Wall-clock budget in seconds for the whole campaign. 0 (default)
    /// means unlimited, preserving the historical behaviour where an
    /// external supervisor (onchain_scripts/auto_pipeline.py) owns the
    /// time budget. Only meaningful together with --jobs > 1, where the
    /// parent process needs to bound and aggregate its workers.
    #[arg(long, default_value = "0")]
    fuzz_seconds: u64,

    /// Whether bypass all SHA3 comparisons, this may break original logic of
    /// contracts  (Experimental)
    #[arg(long, default_value = "false")]
    sha3_bypass: bool,

    /// Only fuzz contracts with the addresses provided, separated by comma
    #[arg(long, default_value = "")]
    only_fuzz: String,

    /// Only needed when using combined.json (source map info).
    /// This is the base path when running solc compile (--base-path passed to
    /// solc). Also, please convert it to absolute path if you are not sure.
    #[arg(long, default_value = "")]
    base_path: String,

    /// Spec ID.
    /// Frontier,Homestead,Tangerine,Spurious,Byzantium,Constantinople,
    /// Petersburg,Istanbul,MuirGlacier,Berlin,London,Merge,Shanghai,Cancun,
    /// Latest
    #[arg(long, default_value = "Latest")]
    spec_id: String,

    /// Builder URL. If specified, will use this builder to build contracts
    /// instead of using bins and abis.
    #[arg(long, default_value = "")]
    onchain_builder: String,

    /// Replacement config (replacing bytecode) for onchain campaign
    #[arg(long, default_value = "")]
    onchain_replacements_file: String,

    /// Builder Artifacts url. If specified, will use this artifact to derive
    /// code coverage.
    #[arg(long, default_value = "")]
    builder_artifacts_url: String,

    /// Builder Artifacts file. If specified, will use this artifact to derive
    /// code coverage.
    #[arg(long, default_value = "")]
    builder_artifacts_file: String,

    /// Offchain Config Url. If specified, will deploy based on offchain config
    /// file.
    #[arg(long, default_value = "")]
    offchain_config_url: String,

    /// Offchain Config File. If specified, will deploy based on offchain config
    /// file.
    #[arg(long, default_value = "")]
    offchain_config_file: String,

    /// Load corpus from directory. If not specified, will use empty corpus.
    #[arg(long, default_value = "")]
    load_corpus: String,

    /// [DEPRECATED alias of --deployment-script] Specify the setup file that
    /// deploys all the contracts. Fuzzer invokes setUp() to deploy. Still
    /// honoured if --deployment-script is not given; if both are given with
    /// different values, --deployment-script wins (a warning is printed).
    #[arg(long, default_value = "")]
    setup_file: String,

    /// Specify the deployment script contract that deploys all the contract.
    /// Fuzzer invokes constructor or setUp() of this script to deploy.
    /// For example, if you have contract X in file Y that deploys all the
    /// contracts, you can specify --deployment-script Y:X
    #[arg(long, short = 'm', default_value = "")]
    deployment_script: String,

    /// Forcing a contract to use the given abi. This is useful when the
    /// contract is a complex proxy or decompiler has trouble to detect the abi.
    /// Format: address:abi_file,...
    #[arg(long, default_value = "")]
    force_abi: String,

    /// Preset file. If specified, will load the preset file and match past
    /// exploit template.
    #[cfg(feature = "use_presets")]
    #[arg(long, default_value = "")]
    preset_file_path: String,

    #[arg(long, default_value = "")]
    base_directory: String,

    /// Command to build the contract. If specified, will use this command to
    /// build contracts instead of using bins and abis.
    #[arg()]
    build_command: Vec<String>,
}

impl fmt::Display for EvmArgs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EvmArgs {{\n")?;
        write!(f, "    target: {},\n", self.target)?;
        write!(f, "    fetch_tx_data: {},\n", self.fetch_tx_data)?;
        write!(f, "    proxy_address: {},\n", self.proxy_address)?;
        write!(f, "    constructor_args: {},\n", self.constructor_args)?;
        write!(f, "    target_type: {:?},\n", self.target_type)?;
        write!(f, "    chain_type: {:?},\n", self.chain_type)?;
        write!(f, "    onchain_block_number: {:?},\n", self.onchain_block_number)?;
        write!(f, "    onchain_url: {:?},\n", self.onchain_url)?;
        write!(f, "    onchain_chain_id: {:?},\n", self.onchain_chain_id)?;
        write!(f, "    onchain_explorer_url: {:?},\n", self.onchain_explorer_url)?;
        write!(f, "    onchain_chain_name: {:?},\n", self.onchain_chain_name)?;
        write!(
            f,
            "    onchain_etherscan_api_key: {:?},\n",
            self.onchain_etherscan_api_key
        )?;
        write!(f, "    onchain_storage_fetching: {},\n", self.onchain_storage_fetching)?;
        write!(f, "    concolic: {},\n", self.concolic)?;
        write!(f, "    concolic_caller: {},\n", self.concolic_caller)?;
        write!(f, "    concolic_timeout: {},\n", self.concolic_timeout)?;
        write!(f, "    concolic_memory_mb: {},\n", self.concolic_memory_mb)?;
        write!(f, "    concolic_num_threads: {},\n", self.concolic_num_threads)?;
        write!(f, "    flashloan: {},\n", self.flashloan)?;
        write!(f, "    panic_on_bug: {},\n", self.panic_on_bug)?;
        write!(f, "    detectors: {},\n", self.detectors)?;
        write!(f, "    invariants: {:?},\n", self.invariants)?;
        write!(f, "    auto_setup: {},\n", self.auto_setup)?;
        write!(f, "    replay_file: {:?},\n", self.replay_file)?;
        write!(f, "    work_dir: {},\n", self.work_dir)?;
        write!(f, "    write_relationship: {},\n", self.write_relationship)?;
        write!(f, "    run_forever: {},\n", self.run_forever)?;
        write!(f, "    max_call_depth: {},\n", self.max_call_depth)?;
        write!(f, "    seed: {},\n", self.seed)?;
        write!(f, "    sha3_bypass: {},\n", self.sha3_bypass)?;
        write!(f, "    only_fuzz: {},\n", self.only_fuzz)?;
        write!(f, "    base_path: {},\n", self.base_path)?;
        write!(f, "    spec_id: {},\n", self.spec_id)?;
        write!(f, "    onchain_builder: {},\n", self.onchain_builder)?;
        write!(
            f,
            "    onchain_replacements_file: {},\n",
            self.onchain_replacements_file
        )?;
        write!(f, "    builder_artifacts_url: {},\n", self.builder_artifacts_url)?;
        write!(f, "    builder_artifacts_file: {},\n", self.builder_artifacts_file)?;
        write!(f, "    offchain_config_url: {},\n", self.offchain_config_url)?;
        write!(f, "    offchain_config_file: {},\n", self.offchain_config_file)?;
        write!(f, "    load_corpus: {},\n", self.load_corpus)?;
        write!(f, "    setup_file: {},\n", self.setup_file)?;
        write!(f, "    deployment_script: {},\n", self.deployment_script)?;
        write!(f, "    force_abi: {},\n", self.force_abi)?;
        #[cfg(feature = "use_presets")]
        write!(f, "    preset_file_path: {},\n", self.preset_file_path)?;
        write!(f, "    base_directory: {},\n", self.base_directory)?;
        write!(f, "    build_command: {:?},\n", self.build_command)?;
        write!(f, "}}")
    }
}

enum EVMTargetType {
    Glob,
    Address,
    AnvilFork,
    Config,
    Setup,
}

impl EVMTargetType {
    #[allow(dead_code)] // kept as the inverse of from_str/from_strs
    fn as_str(&self) -> &'static str {
        match self {
            EVMTargetType::Glob => "glob",
            EVMTargetType::Address => "address",
            EVMTargetType::AnvilFork => "anvil_fork",
            EVMTargetType::Config => "config",
            EVMTargetType::Setup => "setup",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "glob" => EVMTargetType::Glob,
            "address" => EVMTargetType::Address,
            "anvil_fork" => EVMTargetType::AnvilFork,
            "config" => EVMTargetType::Config,
            "setup" => EVMTargetType::Setup,
            _ => panic!("Invalid target type"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OracleType {
    ERC20,
    Pair,
    Reentrancy,
    ArbitraryCall,
    MathCalculate,
    StateComparison,
    TypedBug,
    SelfDestruct,
    Erc4626,
    AccessControl,
    SignatureReplay,
    NftTransfer,
    ProxyIntegrity,
    ProxyUpgradeHijack,
    UnbackedMint,
    ForgedProof,
    TransientGuard,
    ArbTransfer,
    DelegatecallInjection,
    EcrecoverZero,
    ArbitraryStorageWrite,
    TokenAccountingMismatch,
    ForcedEthAccounting,
    ReadonlyReentrancy,
    StorageCollision,
    DelegatecallTarget,
    UninitializedMemory,
    UncheckedCall,
    TxOrigin,
    InitializerFrontRun,
    CentralizationRisk,
    SignatureMalleability,
    CurveVirtualPrice,
    PriceFeedStaleness,
    TwapManipulation,
    PreviewRounding,
    EthBacking,
    UnboundedLoop,
    StaleGuard,
    SelfReferral,
    ZeroAddressSetter,
    GasStipend,
    WeakRandomness,
    PrecisionLoss,
    RevertInLoop,
    AssertViolation,
    Invariant,
}

impl OracleType {
    #[allow(dead_code)] // kept as the inverse of from_str/from_strs
    fn as_str(&self) -> &'static str {
        match self {
            OracleType::ERC20 => "erc20",
            OracleType::Pair => "pair",
            OracleType::Reentrancy => "reentrancy",
            OracleType::ArbitraryCall => "arbitrary_call",
            OracleType::MathCalculate => "math_calculate",
            OracleType::StateComparison => "state_comparison",
            OracleType::TypedBug => "typed_bug",
            OracleType::SelfDestruct => "selfdestruct",
            OracleType::Erc4626 => "erc4626",
            OracleType::AccessControl => "access_control",
            OracleType::SignatureReplay => "signature_replay",
            OracleType::NftTransfer => "nft_transfer",
            OracleType::ProxyIntegrity => "proxy_integrity",
            OracleType::ProxyUpgradeHijack => "proxy_upgrade_hijack",
            OracleType::UnbackedMint => "unbacked_mint",
            OracleType::ForgedProof => "forged_proof",
            OracleType::TransientGuard => "transient_guard",
            OracleType::ArbTransfer => "arb_transfer",
            OracleType::DelegatecallInjection => "delegatecall_injection",
            OracleType::EcrecoverZero => "ecrecover_zero",
            OracleType::ArbitraryStorageWrite => "arbitrary_storage_write",
            OracleType::TokenAccountingMismatch => "token_accounting_mismatch",
            OracleType::ForcedEthAccounting => "forced_eth_accounting",
            OracleType::ReadonlyReentrancy => "readonly_reentrancy",
            OracleType::StorageCollision => "storage_collision",
            OracleType::DelegatecallTarget => "delegatecall_target",
            OracleType::UninitializedMemory => "uninitialized_memory",
            OracleType::UncheckedCall => "unchecked_call",
            OracleType::TxOrigin => "tx_origin",
            OracleType::InitializerFrontRun => "initializer_front_run",
            OracleType::CentralizationRisk => "centralization_risk",
            OracleType::SignatureMalleability => "signature_malleability",
            OracleType::CurveVirtualPrice => "curve_virtual_price",
            OracleType::PriceFeedStaleness => "price_feed_staleness",
            OracleType::TwapManipulation => "twap_manipulation",
            OracleType::PreviewRounding => "preview_rounding",
            OracleType::EthBacking => "eth_backing",
            OracleType::UnboundedLoop => "unbounded_loop",
            OracleType::StaleGuard => "stale_guard",
            OracleType::SelfReferral => "self_referral",
            OracleType::ZeroAddressSetter => "zero_address_setter",
            OracleType::GasStipend => "gas_stipend",
            OracleType::WeakRandomness => "weak_randomness",
            OracleType::PrecisionLoss => "precision_loss",
            OracleType::RevertInLoop => "revert_in_loop",
            OracleType::AssertViolation => "assert_violation",
            OracleType::Invariant => "invariant",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "erc20" => OracleType::ERC20,
            "pair" => OracleType::Pair,
            "reentrancy" => OracleType::Reentrancy,
            "arbitrary_call" => OracleType::ArbitraryCall,
            "math_calculate" => OracleType::MathCalculate,
            "state_comparison" => OracleType::StateComparison,
            "typed_bug" => OracleType::TypedBug,
            "selfdestruct" => OracleType::SelfDestruct,
            "erc4626" => OracleType::Erc4626,
            "access_control" => OracleType::AccessControl,
            "signature_replay" => OracleType::SignatureReplay,
            "nft_transfer" => OracleType::NftTransfer,
            "proxy_integrity" => OracleType::ProxyIntegrity,
            "proxy_upgrade_hijack" => OracleType::ProxyUpgradeHijack,
            "unbacked_mint" => OracleType::UnbackedMint,
            "forged_proof" => OracleType::ForgedProof,
            "transient_guard" => OracleType::TransientGuard,
            "arb_transfer" => OracleType::ArbTransfer,
            "delegatecall_injection" => OracleType::DelegatecallInjection,
            "ecrecover_zero" => OracleType::EcrecoverZero,
            "arbitrary_storage_write" => OracleType::ArbitraryStorageWrite,
            "token_accounting_mismatch" => OracleType::TokenAccountingMismatch,
            "forced_eth_accounting" => OracleType::ForcedEthAccounting,
            "readonly_reentrancy" => OracleType::ReadonlyReentrancy,
            "storage_collision" => OracleType::StorageCollision,
            "delegatecall_target" => OracleType::DelegatecallTarget,
            "uninitialized_memory" => OracleType::UninitializedMemory,
            "unchecked_call" => OracleType::UncheckedCall,
            "tx_origin" => OracleType::TxOrigin,
            "initializer_front_run" => OracleType::InitializerFrontRun,
            "centralization_risk" => OracleType::CentralizationRisk,
            "signature_malleability" => OracleType::SignatureMalleability,
            "curve_virtual_price" => OracleType::CurveVirtualPrice,
            "price_feed_staleness" => OracleType::PriceFeedStaleness,
            "twap_manipulation" => OracleType::TwapManipulation,
            "preview_rounding" => OracleType::PreviewRounding,
            "eth_backing" => OracleType::EthBacking,
            "unbounded_loop" => OracleType::UnboundedLoop,
            "stale_guard" => OracleType::StaleGuard,
            "self_referral" => OracleType::SelfReferral,
            "zero_address_setter" => OracleType::ZeroAddressSetter,
            "gas_stipend" => OracleType::GasStipend,
            "weak_randomness" => OracleType::WeakRandomness,
            "precision_loss" => OracleType::PrecisionLoss,
            "revert_in_loop" => OracleType::RevertInLoop,
            "assert_violation" => OracleType::AssertViolation,
            "invariant" => OracleType::Invariant,
            _ => panic!("Invalid detector type: {}", s),
        }
    }

    fn from_strs(s: &str) -> Vec<Self> {
        let mut results = Vec::new();

        for detector in s.split(',') {
            let detector = detector.trim();
            if detector.is_empty() {
                continue;
            }

            if detector == "all" {
                return vec![
                    OracleType::ERC20,
                    OracleType::Pair,
                    OracleType::Reentrancy,
                    OracleType::ArbitraryCall,
                    OracleType::MathCalculate,
                    OracleType::StateComparison,
                    OracleType::TypedBug,
                    OracleType::SelfDestruct,
                    OracleType::Erc4626,
                    OracleType::AccessControl,
                    OracleType::SignatureReplay,
                    OracleType::SignatureMalleability,
                    OracleType::NftTransfer,
                    OracleType::ProxyIntegrity,
                    OracleType::ProxyUpgradeHijack,
                    OracleType::UnbackedMint,
                    OracleType::ForgedProof,
                    OracleType::TransientGuard,
                    OracleType::ArbTransfer,
                    OracleType::DelegatecallInjection,
                    OracleType::EcrecoverZero,
                    OracleType::ArbitraryStorageWrite,
                    OracleType::TokenAccountingMismatch,
                    OracleType::ForcedEthAccounting,
                    OracleType::ReadonlyReentrancy,
                    OracleType::StorageCollision,
                    OracleType::DelegatecallTarget,
                    OracleType::UninitializedMemory,
                    OracleType::UncheckedCall,
                    OracleType::TxOrigin,
                    OracleType::InitializerFrontRun,
                    OracleType::CentralizationRisk,
                    OracleType::CurveVirtualPrice,
                    OracleType::PriceFeedStaleness,
                    OracleType::TwapManipulation,
                    OracleType::PreviewRounding,
                    OracleType::EthBacking,
                    OracleType::UnboundedLoop,
                    OracleType::StaleGuard,
                    OracleType::SelfReferral,
                    OracleType::ZeroAddressSetter,
                    OracleType::GasStipend,
                    OracleType::WeakRandomness,
                    OracleType::PrecisionLoss,
                    OracleType::RevertInLoop,
                    OracleType::AssertViolation,
                    OracleType::Invariant,
                ];
            }
            if detector == "high_confidence" {
                return vec![
                    OracleType::ERC20,
                    OracleType::Pair,
                    OracleType::Reentrancy,
                    OracleType::ArbitraryCall,
                    OracleType::TypedBug,
                    OracleType::SelfDestruct,
                    OracleType::Erc4626,
                    OracleType::AccessControl,
                    OracleType::SignatureReplay,
                    OracleType::SignatureMalleability,
                    OracleType::NftTransfer,
                    OracleType::ProxyIntegrity,
                    OracleType::ProxyUpgradeHijack,
                    OracleType::ArbTransfer,
                    OracleType::DelegatecallInjection,
                    OracleType::EcrecoverZero,
                    OracleType::ArbitraryStorageWrite,
                    OracleType::StorageCollision,
                    OracleType::DelegatecallTarget,
                    OracleType::TxOrigin,
                    OracleType::InitializerFrontRun,
                    OracleType::PreviewRounding,
                    OracleType::EthBacking,
                    // Promoted here (was Review-only): unlike a single-shot
                    // heuristic guess, this oracle only reports after
                    // empirically observing BOTH outcomes of the same
                    // guard -- jumped AND fell-through -- each with a
                    // confirmed payment to the same argument, across
                    // separately fuzzed calls. That two-sided requirement
                    // is as rigorous as this project's other Confirmed
                    // oracles, not a maybe-false-positive inference (see
                    // oracles/self_referral.rs's own doc comment).
                    OracleType::SelfReferral,
                ];
            }

            results.push(OracleType::from_str(detector));
        }
        results
    }
}

#[allow(clippy::type_complexity)]
/// `SpecId::from(&str)` (revm) is case-sensitive and silently falls back to
/// `SpecId::LATEST` on anything it doesn't recognize -- a typo or wrong
/// case (e.g. "shanghai" instead of "Shanghai") produces no error, just a
/// silently different ruleset than the one asked for. Warn loudly here
/// instead, since --spec-id is otherwise unchecked all the way down.
fn validate_spec_id(spec_id: &str) {
    const KNOWN: &[&str] = &[
        "Frontier",
        "Homestead",
        "Tangerine",
        "Spurious",
        "Byzantium",
        "Constantinople",
        "Petersburg",
        "Istanbul",
        "MuirGlacier",
        "Berlin",
        "London",
        "Merge",
        "Shanghai",
        "Cancun",
        "Latest",
    ];
    if !KNOWN.contains(&spec_id) {
        warn!(
            "--spec-id '{}' is not a recognized SpecId name (expected one of {:?}, exact \
             case). It will silently fall back to SpecId::LATEST rather than error -- this is \
             almost certainly not what you want.",
            spec_id, KNOWN
        );
    }
}

pub fn evm_main(mut args: EvmArgs) {
    // FAZA 6.2: multi-core dispatch. When more than one job is requested,
    // this process becomes a supervisor that launches isolated worker
    // processes and never touches the fuzzing state itself (see
    // `evm::multicore` for why threads are unsound here).
    if args.jobs > 1 {
        // Belt-and-braces against fork-bombing: a worker always sets
        // FORKSPLOIT_JOB=1, so even if the `--jobs 1` override were lost a
        // worker can never re-enter supervisor mode.
        if std::env::var_os("FORKSPLOIT_JOB").is_some() {
            warn!("FORKSPLOIT_JOB is set; forcing --jobs 1 (worker mode)");
            args.jobs = 1;
        } else {
            let code = multicore::run_supervisor(
                args.jobs,
                args.fuzz_seconds,
                Path::new(args.work_dir.as_str()),
                args.seed,
            );
            std::process::exit(code);
        }
    }

    validate_spec_id(&args.spec_id);
    // Collapse the two deployment-script flags without silently dropping an
    // explicitly passed `--setup-file` (see resolve_setup_file).
    let (setup_file, setup_file_conflict) = resolve_setup_file(&args.setup_file, &args.deployment_script);
    if setup_file_conflict {
        warn!(
            "both --setup-file ({}) and --deployment-script ({}) were given with different values; \
             using --deployment-script (the current spelling). Drop one to silence this.",
            args.setup_file, args.deployment_script
        );
    }
    args.setup_file = setup_file;
    let target = args.target.clone();
    if !args.base_directory.is_empty() {
        std::env::set_current_dir(args.base_directory).unwrap();
    }

    let work_dir = args.work_dir.clone();
    let work_path = Path::new(work_dir.as_str());
    let _ = std::fs::create_dir_all(work_path);

    let mut target_type: EVMTargetType = match args.target_type {
        Some(v) => EVMTargetType::from_str(v.as_str()),
        None => {
            // infer target type from args
            if args.target.starts_with("0x") {
                EVMTargetType::Address
            } else {
                EVMTargetType::Glob
            }
        }
    };

    let is_onchain = args.chain_type.is_some() || args.onchain_url.is_some();

    let mut onchain = if is_onchain {
        match args.chain_type {
            Some(chain_str) => {
                let chain = Chain::from_str(&chain_str).expect("Invalid chain type");
                let block_number = args.onchain_block_number.unwrap_or(0);
                // `--onchain-url` is otherwise silently ignored whenever `--chain-type`
                // is also given, even though the help text says it overrides the
                // chain-type default. `Chain::get_chain_rpc()` already honors
                // ETH_RPC_URL, so set it here to make the override actually work.
                if let Some(url) = &args.onchain_url {
                    unsafe {
                        std::env::set_var("ETH_RPC_URL", url);
                    }
                }
                Some(OnChainConfig::new(chain, block_number))
            }
            None => Some(OnChainConfig::new_raw(
                args.onchain_url
                    .expect("You need to either specify chain type or chain rpc"),
                args.onchain_chain_id
                    .expect("You need to either specify chain type or chain id"),
                args.onchain_block_number.unwrap_or(0),
                args.onchain_explorer_url
                    .expect("You need to either specify chain type or block explorer url"),
                args.onchain_chain_name
                    .expect("You need to either specify chain type or chain name"),
            )),
        }
    } else {
        None
    };

    solution::init_cli_args(target, work_dir, &onchain);
    let _onchain_clone = onchain.clone();

    let etherscan_api_key = match args.onchain_etherscan_api_key {
        Some(v) => v,
        None => std::env::var("ETHERSCAN_API_KEY").unwrap_or_default(),
    };

    if onchain.is_some() && !etherscan_api_key.is_empty() {
        onchain.as_mut().unwrap().etherscan_api_key = etherscan_api_key.split(',').map(|s| s.to_string()).collect();
    }
    let erc20_producer = Rc::new(RefCell::new(ERC20Producer::new()));

    let flashloan_oracle = Rc::new(RefCell::new(IERC20OracleFlashloan::new(erc20_producer.clone())));

    // let harness_code = "oracle_harness()";
    // let mut harness_hash: [u8; 4] = [0; 4];
    // set_hash(harness_code, &mut harness_hash);
    // let mut function_oracle =
    //     FunctionHarnessOracle::new_no_condition(EVMAddress::zero(),
    // Vec::from(harness_hash));

    let mut oracles: Vec<
        Rc<
            RefCell<
                dyn Oracle<
                    EVMState,
                    revm_primitives::B160,
                    revm_primitives::Bytecode,
                    bytes::Bytes,
                    revm_primitives::B160,
                    revm_primitives::ruint::Uint<256, 4>,
                    Vec<u8>,
                    EVMInput,
                    FuzzState<
                        EVMInput,
                        EVMState,
                        revm_primitives::B160,
                        revm_primitives::B160,
                        Vec<u8>,
                        ConciseEVMInput,
                    >,
                    ConciseEVMInput,
                    EVMQueueExecutor,
                >,
            >,
        >,
    > = vec![];

    let mut producers: Vec<
        Rc<
            RefCell<
                dyn Producer<
                    EVMState,
                    EVMAddress,
                    _,
                    _,
                    EVMAddress,
                    EVMU256,
                    Vec<u8>,
                    EVMInput,
                    EVMFuzzState,
                    ConciseEVMInput,
                    EVMQueueExecutor,
                >,
            >,
        >,
    > = vec![];

    let oracle_types = OracleType::from_strs(args.detectors.as_str());

    if oracle_types.contains(&OracleType::Pair) {
        oracles.push(Rc::new(RefCell::new(PairBalanceOracle::new())));
    }

    if oracle_types.contains(&OracleType::Erc4626) {
        oracles.push(Rc::new(RefCell::new(Erc4626ShareInflationOracle::new())));
    }

    if oracle_types.contains(&OracleType::AccessControl) {
        oracles.push(Rc::new(RefCell::new(AccessControlOracle::new())));
    }

    if oracle_types.contains(&OracleType::SignatureReplay) {
        oracles.push(Rc::new(RefCell::new(SignatureReplayOracle::new())));
    }

    if oracle_types.contains(&OracleType::SignatureMalleability) {
        oracles.push(Rc::new(RefCell::new(SignatureMalleabilityOracle::new())));
    }

    if oracle_types.contains(&OracleType::NftTransfer) {
        oracles.push(Rc::new(RefCell::new(NftTransferOracle::new())));
    }

    if oracle_types.contains(&OracleType::ProxyIntegrity) {
        oracles.push(Rc::new(RefCell::new(ProxyIntegrityOracle::new())));
    }
    if oracle_types.contains(&OracleType::ProxyUpgradeHijack) {
        oracles.push(Rc::new(RefCell::new(ProxyUpgradeHijackOracle::new())));
    }
    if oracle_types.contains(&OracleType::UnbackedMint) {
        oracles.push(Rc::new(RefCell::new(UnbackedMintOracle::new())));
    }
    if oracle_types.contains(&OracleType::ForgedProof) {
        oracles.push(Rc::new(RefCell::new(ForgedProofOracle::new())));
    }
    if oracle_types.contains(&OracleType::TransientGuard) {
        oracles.push(Rc::new(RefCell::new(TransientGuardOracle::new())));
    }

    if oracle_types.contains(&OracleType::InitializerFrontRun) {
        oracles.push(Rc::new(RefCell::new(InitializerFrontRunOracle::new())));
    }

    if oracle_types.contains(&OracleType::CentralizationRisk) {
        oracles.push(Rc::new(RefCell::new(CentralizationRiskOracle::new())));
    }

    if oracle_types.contains(&OracleType::CurveVirtualPrice) {
        oracles.push(Rc::new(RefCell::new(CurveVirtualPriceOracle::new())));
    }

    if oracle_types.contains(&OracleType::PriceFeedStaleness) {
        oracles.push(Rc::new(RefCell::new(PriceFeedStalenessOracle::new())));
    }

    if oracle_types.contains(&OracleType::TwapManipulation) {
        oracles.push(Rc::new(RefCell::new(TwapManipulationOracle::new())));
    }

    if oracle_types.contains(&OracleType::PreviewRounding) {
        oracles.push(Rc::new(RefCell::new(PreviewRoundingOracle::new())));
    }

    if oracle_types.contains(&OracleType::EthBacking) {
        oracles.push(Rc::new(RefCell::new(EthBackingOracle::new())));
    }

    if oracle_types.contains(&OracleType::ArbTransfer) {
        oracles.push(Rc::new(RefCell::new(ArbitraryERC20TransferOracle::new())));
    }

    if oracle_types.contains(&OracleType::ZeroAddressSetter) {
        oracles.push(Rc::new(RefCell::new(ZeroAddressSetterOracle::new())));
    }

    if oracle_types.contains(&OracleType::GasStipend) {
        oracles.push(Rc::new(RefCell::new(GasStipendOracle::new())));
    }

    if oracle_types.contains(&OracleType::WeakRandomness) {
        oracles.push(Rc::new(RefCell::new(WeakRandomnessOracle::new())));
    }

    if oracle_types.contains(&OracleType::PrecisionLoss) {
        oracles.push(Rc::new(RefCell::new(PrecisionLossOracle::new())));
    }

    if oracle_types.contains(&OracleType::RevertInLoop) {
        oracles.push(Rc::new(RefCell::new(RevertInLoopOracle::new())));
    }

    if oracle_types.contains(&OracleType::AssertViolation) {
        oracles.push(Rc::new(RefCell::new(AssertViolationOracle::new())));
    }

    // The declarative invariant oracle only exists when the user actually
    // supplied an invariant file -- there is nothing to evaluate otherwise.
    // A file that fails to parse is a hard, visible error (not a silent
    // no-op), because silently dropping the user's own invariants would
    // read as "no violation found" when in truth nothing was ever checked.
    if let Some(path) = args.invariants.clone() {
        match crate::evm::oracles::invariant::InvariantSpec::from_file(&path) {
            Some(spec) if !spec.is_empty() => {
                tracing::info!(
                    "Loaded {} user-declared invariant(s) from {}",
                    spec.invariants.len(),
                    path
                );
                oracles.push(Rc::new(RefCell::new(
                    crate::evm::oracles::invariant::InvariantOracle::new(spec),
                )));
            }
            Some(_) => {
                tracing::warn!("Invariants file {} contains no invariants -- nothing to check", path);
            }
            None => {
                tracing::error!(
                    "Failed to load invariants file {} -- NO user invariants will be checked",
                    path
                );
            }
        }
    }

    if oracle_types.contains(&OracleType::ERC20) {
        oracles.push(flashloan_oracle.clone());
        producers.push(erc20_producer);
    }

    let is_onchain = onchain.is_some();
    let mut state: EVMFuzzState = FuzzState::new(args.seed);

    let mut proxy_deploy_codes: Vec<String> = vec![];

    if args.fetch_tx_data {
        let response = reqwest::blocking::get(args.proxy_address).unwrap().text().unwrap();
        let data: Vec<Data> = serde_json::from_str(&response).unwrap();

        for d in data {
            if d.body.method != "eth_sendRawTransaction" {
                continue;
            }

            let tx = d.body.params.unwrap();

            let params: Vec<String> = serde_json::from_value(tx).unwrap();

            let data = params[0].clone();

            let data = if let Some(stripped) = data.strip_prefix("0x") {
                stripped
            } else {
                &data
            };

            let bytes_data = hex::decode(data).unwrap();

            let transaction: Transaction = rlp::decode(&bytes_data).unwrap();

            let code = hex::encode(transaction.input);

            proxy_deploy_codes.push(code);
        }
    }

    let constructor_args_map = parse_constructor_args_string(args.constructor_args);

    let onchain_replacements = if !args.onchain_replacements_file.is_empty() {
        BuildJobResult::from_multi_file(args.onchain_replacements_file)
    } else {
        HashMap::new()
    };

    let builder = if args.onchain_builder.len() > 1 {
        Some(BuildJob::new(
            args.onchain_builder,
            onchain_replacements,
            args.work_dir.clone(),
        ))
    } else {
        None
    };

    if !args.builder_artifacts_url.is_empty() || !args.builder_artifacts_file.is_empty() || args.build_command.len() > 0
    {
        if onchain.is_some() {
            target_type = EVMTargetType::AnvilFork;
        } else if !args.setup_file.is_empty() {
            target_type = EVMTargetType::Setup;
        } else if !args.offchain_config_url.is_empty() || !args.offchain_config_file.is_empty() {
            target_type = EVMTargetType::Config;
        } else {
            panic!("Please specify --deployment-script (The contract that deploys the project) or --offchain-config-file (JSON for deploying the project)");
        }
    }

    let offchain_artifacts = if !args.builder_artifacts_url.is_empty() {
        Some(OffChainArtifact::from_json_url(args.builder_artifacts_url).expect("failed to parse builder artifacts"))
    } else if !args.builder_artifacts_file.is_empty() {
        Some(OffChainArtifact::from_file(args.builder_artifacts_file).expect("failed to parse builder artifacts"))
    } else if args.build_command.len() > 0 {
        let command = args.build_command.join(" ");
        Some(OffChainArtifact::from_command(command).expect("Failed to build the project"))
    } else {
        None
    };

    let offchain_config = if !args.offchain_config_url.is_empty() {
        Some(OffchainConfig::from_json_url(args.offchain_config_url).expect("failed to parse offchain config"))
    } else if !args.offchain_config_file.is_empty() {
        Some(OffchainConfig::from_file(args.offchain_config_file).expect("failed to parse offchain config"))
    } else {
        None
    };

    let force_abis = args
        .force_abi
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|x| {
            let runes = x.split(':').collect_vec();
            assert_eq!(runes.len(), 2, "Invalid force abi format");
            let abi = std::fs::read_to_string(runes[1]).expect("Failed to read abi file");
            (runes[0].to_string(), abi)
        })
        .collect::<HashMap<_, _>>();

    let mut contract_loader = match target_type {
        EVMTargetType::Glob => ContractLoader::from_glob(
            args.target.as_str(),
            &mut state,
            &proxy_deploy_codes,
            &constructor_args_map,
            args.target.clone(),
            Some(args.base_path.clone()),
        ),
        EVMTargetType::Config => ContractLoader::from_config(
            &offchain_artifacts.expect("offchain artifacts is required for config target type"),
            &offchain_config.expect("offchain config is required for config target type"),
        ),
        EVMTargetType::AnvilFork => {
            let addresses: Vec<EVMAddress> = args
                .target
                .split(',')
                .map(|s| {
                    EVMAddress::from_str(s).unwrap_or_else(|e| {
                        error!("'{s}' is not a valid address (--target): {e}");
                        std::process::exit(1);
                    })
                })
                .collect();
            ContractLoader::from_fork(
                &offchain_artifacts.expect("offchain artifacts is required for config target type"),
                onchain.as_mut().expect("onchain is required to fork anvil"),
                HashSet::from_iter(addresses),
            )
        }
        EVMTargetType::Setup => ContractLoader::from_setup(
            &offchain_artifacts.expect("offchain artifacts is required for config target type"),
            args.setup_file,
            args.work_dir.clone(),
            &etherscan_api_key,
        ),
        EVMTargetType::Address => {
            if onchain.is_none() {
                panic!("Onchain is required for address target type");
            }
            let args_target = args.target.clone();

            // Confirmed live 2026-11-01: a malformed address here (e.g. a
            // one-character-short typo pasted into --target) used to
            // panic with a raw Rust backtrace instead of a clear "fix
            // your input" message -- an easy, realistic user mistake that
            // shouldn't crash the whole process.
            let addresses: Vec<EVMAddress> = args_target
                .split(',')
                .map(|s| {
                    EVMAddress::from_str(s).unwrap_or_else(|e| {
                        error!("'{s}' is not a valid address (--target): {e}");
                        std::process::exit(1);
                    })
                })
                .collect();
            ContractLoader::from_address(
                onchain.as_mut().unwrap(),
                HashSet::from_iter(addresses),
                builder.clone(),
            )
        }
    };

    contract_loader.force_abi(force_abis);

    // `--auto-setup`: derive wiring preconditions when no explicit setup was
    // supplied. An explicit `setup.json` (loaded by `from_glob`/`from_setup`)
    // always wins -- we only fill the gap, never override a user's own spec.
    if args.auto_setup {
        match &contract_loader.setup_spec {
            Some(existing) if !existing.is_empty() => {
                tracing::info!(
                    "--auto-setup: an explicit setup ({} call(s)) is already present; keeping it",
                    existing.calls.len()
                );
            }
            _ => {
                let derived = crate::evm::auto_setup::derive_setup_spec(&contract_loader.contracts);
                if derived.is_empty() {
                    tracing::info!(
                        "--auto-setup: no `setX(address)` wiring between the deployed contracts was derivable"
                    );
                } else {
                    tracing::info!(
                        "--auto-setup: derived {} wiring call(s): {}",
                        derived.calls.len(),
                        derived
                            .calls
                            .iter()
                            .map(|c| format!("{}.{}", c.to, c.sig))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    contract_loader.setup_spec = Some(derived);
                }
            }
        }
    }

    let config = Config {
        contract_loader,
        only_fuzz: if !args.only_fuzz.is_empty() {
            args.only_fuzz
                .split(',')
                .map(|s| {
                    EVMAddress::from_str(s).unwrap_or_else(|e| {
                        error!("'{s}' is not a valid address (--only-fuzz): {e}");
                        std::process::exit(1);
                    })
                })
                .collect()
        } else {
            HashSet::new()
        },
        onchain,
        concolic: args.concolic,
        concolic_caller: args.concolic_caller,
        concolic_timeout: args.concolic_timeout,
        concolic_memory_mb: args.concolic_memory_mb,
        concolic_num_threads: resolve_concolic_num_threads(args.concolic_num_threads),
        oracle: oracles,
        producers,
        flashloan: args.flashloan,
        onchain_storage_fetching: if is_onchain {
            Some(
                StorageFetchingMode::from_str(args.onchain_storage_fetching.as_str())
                    .expect("unknown storage fetching mode"),
            )
        } else {
            None
        },
        replay_file: args.replay_file,
        flashloan_oracle,
        selfdestruct_oracle: oracle_types.contains(&OracleType::SelfDestruct),
        reentrancy_oracle: oracle_types.contains(&OracleType::Reentrancy),
        state_comp_oracle: args.state_comp_file.clone(),
        state_comp_matching: Some(args.state_comp_matching.clone()),
        work_dir: args.work_dir.clone(),
        write_relationship: args.write_relationship,
        run_forever: args.run_forever,
        max_call_depth: args.max_call_depth,
        sha3_bypass: args.sha3_bypass,
        base_path: args.base_path,
        panic_on_bug: args.panic_on_bug,
        spec_id: args.spec_id,
        typed_bug: oracle_types.contains(&OracleType::TypedBug),
        arbitrary_external_call: oracle_types.contains(&OracleType::ArbitraryCall),
        math_calculate_oracle: oracle_types.contains(&OracleType::MathCalculate),
        delegatecall_injection_oracle: oracle_types.contains(&OracleType::DelegatecallInjection),
        ecrecover_zero_oracle: oracle_types.contains(&OracleType::EcrecoverZero),
        arbitrary_storage_write_oracle: oracle_types.contains(&OracleType::ArbitraryStorageWrite),
        token_accounting_mismatch_oracle: oracle_types.contains(&OracleType::TokenAccountingMismatch),
        forced_eth_accounting_oracle: oracle_types.contains(&OracleType::ForcedEthAccounting),
        readonly_reentrancy_oracle: oracle_types.contains(&OracleType::ReadonlyReentrancy),
        storage_collision_oracle: oracle_types.contains(&OracleType::StorageCollision),
        delegatecall_target_oracle: oracle_types.contains(&OracleType::DelegatecallTarget),
        uninitialized_memory_oracle: oracle_types.contains(&OracleType::UninitializedMemory),
        unchecked_call_oracle: oracle_types.contains(&OracleType::UncheckedCall),
        unbounded_loop_oracle: oracle_types.contains(&OracleType::UnboundedLoop),
        stale_guard_oracle: oracle_types.contains(&OracleType::StaleGuard),
        self_referral_oracle: oracle_types.contains(&OracleType::SelfReferral),
        zero_address_setter_oracle: oracle_types.contains(&OracleType::ZeroAddressSetter),
        gas_stipend_oracle: oracle_types.contains(&OracleType::GasStipend),
        weak_randomness_oracle: oracle_types.contains(&OracleType::WeakRandomness),
        precision_loss_oracle: oracle_types.contains(&OracleType::PrecisionLoss),
        revert_in_loop_oracle: oracle_types.contains(&OracleType::RevertInLoop),
        assert_violation_oracle: oracle_types.contains(&OracleType::AssertViolation),
        tx_origin_oracle: oracle_types.contains(&OracleType::TxOrigin),
        builder,
        local_files_basedir_pattern: match target_type {
            EVMTargetType::Glob => Some(args.target),
            _ => None,
        },
        #[cfg(feature = "use_presets")]
        preset_file_path: args.preset_file_path,
        load_corpus: args.load_corpus,
        etherscan_api_key,
    };

    let mut abis_map: HashMap<String, Vec<Vec<serde_json::Value>>> = HashMap::new();

    for contract_info in config.contract_loader.contracts.clone() {
        let abis: Vec<serde_json::Value> = contract_info
            .abi
            .iter()
            .map(|config| {
                json!({
                    hex::encode(config.function): format!("{}{}", &config.function_name, &config.abi)
                })
            })
            .collect();
        abis_map
            .entry(hex::encode(contract_info.deployed_address))
            .or_default()
            .push(abis);
    }

    let json_str = serde_json::to_string(&abis_map).expect("Failed to serialize ABI map to JSON");

    let abis_json = format!("{}/abis.json", args.work_dir.clone().as_str());

    utils::try_write_file(&abis_json, &json_str, true).unwrap();
    evm_fuzzer(config, &mut state)
}

// #[test]
#[allow(dead_code)] // manual harness, run by uncommenting #[test]
fn test_evm_offchain_setup() {
    let mut args = EvmArgs {
        proxy_address: String::from("http://localhost:5001/data"),
        onchain_storage_fetching: String::from("onebyone"),
        concolic_timeout: 1000,
        detectors: String::from("all"),
        work_dir: String::from("work_dir"),
        seed: 1667840158231589000,
        spec_id: String::from("Latest"),
        // deployment_script: String::from("test/foundry/invariants/BaseInvariant.t.sol:BaseInvariant"),
        deployment_script: String::from("CounterLibByLibTest"),
        build_command: vec![String::from("forge"), String::from("build")],
        ..Default::default()
    };

    args.setup_file = resolve_setup_file(&args.setup_file, &args.deployment_script).0;
    if !args.base_directory.is_empty() {
        std::env::set_current_dir(args.base_directory).unwrap();
    }

    let work_dir = args.work_dir.clone();
    let work_path = Path::new(work_dir.as_str());
    let _ = std::fs::create_dir_all(work_path);

    let target_type: EVMTargetType = EVMTargetType::Setup;

    let erc20_producer = Rc::new(RefCell::new(ERC20Producer::new()));

    let flashloan_oracle = Rc::new(RefCell::new(IERC20OracleFlashloan::new(erc20_producer.clone())));

    let mut oracles: Vec<
        Rc<
            RefCell<
                dyn Oracle<
                    EVMState,
                    B160,
                    revm_primitives::Bytecode,
                    bytes::Bytes,
                    B160,
                    revm_primitives::ruint::Uint<256, 4>,
                    Vec<u8>,
                    EVMInput,
                    FuzzState<EVMInput, EVMState, B160, B160, Vec<u8>, ConciseEVMInput>,
                    ConciseEVMInput,
                    EVMQueueExecutor,
                >,
            >,
        >,
    > = vec![];

    let mut producers: Vec<
        Rc<
            RefCell<
                dyn Producer<
                    EVMState,
                    EVMAddress,
                    _,
                    _,
                    EVMAddress,
                    EVMU256,
                    Vec<u8>,
                    EVMInput,
                    EVMFuzzState,
                    ConciseEVMInput,
                    EVMQueueExecutor,
                >,
            >,
        >,
    > = vec![];

    let oracle_types = OracleType::from_strs(args.detectors.as_str());

    if oracle_types.contains(&OracleType::Pair) {
        oracles.push(Rc::new(RefCell::new(PairBalanceOracle::new())));
    }

    if oracle_types.contains(&OracleType::Erc4626) {
        oracles.push(Rc::new(RefCell::new(Erc4626ShareInflationOracle::new())));
    }

    if oracle_types.contains(&OracleType::AccessControl) {
        oracles.push(Rc::new(RefCell::new(AccessControlOracle::new())));
    }

    if oracle_types.contains(&OracleType::SignatureReplay) {
        oracles.push(Rc::new(RefCell::new(SignatureReplayOracle::new())));
    }

    if oracle_types.contains(&OracleType::SignatureMalleability) {
        oracles.push(Rc::new(RefCell::new(SignatureMalleabilityOracle::new())));
    }

    if oracle_types.contains(&OracleType::NftTransfer) {
        oracles.push(Rc::new(RefCell::new(NftTransferOracle::new())));
    }

    if oracle_types.contains(&OracleType::ProxyIntegrity) {
        oracles.push(Rc::new(RefCell::new(ProxyIntegrityOracle::new())));
    }
    if oracle_types.contains(&OracleType::ProxyUpgradeHijack) {
        oracles.push(Rc::new(RefCell::new(ProxyUpgradeHijackOracle::new())));
    }
    if oracle_types.contains(&OracleType::UnbackedMint) {
        oracles.push(Rc::new(RefCell::new(UnbackedMintOracle::new())));
    }
    if oracle_types.contains(&OracleType::ForgedProof) {
        oracles.push(Rc::new(RefCell::new(ForgedProofOracle::new())));
    }
    if oracle_types.contains(&OracleType::TransientGuard) {
        oracles.push(Rc::new(RefCell::new(TransientGuardOracle::new())));
    }

    if oracle_types.contains(&OracleType::InitializerFrontRun) {
        oracles.push(Rc::new(RefCell::new(InitializerFrontRunOracle::new())));
    }

    if oracle_types.contains(&OracleType::CentralizationRisk) {
        oracles.push(Rc::new(RefCell::new(CentralizationRiskOracle::new())));
    }

    if oracle_types.contains(&OracleType::CurveVirtualPrice) {
        oracles.push(Rc::new(RefCell::new(CurveVirtualPriceOracle::new())));
    }

    if oracle_types.contains(&OracleType::PriceFeedStaleness) {
        oracles.push(Rc::new(RefCell::new(PriceFeedStalenessOracle::new())));
    }

    if oracle_types.contains(&OracleType::TwapManipulation) {
        oracles.push(Rc::new(RefCell::new(TwapManipulationOracle::new())));
    }

    if oracle_types.contains(&OracleType::PreviewRounding) {
        oracles.push(Rc::new(RefCell::new(PreviewRoundingOracle::new())));
    }

    if oracle_types.contains(&OracleType::EthBacking) {
        oracles.push(Rc::new(RefCell::new(EthBackingOracle::new())));
    }

    if oracle_types.contains(&OracleType::ArbTransfer) {
        oracles.push(Rc::new(RefCell::new(ArbitraryERC20TransferOracle::new())));
    }

    if oracle_types.contains(&OracleType::ZeroAddressSetter) {
        oracles.push(Rc::new(RefCell::new(ZeroAddressSetterOracle::new())));
    }

    if oracle_types.contains(&OracleType::GasStipend) {
        oracles.push(Rc::new(RefCell::new(GasStipendOracle::new())));
    }

    if oracle_types.contains(&OracleType::WeakRandomness) {
        oracles.push(Rc::new(RefCell::new(WeakRandomnessOracle::new())));
    }

    if oracle_types.contains(&OracleType::PrecisionLoss) {
        oracles.push(Rc::new(RefCell::new(PrecisionLossOracle::new())));
    }

    if oracle_types.contains(&OracleType::RevertInLoop) {
        oracles.push(Rc::new(RefCell::new(RevertInLoopOracle::new())));
    }

    if oracle_types.contains(&OracleType::AssertViolation) {
        oracles.push(Rc::new(RefCell::new(AssertViolationOracle::new())));
    }

    if oracle_types.contains(&OracleType::ERC20) {
        oracles.push(flashloan_oracle.clone());
        producers.push(erc20_producer);
    }

    let mut state: EVMFuzzState = FuzzState::new(args.seed);

    let builder = None;

    let offchain_artifacts = if !args.builder_artifacts_url.is_empty() {
        Some(OffChainArtifact::from_json_url(args.builder_artifacts_url).expect("failed to parse builder artifacts"))
    } else if !args.builder_artifacts_file.is_empty() {
        Some(OffChainArtifact::from_file(args.builder_artifacts_file).expect("failed to parse builder artifacts"))
    } else if args.build_command.len() > 0 {
        let command = args.build_command.join(" ");
        Some(OffChainArtifact::from_command(command).expect("Failed to build the project"))
    } else {
        None
    };

    let contract_loader = ContractLoader::from_setup(
        &offchain_artifacts.expect("offchain artifacts is required for config target type"),
        args.setup_file,
        args.work_dir.clone(),
        "",
    );

    let config = Config {
        contract_loader,
        only_fuzz: HashSet::new(),
        onchain: None,
        concolic: args.concolic,
        concolic_caller: args.concolic_caller,
        concolic_timeout: args.concolic_timeout,
        concolic_memory_mb: args.concolic_memory_mb,
        concolic_num_threads: resolve_concolic_num_threads(args.concolic_num_threads),
        oracle: oracles,
        producers,
        flashloan: args.flashloan,
        onchain_storage_fetching: None,
        replay_file: args.replay_file,
        flashloan_oracle,
        selfdestruct_oracle: oracle_types.contains(&OracleType::SelfDestruct),
        reentrancy_oracle: oracle_types.contains(&OracleType::Reentrancy),
        state_comp_oracle: args.state_comp_file.clone(),
        state_comp_matching: Some(args.state_comp_matching.clone()),
        work_dir: args.work_dir.clone(),
        write_relationship: args.write_relationship,
        run_forever: args.run_forever,
        max_call_depth: args.max_call_depth,
        sha3_bypass: args.sha3_bypass,
        base_path: args.base_path,
        panic_on_bug: args.panic_on_bug,
        spec_id: args.spec_id,
        typed_bug: oracle_types.contains(&OracleType::TypedBug),
        arbitrary_external_call: oracle_types.contains(&OracleType::ArbitraryCall),
        math_calculate_oracle: oracle_types.contains(&OracleType::MathCalculate),
        delegatecall_injection_oracle: oracle_types.contains(&OracleType::DelegatecallInjection),
        ecrecover_zero_oracle: oracle_types.contains(&OracleType::EcrecoverZero),
        arbitrary_storage_write_oracle: oracle_types.contains(&OracleType::ArbitraryStorageWrite),
        token_accounting_mismatch_oracle: oracle_types.contains(&OracleType::TokenAccountingMismatch),
        forced_eth_accounting_oracle: oracle_types.contains(&OracleType::ForcedEthAccounting),
        readonly_reentrancy_oracle: oracle_types.contains(&OracleType::ReadonlyReentrancy),
        storage_collision_oracle: oracle_types.contains(&OracleType::StorageCollision),
        delegatecall_target_oracle: oracle_types.contains(&OracleType::DelegatecallTarget),
        uninitialized_memory_oracle: oracle_types.contains(&OracleType::UninitializedMemory),
        unchecked_call_oracle: oracle_types.contains(&OracleType::UncheckedCall),
        unbounded_loop_oracle: oracle_types.contains(&OracleType::UnboundedLoop),
        stale_guard_oracle: oracle_types.contains(&OracleType::StaleGuard),
        self_referral_oracle: oracle_types.contains(&OracleType::SelfReferral),
        zero_address_setter_oracle: oracle_types.contains(&OracleType::ZeroAddressSetter),
        gas_stipend_oracle: oracle_types.contains(&OracleType::GasStipend),
        weak_randomness_oracle: oracle_types.contains(&OracleType::WeakRandomness),
        precision_loss_oracle: oracle_types.contains(&OracleType::PrecisionLoss),
        revert_in_loop_oracle: oracle_types.contains(&OracleType::RevertInLoop),
        assert_violation_oracle: oracle_types.contains(&OracleType::AssertViolation),
        tx_origin_oracle: oracle_types.contains(&OracleType::TxOrigin),
        builder,
        local_files_basedir_pattern: match target_type {
            EVMTargetType::Glob => Some(args.target),
            _ => None,
        },
        #[cfg(feature = "use_presets")]
        preset_file_path: args.preset_file_path,
        load_corpus: args.load_corpus,
        etherscan_api_key: String::from(""),
    };

    let mut abis_map: HashMap<String, Vec<Vec<serde_json::Value>>> = HashMap::new();

    for contract_info in config.contract_loader.contracts.clone() {
        let abis: Vec<serde_json::Value> = contract_info
            .abi
            .iter()
            .map(|config| {
                json!({
                    hex::encode(config.function): format!("{}{}", &config.function_name, &config.abi)
                })
            })
            .collect();
        abis_map
            .entry(hex::encode(contract_info.deployed_address))
            .or_default()
            .push(abis);
    }

    let json_str = serde_json::to_string(&abis_map).expect("Failed to serialize ABI map to JSON");

    debug!("work_dir: {:?}", args.work_dir.clone().as_str());
    let abis_json = format!("{}/abis.json", args.work_dir.clone().as_str());

    utils::try_write_file(&abis_json, &json_str, true).unwrap();
    evm_fuzzer(config, &mut state)
}

#[cfg(test)]
mod test {
    use super::{parse_constructor_args_string, resolve_concolic_num_threads, resolve_setup_file};
    use crate::r#const::{max_concolic_threads, MAX_CONCOLIC_THREADS};

    // Concolic (Z3) solving runs on a BOUNDED pool: at most min(2, cores)
    // solvers at once, campaign-wide. 0/unset means "use the cap"; a smaller
    // request is honoured (1 = sequential); a larger one is clamped to the cap
    // rather than honoured, because that is the oversubscription that froze a
    // 15-core host (one solver per core under the old num_cpus default).
    #[test]
    fn concolic_threads_are_bounded_by_the_campaign_cap() {
        let cap = max_concolic_threads();
        assert!(cap >= 1 && cap <= MAX_CONCOLIC_THREADS, "cap must be within the hard ceiling");

        assert_eq!(resolve_concolic_num_threads(0), cap, "0/unset must mean the cap");
        assert_eq!(resolve_concolic_num_threads(1), 1, "1 must force a single sequential solver");
        if cap >= 2 {
            assert_eq!(resolve_concolic_num_threads(2), 2, "2 must be honoured when the cap allows it");
        }
        for requested in [MAX_CONCOLIC_THREADS, 3, 15, 64, usize::MAX] {
            assert_eq!(
                resolve_concolic_num_threads(requested),
                cap,
                "a request above the cap must be clamped, never honoured (requested {requested})"
            );
        }
    }

    #[test]
    fn concolic_cap_never_exceeds_two_or_cores() {
        let cap = max_concolic_threads();
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        assert!(cap <= 2, "the cap must stay at or below 2 solvers");
        assert!(cap <= cores, "the cap must never exceed the machine's core count");
    }

    #[test]
    fn test_parse_constructor_args_string() {
        let input =
            "Test1:88,0x97C6D26d7E0D316850A967b46845E15a32666d25;Test2:88,0x97C6D26d7E0D316850A967b46845E15a32666d25"
                .to_string();
        let _ret = parse_constructor_args_string(input);
        // println!("constructor args: {:?}", ret);
    }

    /// A3 regression: an explicitly passed `--setup-file` must survive, and
    /// the two flags must resolve deterministically. The old code did
    /// `setup_file = deployment_script` unconditionally, so `--setup-file X`
    /// with `--deployment-script` left at its empty default silently became
    /// `""` and the run panicked with "Deployment script  not found".
    #[test]
    fn setup_file_flag_is_not_silently_discarded() {
        // Only the deprecated flag: it must be honoured, not overwritten by
        // the empty --deployment-script default.
        assert_eq!(resolve_setup_file("Y:X", ""), ("Y:X".to_string(), false));
        // Only the modern flag.
        assert_eq!(resolve_setup_file("", "Y:X"), ("Y:X".to_string(), false));
        // Neither.
        assert_eq!(resolve_setup_file("", ""), (String::new(), false));
        // Both identical: no conflict.
        assert_eq!(resolve_setup_file("Y:X", "Y:X"), ("Y:X".to_string(), false));
        // Both, different: --deployment-script wins, and the conflict is
        // reported so the caller can warn instead of dropping one silently.
        assert_eq!(resolve_setup_file("A:Old", "B:New"), ("B:New".to_string(), true));
    }
}
