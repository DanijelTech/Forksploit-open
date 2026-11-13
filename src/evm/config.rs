use std::{
    cell::RefCell,
    collections::HashSet,
    fmt::{self, Debug},
    rc::Rc,
    str::FromStr,
};

/// Configuration for the EVM fuzzer
use crate::evm::contract_utils::ContractLoader;
use crate::{
    evm::{
        blaz::builder::BuildJob,
        onchain::endpoints::OnChainConfig,
        oracles::erc20::IERC20OracleFlashloan,
        types::EVMAddress,
    },
    oracle::{Oracle, Producer},
};

pub enum FuzzerTypes {
    CMP,
    DATAFLOW,
    BASIC,
}

#[derive(Copy, Clone)]
pub enum StorageFetchingMode {
    Dump,
    OneByOne,
}

impl FromStr for StorageFetchingMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dump" => Ok(StorageFetchingMode::Dump),
            "onebyone" => Ok(StorageFetchingMode::OneByOne),
            _ => Err(format!("Unknown storage fetching mode: {}", s)),
        }
    }
}

impl FromStr for FuzzerTypes {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cmp" => Ok(FuzzerTypes::CMP),
            "dataflow" => Ok(FuzzerTypes::DATAFLOW),
            "basic" => Ok(FuzzerTypes::BASIC),
            _ => Err(format!("Unknown fuzzer type: {}", s)),
        }
    }
}

#[allow(clippy::type_complexity)]
pub struct Config<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E> {
    pub onchain: Option<OnChainConfig>,
    pub onchain_storage_fetching: Option<StorageFetchingMode>,
    pub etherscan_api_key: String,
    pub flashloan: bool,
    pub concolic: bool,
    pub concolic_caller: bool,
    pub concolic_timeout: u32,
    pub concolic_memory_mb: u32,
    pub concolic_num_threads: usize,
    pub contract_loader: ContractLoader,
    pub oracle: Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>>>>,
    pub producers: Vec<Rc<RefCell<dyn Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>>>>,
    pub replay_file: Option<String>,
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
    pub selfdestruct_oracle: bool,
    pub reentrancy_oracle: bool,
    pub state_comp_oracle: Option<String>,
    pub state_comp_matching: Option<String>,
    pub work_dir: String,
    pub write_relationship: bool,
    pub run_forever: bool,
    pub max_call_depth: u64,
    pub sha3_bypass: bool,
    pub base_path: String,
    pub panic_on_bug: bool,
    pub spec_id: String,
    pub only_fuzz: HashSet<EVMAddress>,
    pub typed_bug: bool,
    pub arbitrary_external_call: bool,
    pub math_calculate_oracle: bool,
    pub delegatecall_injection_oracle: bool,
    pub ecrecover_zero_oracle: bool,
    pub arbitrary_storage_write_oracle: bool,
    pub token_accounting_mismatch_oracle: bool,
    pub forced_eth_accounting_oracle: bool,
    pub readonly_reentrancy_oracle: bool,
    pub storage_collision_oracle: bool,
    pub delegatecall_target_oracle: bool,
    pub uninitialized_memory_oracle: bool,
    pub unchecked_call_oracle: bool,
    pub unbounded_loop_oracle: bool,
    pub stale_guard_oracle: bool,
    pub self_referral_oracle: bool,
    pub zero_address_setter_oracle: bool,
    pub gas_stipend_oracle: bool,
    pub weak_randomness_oracle: bool,
    pub precision_loss_oracle: bool,
    pub revert_in_loop_oracle: bool,
    pub assert_violation_oracle: bool,
    pub tx_origin_oracle: bool,
    pub builder: Option<BuildJob>,
    pub local_files_basedir_pattern: Option<String>,
    pub load_corpus: String,
    #[cfg(feature = "use_presets")]
    pub preset_file_path: String,
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E> Debug
    for Config<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("onchain", &self.onchain)
            // .field("onchain_storage_fetching", &self.onchain_storage_fetching)
            .field("flashloan", &self.flashloan)
            .field("concolic", &self.concolic)
            .field("concolic_caller", &self.concolic_caller)
            .field("contract_loader", &self.contract_loader)
            // .field("oracle", &self.oracle)
            // .field("producers", &self.producers)
            .field("replay_file", &self.replay_file)
            // .field("flashloan_oracle", &self.flashloan_oracle)
            .field("selfdestruct_oracle", &self.selfdestruct_oracle)
            .field("state_comp_oracle", &self.state_comp_oracle)
            .field("state_comp_matching", &self.state_comp_matching)
            .field("work_dir", &self.work_dir)
            .field("write_relationship", &self.write_relationship)
            .field("run_forever", &self.run_forever)
            .field("max_call_depth", &self.max_call_depth)
            .field("sha3_bypass", &self.sha3_bypass)
            .field("base_path", &self.base_path)
            .field("panic_on_bug", &self.panic_on_bug)
            .field("spec_id", &self.spec_id)
            .field("only_fuzz", &self.only_fuzz)
            .field("typed_bug", &self.typed_bug)
            // .field("builder", &self.builder)
            .finish()
    }
}
