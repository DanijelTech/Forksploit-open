use std::{
    cell::RefCell,
    fs::File,
    io::Read,
    ops::Deref,
    path::Path,
    process::exit,
    rc::Rc,
    sync::atomic::Ordering,
};

use bytes::Bytes;
use glob::glob;
use libafl::{
    feedbacks::Feedback,
    prelude::{HasMetadata, MaxMapFeedback, SimpleEventManager, SimpleMonitor, StdMapObserver},
    Evaluator,
    Fuzzer,
};
use libafl_bolts::tuples::tuple_list;
use revm_primitives::Bytecode;
use tracing::{debug, error, info, warn};

use crate::{
    evm::{
        abi::ABIAddressToInstanceMap,
        blaz::builder::ArtifactInfoMetadata,
        concolic::{
            concolic_host::{CONCOLIC_MEMORY_MB, CONCOLIC_TIMEOUT},
            concolic_stage::{ConcolicFeedbackWrapper, ConcolicStage},
        },
        config::Config,
        contract_utils::FIX_DEPLOYER,
        corpus_initializer::EVMCorpusInitializer,
        cov_stage::CoverageStage,
        feedbacks::Sha3WrappedFeedback,
        host::{
            FuzzHost,
            ACTIVE_MATCH_EXT_CALL,
            CALL_UNTIL,
            CMP_MAP,
            JMP_MAP,
            MAX_ANALYSIS_CALL_DEPTH,
            PANIC_ON_BUG,
            READ_MAP,
            WRITE_MAP,
            WRITE_RELATIONSHIPS,
        },
        input::{ConciseEVMInput, EVMInput},
        middlewares::{
            arbitrary_storage_write::ArbitraryStorageWriteTracer,
            call_printer::CallPrinter,
            // cheatcode::Cheatcode,
            coverage::{Coverage, EVAL_COVERAGE},
            delegatecall::DelegatecallInjectionTracer,
            delegatecall_target::DelegatecallTargetTracer,
            ecrecover::EcrecoverZeroTracer,
            middleware::Middleware,
            overflow::IntegerOverflowTracer,
            reentrancy::ReentrancyTracer,
            sha3_bypass::{Sha3Bypass, Sha3TaintAnalysis},
            storage_collision::StorageCollisionTracer,
            tx_origin::TxOriginTracer,
            unchecked_call::UncheckedCallTracer,
            uninitialized_memory::UninitializedMemoryTracer,
        },
        minimizer::EVMMinimizer,
        mutator::FuzzMutator,
        onchain::{flashloan::Flashloan, offchain::OffChainConfig, ChainConfig, OnChain, WHITELIST_ADDR},
        oracles::{
            arb_call::ArbitraryCallOracle,
            arbitrary_storage_write::ArbitraryStorageWriteOracle,
            assert_violation::AssertViolationOracle,
            token_accounting_mismatch::TokenAccountingMismatchOracle,
            forced_eth_accounting::ForcedEthAccountingOracle,
            gas_stipend::GasStipendOracle,
            readonly_reentrancy::ReadonlyReentrancyOracle,
            delegatecall::DelegatecallInjectionOracle,
            delegatecall_target::DelegatecallTargetOracle,
            ecrecover::EcrecoverZeroOracle,
            overflow::IntegerOverflowOracle,
            precision_loss::PrecisionLossOracle,
            reentrancy::ReentrancyOracle,
            revert_in_loop::RevertInLoopOracle,
            self_referral::SelfReferralOracle,
            selfdestruct::SelfdestructOracle,
            stale_guard::StaleGuardOracle,
            state_comp::StateCompOracle,
            storage_collision::StorageCollisionOracle,
            typed_bug::TypedBugOracle,
            tx_origin::TxOriginOracle,
            unbounded_loop::UnboundedLoopOracle,
            unchecked_call::UncheckedCallOracle,
            uninitialized_memory::UninitializedMemoryOracle,
            weak_randomness::WeakRandomnessOracle,
            zero_address_setter::ZeroAddressSetterOracle,
        },
        scheduler::{PowerABIMutationalStage, PowerABIScheduler, UncoveredBranchesMetadata},
        types::{fixed_address, EVMAddress, EVMFuzzMutator, EVMFuzzState, EVMQueueExecutor, EVMU256},
        vm::{EVMExecutor, EVMState},
    },
    executor::FuzzExecutor,
    feedback::{CmpFeedback, DataflowFeedback, OracleFeedback},
    fuzzer::{ForkSploitFuzzer, REPLAY, RUN_FOREVER},
    oracle::BugMetadata,
    scheduler::SortedDroppingScheduler,
    state::{FuzzState, HasCaller, HasExecutionResult},
};

#[allow(clippy::type_complexity)]
pub fn evm_fuzzer(
    config: Config<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
        EVMQueueExecutor,
    >,
    state: &mut EVMFuzzState,
) {
    info!("\n\n ================ EVM Fuzzer Start ===================\n\n");

    // create work dir if not exists
    let _path = Path::new(config.work_dir.as_str());

    let monitor = SimpleMonitor::new(|s| info!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = SortedDroppingScheduler::new();
    let scheduler = PowerABIScheduler::new();

    let jmps = unsafe { JMP_MAP.get_mut() };
    let cmps = unsafe { CMP_MAP.get_mut() };
    let reads = unsafe { READ_MAP.get_mut() };
    let writes = unsafe { WRITE_MAP.get_mut() };
    let jmp_observer = unsafe { StdMapObserver::new("jmp", jmps) };

    let deployer = fixed_address(FIX_DEPLOYER);
    let mut fuzz_host = FuzzHost::new(scheduler.clone(), config.work_dir.clone());

    // Ethereum Classic never did the Merge and is missing EIP-4399/EIP-4895
    // from its latest hardfork (Spiral/ECIP-1109, live since block
    // 19,250,000) -- revm has no SpecId that models that ruleset exactly.
    // SHANGHAI is the closest real match (gets PUSH0/warm-COINBASE/initcode
    // limits right) but will treat the DIFFICULTY opcode (0x44) as
    // PREVRANDAO-style randomness instead of ETC's real PoW difficulty
    // value. Surfaced explicitly here rather than silently defaulted,
    // since the gap is narrow but real -- revisit if ETC adopts another
    // ECIP that changes this.
    let chain_name = config.onchain.as_ref().map(|o| o.chain_name.as_str());
    // Mordor (ETC's testnet) runs the exact same client/consensus rules as
    // ETC mainnet -- it was simply missing from this check entirely until
    // now, the one place in the Rust binary that still only knew about
    // "etc" after Mordor was added chain-wide (Chain::MORDOR, chains.py,
    // etc.) -- meaning a Mordor run got NO warning at all, not even the
    // one ETC mainnet already had.
    if (chain_name == Some("etc") || chain_name == Some("mordor")) && config.spec_id != "Shanghai" {
        warn!(
            "Chain is Ethereum Classic ({}) but --spec-id is '{}', not 'Shanghai'. ETC's \
             current hardfork (Spiral/ECIP-1109) is closest to Shanghai (adds PUSH0 and warm \
             COINBASE) but explicitly skips the Merge-related EIPs (DIFFICULTY stays real PoW \
             difficulty, not PREVRANDAO). Recommended: --spec-id Shanghai (exact case).",
            chain_name.unwrap_or("etc"),
            config.spec_id
        );
    }

    fuzz_host.set_spec_id(config.spec_id);

    // **Note**: cheatcode should be the first middleware because it consumes the
    // step if it is a call to cheatcode_address, and this step should not be
    // visible to other middlewares.
    // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved
    // fuzz_host.add_middlewares(Rc::new(RefCell::new(Cheatcode::new(&config.
    // etherscan_api_key))));

    macro_rules! create_onchain {
        ($onchain: expr) => {{
            let mid = Rc::new(RefCell::new(OnChain::new(
                // scheduler can be cloned because it never uses &mut self
                $onchain,
                config.onchain_storage_fetching.unwrap(),
            )));

            if let Some(builder) = config.builder.clone() {
                mid.borrow_mut().add_builder(builder);
            }

            debug!("onchain middleware enabled");
            fuzz_host.add_middlewares(mid.clone());
            mid
        }};
    }

    let onchain_middleware = match config.onchain.clone() {
        Some(onchain) => Some(create_onchain!(onchain)),
        None => {
            // enable active match for offchain fuzzing (todo: handle this more elegantly)
            match &config.contract_loader.setup_data.clone().map(|s| s.onchain_middleware) {
                Some(Some(mid)) => {
                    let mid = Rc::new(RefCell::new(mid.clone()));
                    if let Some(builder) = config.builder.clone() {
                        mid.borrow_mut().add_builder(builder);
                    }
                    fuzz_host.add_middlewares(mid.clone());
                    Some(mid)
                }
                _ => {
                    ACTIVE_MATCH_EXT_CALL.store(false, Ordering::Relaxed);
                    None
                }
            }
        }
    };

    if config.write_relationship {
        WRITE_RELATIONSHIPS.store(true, Ordering::Relaxed);
    }

    if config.run_forever {
        RUN_FOREVER.store(true, Ordering::Relaxed);
    }

    MAX_ANALYSIS_CALL_DEPTH.store(config.max_call_depth, Ordering::Relaxed);

    PANIC_ON_BUG.store(config.panic_on_bug, Ordering::Relaxed);

    if !config.only_fuzz.is_empty() {
        *WHITELIST_ADDR.lock().unwrap() = Some(config.only_fuzz.clone());
    }

    if config.flashloan {
        // we should use real balance of tokens in the contract instead of providing
        // flashloan to contract as well for on chain env
        {
            let chain_cfg: Option<Box<dyn ChainConfig>> = if let Some(onchain) = config.onchain.clone() {
                Some(Box::new(onchain) as Box<dyn ChainConfig>)
            } else if let Some(ref setup_data) = config.contract_loader.setup_data {
                if setup_data.v2_pairs.is_empty() {
                    None
                } else {
                    Some(Box::new(OffChainConfig::new(setup_data).unwrap()) as Box<dyn ChainConfig>)
                }
            } else {
                None
            };

            fuzz_host.add_flashloan_middleware(Flashloan::new(true, chain_cfg, config.flashloan_oracle));
        }
    }
    let sha3_taint = Rc::new(RefCell::new(Sha3TaintAnalysis::new()));

    if config.sha3_bypass {
        debug!("sha3 bypass enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(Sha3Bypass::new(sha3_taint.clone()))));
    }

    if config.reentrancy_oracle {
        debug!("reentrancy oracle enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(ReentrancyTracer::new())));
    }

    if config.math_calculate_oracle {
        debug!("integer overflow middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(IntegerOverflowTracer::new())));
    }

    if config.delegatecall_injection_oracle {
        debug!("delegatecall injection middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(DelegatecallInjectionTracer::new())));
    }

    if config.ecrecover_zero_oracle {
        debug!("ecrecover(0) middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(EcrecoverZeroTracer::new())));
    }

    if config.arbitrary_storage_write_oracle {
        debug!("arbitrary storage write middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(ArbitraryStorageWriteTracer::new())));
    }

    if config.storage_collision_oracle {
        debug!("storage collision middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(StorageCollisionTracer::new())));
    }

    if config.delegatecall_target_oracle {
        debug!("delegatecall target middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(DelegatecallTargetTracer::new())));
    }

    if config.uninitialized_memory_oracle {
        debug!("uninitialized memory middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(UninitializedMemoryTracer::new())));
    }

    if config.unchecked_call_oracle {
        debug!("unchecked call middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(UncheckedCallTracer::new())));
    }

    if config.tx_origin_oracle {
        debug!("tx.origin middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(TxOriginTracer::new())));
    }

    let mut evm_executor: EVMQueueExecutor = EVMExecutor::new(fuzz_host, deployer);

    if config.replay_file.is_some() {
        // add coverage middleware for replay
        REPLAY.store(true, Ordering::Relaxed);
    }

    // moved here to ensure state has ArtifactInfoMetadata during corpus
    // initialization
    if !state.has_metadata::<ArtifactInfoMetadata>() {
        state.add_metadata(ArtifactInfoMetadata::new());
    }
    let mut corpus_initializer = EVMCorpusInitializer::new(
        &mut evm_executor,
        scheduler.clone(),
        infant_scheduler.clone(),
        state,
        config.work_dir.clone(),
    );

    let mut artifacts = corpus_initializer.initialize(&mut config.contract_loader.clone());

    // Seed the address/caller pools with this chain's real wrapped-native
    // token (see `known_base_token`'s own doc for why) -- complements the
    // SLOAD-based harvesting in host.rs, which only discovers addresses
    // already sitting in a target's OWN storage. A fresh DEX factory has
    // none to harvest (nothing's been paired yet), so without this,
    // createPair(tokenA, tokenB)-shaped code stays unreachable by random
    // mutation alone no matter how long fuzzing runs.
    if let Some(onchain) = &config.onchain {
        if let Some(base_token) = crate::evm::tokens::onchain_pair_discovery::known_base_token(onchain.chain_id) {
            state.add_caller(&base_token);
        }
    }

    let mut instance_map = ABIAddressToInstanceMap::new();
    artifacts.address_to_abi_object.iter().for_each(|(addr, abi)| {
        instance_map.map.insert(*addr, abi.clone());
    });

    #[cfg(feature = "use_presets")]
    {
        let (has_preset_match, matched_templates, sig_to_addr_abi_map): (
            bool,
            Vec<ExploitTemplate>,
            HashMap<[u8; 4], (EVMAddress, BoxedABI)>,
        ) = if !config.preset_file_path.is_empty() {
            let mut sig_to_addr_abi_map = HashMap::new();
            let exploit_templates = match ExploitTemplate::from_filename(config.preset_file_path.clone()) {
                Ok(templates) => templates,
                Err(e) => {
                    error!("{e}");
                    vec![]
                }
            };
            let mut matched_templates = vec![];
            for template in exploit_templates {
                // to match, all function_sigs in the template
                // must exists in all abi.function
                let mut function_sigs = template.function_sigs.clone();
                for (addr, abis) in &artifacts.address_to_abi_object {
                    for abi in abis {
                        for (idx, function_sig) in function_sigs.iter().enumerate() {
                            if abi.function == function_sig.value {
                                debug!("matched: {:?} @ {:?}", abi.function, addr);
                                sig_to_addr_abi_map.insert(function_sig.value, (*addr, abi.clone()));
                                function_sigs.remove(idx);
                                break;
                            }
                        }
                    }
                    if function_sigs.is_empty() {
                        matched_templates.push(template);
                        break;
                    }
                }
            }

            if !matched_templates.is_empty() {
                (true, matched_templates, sig_to_addr_abi_map)
            } else {
                (false, vec![], HashMap::new())
            }
        } else {
            (false, vec![], HashMap::new())
        };
        debug!("has_preset_match: {} {}", has_preset_match, matched_templates.len());

        state.init_presets(has_preset_match, matched_templates.clone(), sig_to_addr_abi_map);
    }
    let cov_middleware = Rc::new(RefCell::new(Coverage::new(
        artifacts.address_to_name.clone(),
        config.work_dir.clone(),
    )));

    evm_executor.host.add_middlewares(cov_middleware.clone());

    state.add_metadata(instance_map);

    evm_executor.host.initialize(state);

    // now evm executor is ready, we can clone it

    let evm_executor_ref = Rc::new(RefCell::new(evm_executor));

    let meta = state.metadata_map_mut().get_mut::<ArtifactInfoMetadata>().unwrap();
    for (addr, build_artifact) in &artifacts.build_artifacts {
        meta.add(*addr, build_artifact.clone());
    }

    for (addr, bytecode) in &mut artifacts.address_to_bytecode {
        unsafe {
            cov_middleware.deref().borrow_mut().on_insert(
                None,
                &mut evm_executor_ref.deref().borrow_mut().host,
                state,
                bytecode,
                *addr,
            );
        }
    }

    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    feedback.init_state(state).expect("Failed to init state");
    // let calibration = CalibrationStage::new(&feedback);
    if config.concolic {
        CONCOLIC_TIMEOUT.store(config.concolic_timeout, Ordering::Relaxed);
        CONCOLIC_MEMORY_MB.store(config.concolic_memory_mb, Ordering::Relaxed);
    }

    let concolic_stage = ConcolicStage::new(
        config.concolic,
        config.concolic_caller,
        evm_executor_ref.clone(),
        config.concolic_num_threads,
    );
    let mutator: EVMFuzzMutator = FuzzMutator::new(infant_scheduler.clone());

    state.metadata_map_mut().insert(UncoveredBranchesMetadata::new());
    let std_stage = PowerABIMutationalStage::new(mutator);

    let call_printer_mid = Rc::new(RefCell::new(CallPrinter::new(artifacts.address_to_name.clone())));

    let coverage_obs_stage = CoverageStage::new(
        evm_executor_ref.clone(),
        cov_middleware.clone(),
        call_printer_mid.clone(),
        config.work_dir.clone(),
    );

    let mut stages = tuple_list!(std_stage, concolic_stage, coverage_obs_stage);

    let mut executor = FuzzExecutor::new(evm_executor_ref.clone(), tuple_list!(jmp_observer));

    #[cfg(feature = "deployer_is_attacker")]
    state.add_caller(&deployer);
    let infant_feedback = CmpFeedback::new(cmps, infant_scheduler.clone(), evm_executor_ref.clone());
    let infant_result_feedback = DataflowFeedback::new(reads, writes);

    let mut oracles = config.oracle;

    if let Some(path) = config.state_comp_oracle.clone() {
        let mut file = File::open(path.clone()).unwrap_or_else(|e| panic!("Failed to open state comp oracle file {path}: {e}"));
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .unwrap_or_else(|e| panic!("Failed to read state comp oracle file {path}: {e}"));

        let evm_state = serde_json::from_str::<EVMState>(buf.as_str())
            .unwrap_or_else(|e| panic!("Failed to parse state comp oracle file {path}: {e}"));

        let oracle = Rc::new(RefCell::new(StateCompOracle::new(
            evm_state,
            config
                .state_comp_matching
                .clone()
                .expect("--state-comp-matching must be set when --state-comp-file is given"),
        )));
        oracles.push(oracle);
    }

    if config.math_calculate_oracle {
        debug!("integer overflow oracle enabled");
        oracles.push(Rc::new(RefCell::new(IntegerOverflowOracle::new())));
    }

    if config.delegatecall_injection_oracle {
        debug!("delegatecall injection oracle enabled");
        oracles.push(Rc::new(RefCell::new(DelegatecallInjectionOracle::new())));
    }

    if config.ecrecover_zero_oracle {
        debug!("ecrecover(0) oracle enabled");
        oracles.push(Rc::new(RefCell::new(EcrecoverZeroOracle::new())));
    }

    if config.arbitrary_storage_write_oracle {
        debug!("arbitrary storage write oracle enabled");
        oracles.push(Rc::new(RefCell::new(ArbitraryStorageWriteOracle::new())));
    }

    if config.token_accounting_mismatch_oracle {
        debug!("token accounting mismatch oracle enabled");
        oracles.push(Rc::new(RefCell::new(TokenAccountingMismatchOracle::new())));
    }

    if config.forced_eth_accounting_oracle {
        debug!("forced eth accounting oracle enabled");
        oracles.push(Rc::new(RefCell::new(ForcedEthAccountingOracle::new())));
    }

    if config.readonly_reentrancy_oracle {
        debug!("readonly reentrancy oracle enabled");
        oracles.push(Rc::new(RefCell::new(ReadonlyReentrancyOracle::new())));
    }

    if config.storage_collision_oracle {
        debug!("storage collision oracle enabled");
        oracles.push(Rc::new(RefCell::new(StorageCollisionOracle::new())));
    }

    if config.delegatecall_target_oracle {
        debug!("delegatecall target oracle enabled");
        oracles.push(Rc::new(RefCell::new(DelegatecallTargetOracle::new())));
    }

    if config.uninitialized_memory_oracle {
        debug!("uninitialized memory oracle enabled");
        oracles.push(Rc::new(RefCell::new(UninitializedMemoryOracle::new())));
    }

    if config.unchecked_call_oracle {
        debug!("unchecked call oracle enabled");
        oracles.push(Rc::new(RefCell::new(UncheckedCallOracle::new())));
    }

    if config.unbounded_loop_oracle {
        debug!("unbounded loop oracle enabled");
        oracles.push(Rc::new(RefCell::new(UnboundedLoopOracle::new())));
    }

    if config.stale_guard_oracle {
        debug!("stale guard oracle enabled");
        oracles.push(Rc::new(RefCell::new(StaleGuardOracle::new())));
    }

    if config.self_referral_oracle {
        debug!("self-referral oracle enabled");
        oracles.push(Rc::new(RefCell::new(SelfReferralOracle::new())));
    }

    if config.tx_origin_oracle {
        debug!("tx.origin oracle enabled");
        oracles.push(Rc::new(RefCell::new(TxOriginOracle::new())));
    }

    if config.zero_address_setter_oracle {
        debug!("zero address setter oracle enabled");
        oracles.push(Rc::new(RefCell::new(ZeroAddressSetterOracle::new())));
    }

    if config.gas_stipend_oracle {
        debug!("hardcoded gas stipend oracle enabled");
        oracles.push(Rc::new(RefCell::new(GasStipendOracle::new())));
    }

    if config.weak_randomness_oracle {
        debug!("weak randomness oracle enabled");
        oracles.push(Rc::new(RefCell::new(WeakRandomnessOracle::new())));
    }

    if config.precision_loss_oracle {
        debug!("precision loss oracle enabled");
        oracles.push(Rc::new(RefCell::new(PrecisionLossOracle::new())));
    }

    if config.revert_in_loop_oracle {
        debug!("revert in loop oracle enabled");
        oracles.push(Rc::new(RefCell::new(RevertInLoopOracle::new())));
    }

    if config.assert_violation_oracle {
        debug!("assert violation oracle enabled");
        oracles.push(Rc::new(RefCell::new(AssertViolationOracle::new())));
    }

    if config.arbitrary_external_call {
        oracles.push(Rc::new(RefCell::new(ArbitraryCallOracle::new(
            artifacts.address_to_name.clone(),
        ))));
    }

    if config.typed_bug {
        oracles.push(Rc::new(RefCell::new(TypedBugOracle::new(
            artifacts.address_to_name.clone(),
        ))));
    }

    state.add_metadata(BugMetadata::new());

    if config.selfdestruct_oracle {
        oracles.push(Rc::new(RefCell::new(SelfdestructOracle::new(
            artifacts.address_to_name.clone(),
        ))));
    }

    if config.reentrancy_oracle {
        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
            artifacts.address_to_name.clone(),
        ))));
    }

    if let Some(m) = onchain_middleware.clone() {
        m.borrow_mut().add_abi(artifacts.address_to_abi.clone());
    }

    let mut producers = config.producers;

    let objective: OracleFeedback<
        '_,
        EVMState,
        revm_primitives::B160,
        Bytecode,
        Bytes,
        revm_primitives::B160,
        revm_primitives::ruint::Uint<256, 4>,
        Vec<u8>,
        EVMInput,
        FuzzState<EVMInput, EVMState, revm_primitives::B160, revm_primitives::B160, Vec<u8>, ConciseEVMInput>,
        ConciseEVMInput,
        EVMQueueExecutor,
    > = OracleFeedback::new(&mut oracles, &mut producers, evm_executor_ref.clone());
    let wrapped_feedback = ConcolicFeedbackWrapper::new(Sha3WrappedFeedback::new(
        feedback,
        sha3_taint,
        evm_executor_ref.clone(),
        config.sha3_bypass,
    ));

    let mut fuzzer: ForkSploitFuzzer<_, _, _, _, _, _, _, _, _, _, _, _, _, _, EVMMinimizer> = ForkSploitFuzzer::new(
        scheduler,
        infant_scheduler,
        wrapped_feedback,
        infant_feedback,
        infant_result_feedback,
        objective,
        EVMMinimizer::new(evm_executor_ref.clone()),
        config.work_dir,
    );

    let initial_vm_state = artifacts.initial_state.clone();
    let mut testcases = vec![];
    let to_load_glob: String;

    if let Some(files) = config.replay_file.clone() {
        to_load_glob = files;
    } else {
        to_load_glob = config.load_corpus;
    }

    if !to_load_glob.is_empty() {
        'process_file: for file in glob(to_load_glob.as_str()).expect("Failed to read glob pattern") {
            let mut f = File::open(file.as_ref().expect("glob issue")).expect("Failed to open file");
            let mut transactions = String::new();
            let mut deserialized_transactions = vec![];
            f.read_to_string(&mut transactions).expect("Failed to read file");
            for txn in transactions.split('\n') {
                if txn.len() < 4 {
                    continue;
                }
                let deserialized_tx = serde_json::from_slice::<ConciseEVMInput>(txn.as_bytes());
                if deserialized_tx.is_err() {
                    error!("Failed to deserialize file: {:?}", file);
                    continue 'process_file;
                }
                deserialized_transactions.push(deserialized_tx.unwrap());
            }
            testcases.push(deserialized_transactions);
        }
    }

    macro_rules! load_code {
        ($txn: expr) => {
            if let Some(onchain_mid) = onchain_middleware.clone() {
                onchain_mid.borrow_mut().load_code(
                    $txn.contract,
                    &mut evm_executor_ref.clone().deref().borrow_mut().host,
                    false,
                    true,
                    false,
                    $txn.caller,
                    state,
                );
            }
        };
    }

    match config.replay_file {
        None => {
            // load initial corpus
            //
            // Each seeded testcase may carry its own recorded `call_leak`
            // boundary, which this loop applies to the process-global
            // `CALL_UNTIL` per step. Scope a guard to JUST this loop so the
            // neutral value is restored before `fuzz_loop` below: the normal
            // fuzzing loop must run with `u32::MAX` (leaks there are
            // address/caller-based, not count-based), and a stale boundary
            // left by a seeded trace would otherwise silently change the whole
            // campaign's search.
            {
                let _call_until_guard = crate::evm::host::CallUntilGuard::preserve();
                for testcase in testcases {
                    let mut vm_state = initial_vm_state.clone();
                    for txn in testcase {
                        load_code!(txn);
                        let (inp, call_until) = txn.to_input(vm_state.clone());
                        CALL_UNTIL.store(call_until, Ordering::Relaxed);
                        fuzzer
                            .evaluate_input_events(state, &mut executor, &mut mgr, inp, false)
                            .unwrap();
                        vm_state = state.get_execution_result().new_state.clone();
                    }
                }
            }
            let res = fuzzer.fuzz_loop(&mut stages, &mut executor, state, &mut mgr);

            // it is not possible to reach here unless an exception is thrown
            let rv = res.err().unwrap().to_string();
            if rv == "No items in No entries in corpus" {
                error!("There is nothing to fuzz. Please check the target you provided.");
                return;
            } else {
                error!("{}", rv);
            }
            exit(1);
        }
        Some(_) => {
            EVAL_COVERAGE.store(true, Ordering::Relaxed);

            let printer = Rc::new(RefCell::new(CallPrinter::new(artifacts.address_to_name.clone())));
            evm_executor_ref.borrow_mut().host.add_middlewares(printer.clone());

            for testcase in testcases {
                let mut vm_state = initial_vm_state.clone();
                let mut idx = 0;
                for txn in testcase {
                    load_code!(txn);
                    idx += 1;
                    // let splitter = txn.split(" ").collect::<Vec<&str>>();
                    info!("============ Execution {} ===============", idx);
                    let (inp, call_until) = txn.to_input(vm_state.clone());
                    printer.borrow_mut().cleanup();

                    CALL_UNTIL.store(call_until, Ordering::Relaxed);

                    fuzzer
                        .evaluate_input_events(state, &mut executor, &mut mgr, inp, false)
                        .unwrap();

                    info!("============ Execution result {} =============", idx);
                    info!("reverted: {:?}", state.get_execution_result().clone().reverted);
                    info!("call trace:\n{}", printer.deref().borrow().get_trace());
                    info!("output: {:?}", hex::encode(state.get_execution_result().clone().output));

                    // debug!(
                    //     "new_state: {:?}",
                    //     state.get_execution_result().clone().new_state.state
                    // );

                    vm_state = state.get_execution_result().new_state.clone();
                    info!("================================================");
                }
            }

            // dump coverage:
            cov_middleware.borrow_mut().record_instruction_coverage();
            // unsafe {
            //     EVAL_COVERAGE = false;
            //     CALL_UNTIL = u32::MAX;
            // }

            // fuzzer
            //     .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
            //     .expect("Fuzzing failed");
        }
    }
}
