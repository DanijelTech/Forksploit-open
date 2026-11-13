# RUST CORE — module by module

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it. See [`DISCLAIMER.md`](../DISCLAIMER.md).**

> Standalone document. Related: [ARCHITECTURE.md](ARCHITECTURE.md),
> [ORACLES.md](ORACLES.md), [PLAN_JSON.md](PLAN_JSON.md),
> [DEPENDENCIES.md](DEPENDENCIES.md).

All paths are relative to the repository root. Every claim is verified in code
(`src/**/*.rs`).

---

## 1. Entry point and constants

### `src/main.rs`
* `Cli` (clap `Parser`), `Commands` (the `Evm` subcommand).
* `main`: `logger::init()`, `Cli::parse()`, then `evm_main(args)`.
* Version: `version=env!("GIT_VERSION_INFO")`, set by `src/build.rs`.

### `src/build.rs`
* At build time it runs `git rev-parse HEAD` and prints
  `cargo:rustc-env=GIT_VERSION_INFO=<hash>[<features>]`.
* Declares `cargo:rustc-check-cfg` for foreign features (`serdeany_autoreg`,
  `introspection`), so the lint does not report errors in dependency macros.

### `src/const.rs`
Global constants (selected; all values from the code):

| Constant | Value | Meaning |
|-----------|----------|-------|
| `MAX_CONCOLIC_THREADS` | `2` | hard cap on concolic solvers for the whole campaign |
| `max_concolic_threads()` | `min(2, cores)` | the effective cap |
| `INFANT_STATE_INITIAL_VOTES` | `3` | initial votes of an infant state |
| `CORPUS_INITIAL_VOTES` | `3` | initial corpus votes |
| `MAX_STACK_POW` | `7` | depth of the libafl stack mutator (2^7) |
| `MAX_HAVOC_ATTEMPTS` | `32` | havoc mutation attempts |
| `KNOWN_STATE_MAX_SIZE` | `1000` | — |
| `KNOWN_STATE_SKIP_SIZE` | `500` | — |
| `DROP_THRESHOLD` | `4000` | corpus pruning threshold |
| `PRUNE_AMT` | `1000` | how much is pruned at once |
| `VISIT_IGNORE_THRESHOLD` | `2` | ignore during pruning |
| `ACCOUNT_AMT` | `8` | number of random accounts/callers |
| `CONTRACT_AMT` | `8` | number of random contracts |
| `MAX_INPUT_SIZE` | `64` | maximum input data size |
| `SAMPLE_MAX` | `100` | — |
| `MUTATE_CHOICE_MAX` | `80` | — |
| `EXPAND_CHOICE_MAX` | `90` | — |
| `RANDOM_ADDRESS_CHOICE` | `90` | — |
| `MULTI_ADDR_CHOICE` | `35` | probability of setting addresses together |
| `UNKNOWN_SIGS_DIVISOR` | `30` | threshold for EVMole decompilation |
| `MUTATOR_SAMPLE_MAX` | `100` | — |
| `EXPLOIT_PRESET_CHOICE` | `20` | — |
| `ABI_MUTATE_CHOICE` | `96` | — |
| `HAVOC_CHOICE` | `60` | — |
| `HAVOC_MAX_ITERS` | `10` | — |
| `MUTATE_CALLER_CHOICE` | `20` | — |
| `TURN_TO_STEP_CHOICE` | `60` | — |
| `RANDOMNESS_CHOICE` | `33` | — |
| `LIQUIDATE_CHOICE` | `5` | — |
| `LIQ_PERCENT_CHOICE` | `80` | — |
| `LIQ_PERCENT` | `10` | — |
| `RANDOMNESS_CHOICE_2` | `6` | — |
| `MUTATION_RETRIES` | `20` | — |
| `POWER_MULTIPLIER` | `32.0` | scheduler |
| `MAX_POWER` | `3200.0` | — |
| `MIN_POWER` | `32.0` | — |

---

## 2. `src/evm/mod.rs` — CLI and configuration assembly

### `EvmArgs` (clap)
All flags are in `EvmArgs`. A brief summary (exact reference in
[CLI_REFERENCE.md](CLI_REFERENCE.md)):

| Flag | Short | Field | Default |
|-----------|--------|-------|----------|
| `--target` | `-t` | `target` | `"none"` |
| `--fetch-tx-data` | — | `fetch_tx_data` | `false` |
| `--proxy-address` | — | `proxy_address` | `http://localhost:5001/data` |
| `--constructor-args` | — | `constructor_args` | `""` |
| `--target-type` | — | `target_type` | `None` |
| `--chain-type` | `-c` | `chain_type` | `None` |
| `--onchain-block-number` | `-b` | `onchain_block_number` | `None` |
| `--onchain-url` | `-u` | `onchain_url` | `None` |
| `--onchain-chain-id` | `-i` | `onchain_chain_id` | `None` |
| `--onchain-explorer-url` | `-e` | `onchain_explorer_url` | `None` |
| `--onchain-chain-name` | `-n` | `onchain_chain_name` | `None` |
| `--onchain-etherscan-api-key` | `-k` | `onchain_etherscan_api_key` | `None` |
| `--onchain-storage-fetching` | — | `onchain_storage_fetching` | `"onebyone"` |
| `--concolic` | — | `concolic` | `false` |
| `--concolic-caller` | — | `concolic_caller` | `false` |
| `--concolic-timeout` | — | `concolic_timeout` | `1000` |
| `--concolic-memory-mb` | — | `concolic_memory_mb` | `2048` |
| `--concolic-num-threads` | — | `concolic_num_threads` | `0` |
| `--flashloan` | `-f` | `flashloan` | `false` |
| `--panic-on-bug` | — | `panic_on_bug` | `false` |
| `--detectors` | `-d` | `detectors` | `"all"` |
| `--invariants` | — | `invariants` | `None` |
| `--auto-setup` | — | `auto_setup` | `false` |
| `--state-comp-file` | — | `state_comp_file` | `None` |
| `--state-comp-matching` | — | `state_comp_matching` | `"Exact"` |
| `--replay-file` | `-r` | `replay_file` | `None` |
| `--work-dir` | `-w` | `work_dir` | `"work_dir"` |
| `--write-relationship` | — | `write_relationship` | `false` |
| `--run-forever` | — | `run_forever` | `false` |
| `--max-call-depth` | — | `max_call_depth` | `32` |
| `--seed` | — | `seed` | `1667840158231589000` |
| `--jobs` | — | `jobs` | `1` |
| `--fuzz-seconds` | — | `fuzz_seconds` | `0` |
| `--sha3-bypass` | — | `sha3_bypass` | `false` |
| `--only-fuzz` | — | `only_fuzz` | `""` |
| `--base-path` | — | `base_path` | `""` |
| `--spec-id` | — | `spec_id` | `"Latest"` |
| `--onchain-builder` | — | `onchain_builder` | `""` |
| `--onchain-replacements-file` | — | `onchain_replacements_file` | `""` |
| `--builder-artifacts-url` | — | `builder_artifacts_url` | `""` |
| `--builder-artifacts-file` | — | `builder_artifacts_file` | `""` |
| `--offchain-config-url` | — | `offchain_config_url` | `""` |
| `--offchain-config-file` | — | `offchain_config_file` | `""` |
| `--load-corpus` | — | `load_corpus` | `""` |
| `--setup-file` | — | `setup_file` | `""` (deprecated alias) |
| `--deployment-script` | `-m` | `deployment_script` | `""` |
| `--force-abi` | — | `force_abi` | `""` |
| `--base-directory` | — | `base_directory` | `""` |
| `--preset-file-path` | — | `preset_file_path` | feature `use_presets` |
| `build_command` (positional) | — | `build_command` | `[]` |

Note: the default feature set (`Cargo.toml`) is
`cmp dataflow evm print_txn_corpus full_trace force_cache real_balance`.
`use_presets`, `print_logs`, `debug`, `z3_debug`, `flashloan_debug`,
`ondisk_corpus`, `fuzz_static`, `evaluation`, `deployer_is_attacker`,
`print_infant_corpus`, `no_etherscan` are off.

### `OracleType`
* `enum OracleType` with `as_str()`/`from_str()`/`from_strs()`.
* `from_strs` supports two presets:
  * `"all"` → 47 oracles (including `Invariant`);
  * `"high_confidence"` → a narrower list (without Review-tier oracles; it
    includes `SelfReferral`).
* An unknown name → `panic!("Invalid detector type: {}", s)`.

### `evm_main`
* If `args.jobs > 1` and `FORKSPLOIT_JOB` is not set → `multicore::run_supervisor`.
* `validate_spec_id` warns about an unknown `--spec-id`.
* `resolve_setup_file(setup_file, deployment_script)` — deterministically
  merges `--setup-file` and `--deployment-script` (the latter wins on conflict).
* It builds `onchain` from `--chain-type` or `--onchain-*`; if `--onchain-url`
  is given together with `--chain-type`, it sets `ETH_RPC_URL`.
* `solution::init_cli_args(target, work_dir, &onchain)`.
* It builds the list of `oracles` from `oracle_types` (see [ORACLES.md](ORACLES.md)).
* `--invariants` loads `InvariantSpec::from_file`; a read error is a visible
  `error!` (not silent).
* Target loader based on `target_type` (see `contract_utils.rs`).
* `--auto-setup` derives a `SetupSpec` via `auto_setup::derive_setup_spec`.
* It builds `Config` and calls `evm_fuzzer(config, &mut state)`.
* It writes `work_dir/abis.json`.

### `resolve_concolic_num_threads`
The cap is `min(2, cores)`; `0` = the cap, a smaller value is honoured, a larger
one is clamped with a warning.

### Tests in `mod.rs`
`concolic_threads_are_bounded_by_the_campaign_cap`,
`concolic_cap_never_exceeds_two_or_cores`,
`setup_file_flag_is_not_silently_discarded`, `test_parse_constructor_args_string`.

---

## 3. `src/evm/config.rs`

`Config<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI, E>` carries everything
the fuzzer needs: `contract_loader`, `only_fuzz`, `onchain`, concolic fields,
`oracle`, `producers`, `flashloan`, oracle flags (`typed_bug`,
`arbitrary_external_call`, `math_calculate_oracle`, ...), `work_dir`,
`run_forever`, `max_call_depth`, `sha3_bypass`, `spec_id`, `load_corpus`,
`etherscan_api_key`.

`StorageFetchingMode` (`FromStr`): `dump`, `onebyone`.

---

## 4. `src/evm/contract_utils.rs` — target loading

| Symbol | Purpose |
|--------|---------|
| `ContractLoader` | carries `contracts`, `setup_spec`, `base_path`, ... |
| `ContractInfo` | address, name, ABI, bytecode |
| `ABIConfig`, `ABIInfo` | parsed ABI |
| `from_glob(path, state, proxy_deploy_codes, constructor_args_map, target, base_path)` | a local directory with `.bin`/`.abi` |
| `from_address(onchain, addresses, builder)` | already-deployed contracts + `expand_proxy_targets` |
| `from_fork(offchain_artifacts, onchain, targets)` | Anvil fork + `expand_proxy_targets` |
| `from_config(offchain_artifacts, offchain_config)` | from `--offchain-config-*` |
| `from_setup(offchain_artifacts, setup_file, work_dir, etherscan_api_key)` | from a deployment contract |
| `expand_proxy_targets(onchain, addresses)` | adds proxy implementations |
| `proxy_implementations_of(onchain, addr)` | EIP-1967 impl/beacon, EIP-1822 UUPS, EIP-1167, EIP-7702 |
| `force_abi(mapping)` | forces the ABI from `--force-abi` |
| `extract_combined_json`, `extract_sig_from_contract`, `compute_address`, `to_hex_string` | helpers |

The slot constants are in `src/evm/mod.rs`: `EIP1967_IMPLEMENTATION_SLOT`,
`EIP1967_ADMIN_SLOT`. The test
`contract_utils::tests::test_proxy_slot_constants_match_keccak` verifies that
they match keccak.

---

## 5. `src/evm/vm.rs` and `src/generic_vm/*`

* `EVMState` (`src/evm/vm.rs`): `state` (storage by address), `balance`,
  `post_execution`, `trace`, `swap_data`.
* `EVMExecutor<VS, CI, SC>`: `new(fuzz_host, deployer)`, `execute_from_pc`,
  `reexecute_with_middleware`.
* `SinglePostExecution`, `PostExecutionCtx`, `Constraint` (for concolic).
* `is_reverted_or_control_leak(ret)`.
* `src/generic_vm/vm_state.rs`: the `VMStateT` trait, `SwapInfo`.
* `src/generic_vm/vm_executor.rs`: `MAP_SIZE`, the generic executor.

---

## 6. `src/evm/host.rs` — FuzzHost

Key global elements:

| Symbol | Purpose |
|--------|-------|
| `JMP_MAP`, `READ_MAP`, `WRITE_MAP`, `CMP_MAP`, `ABI_MAX_SIZE` | `RacyCell` maps for feedback |
| `CALL_UNTIL` | `AtomicU32`; when to trigger the control leak (u32::MAX = never) |
| `CONCOLIC_NO_CONTROL_LEAK` | `AtomicBool`; disables the leak during concolic search |
| `control_leak_bypassed()` | `CALL_UNTIL != u32::MAX` or the concolic flag |
| `CallUntilGuard` | RAII for safely setting `CALL_UNTIL` |
| `MAX_ANALYSIS_CALL_DEPTH` | `AtomicU64`, default `15` |
| `HARVESTED_STORAGE_ADDRESSES` | addresses read from the storage of any target |
| `HARVESTED_ADDRESS_ORIGINS` | (contract, slot) origin of each harvested address |
| `HARVESTED_SENDER_GUARDS` | (contract, caller) pairs where the caller comes from the **same** contract |
| `record_harvested_storage_address(addr, contract, slot)` | records a harvest |
| `is_harvested_storage_address(checksummed)` | whether an address is harvested |
| `harvested_address_origin(checksummed)` | (contract, slot) |
| `is_harvested_sender_for(contract, addr)` | the semantic owner-gated test |
| `FuzzHost<SC>` | the call executor itself |
| `call_allow_control_leak` | allows a faked return after `CALL_UNTIL` |
| `call_forbid_control_leak` | a real call (used in concolic) |
| `CONTROL_LEAK_THRESHOLD` | `200` |

`control_leak` is the mechanism the fuzzer uses to explore (e.g. reentrancy). A
plan found with it is tagged `call_leak != u32::MAX` and consequently
`atomic_replayable = false`.

---

## 7. `src/evm/oracle.rs` — the confidence level

* `enum ConfidenceTier { Confirmed, Review }`; `as_str()` → `"sim-confirmed"`
  / `"sim-review"` (never a bare `"confirmed"`).
* `classify_confidence(bug_type) -> ConfidenceTier` — maps `bug_type` to a
  level. The list of Confirmed-tier types is in this function.
* `effective_confidence(base, call_leak)` — if `call_leak != u32::MAX`, it
  forces `Review`.
* `EVMBugResult { bug_type, bug_info, input, issue_source, sourcemap, bug_idx,
  confidence }`; `to_value()` prints JSON with `confidence` (per
  `effective_confidence`) and `evidence: "replayable_transaction_trace"`.
* `new(...)`, `new_simple(...)`, `push_to_output()` (into `ORACLE_OUTPUT`).
* Tests: `effective_confidence_tests`.

The detailed list of Confirmed-tier `bug_type` values is in
[ORACLES.md](ORACLES.md) and [PLAN_JSON.md](PLAN_JSON.md).

---

## 8. `src/evm/oracles/*` — the detectors

Every oracle implements the `Oracle` trait (`src/oracle.rs`):
`oracle(&mut self, ctx: EVMOracleCtx<...>) -> Vec<u64>` returns a `bug_idx`.
`EVMBugResult::push_to_output` writes into `ORACLE_OUTPUT`.

The `bug_idx` constants are in `src/evm/oracles/mod.rs` (`ERC20_BUG_IDX = 0`,
... `INVARIANT_BUG_IDX = 50`). The full catalogue is in [ORACLES.md](ORACLES.md).

Helper macro: `oracle_should_skip!` (checks `BugMetadata::known_bugs`).

---

## 9. `src/evm/middlewares/*`

The `Middleware<SC>` trait (`middleware.rs`): `on_step`, `on_goal`, ...
`MiddlewareType` enum: `OnChain`, `Concolic`, `Flashloan`, `InstructionCoverage`,
`BranchCoverage`, `Sha3Bypass`, `Sha3TaintAnalysis`, `CallPrinter`,
`Reentrancy`, `IntegerOverflow`, `DelegatecallInjection`, `EcrecoverZero`,
`StorageCollision`, `DelegatecallTarget`, `UninitializedMemory`,
`UncheckedCall`, `TxOrigin`, `ArbitraryStorageWrite`, `Cheatcode`.

| Module | Purpose |
|-------|-------|
| `coverage.rs` | `Coverage`, `CoverageReport`, `dump_file` (writes `coverage.txt`) |
| `sha3_bypass.rs` | `Sha3TaintAnalysis`, `Sha3Bypass` |
| `reentrancy.rs` | `ReentrancyTracer` |
| `overflow.rs` | `IntegerOverflowTracer` |
| `delegatecall.rs` | `DelegatecallInjectionTracer` |
| `delegatecall_target.rs` | `DelegatecallTargetTracer` |
| `ecrecover.rs` | `EcrecoverZeroTracer` |
| `arbitrary_storage_write.rs` | `ArbitraryStorageWriteTracer` |
| `storage_collision.rs` | `StorageCollisionTracer` |
| `uninitialized_memory.rs` | `UninitializedMemoryTracer` |
| `unchecked_call.rs` | `UncheckedCallTracer` |
| `tx_origin.rs` | `TxOriginTracer` |
| `call_printer.rs` | `CallPrinter` (prints the trace) |
| `cheatcode/*` | Foundry cheatcode (currently **commented out** in `evm_fuzzer.rs`) |

---

## 10. `src/evm/concolic/*`

| Module | Purpose |
|-------|-------|
| `concolic_stage.rs` | `ConcolicStage` (a libafl Stage), `ConcolicFeedbackWrapper` |
| `concolic_host.rs` | `ConcolicHost`, `Solution`, `threaded_solve`, `ALL_WORKER_THREADS`, `ALL_SOLUTIONS` |
| `expr.rs` | symbolic expressions |
| `mod.rs` | module |

`ConcolicStage::perform`:
* logs `concolic: testcase #N (i/total) -- bounded pool of M Z3 solver(s)`;
* skips a testcase without input and a testcase with uninitialized staged state
  (`StagedVMState::new_uninitialized` → empty world state);
* during execution it sets `CONCOLIC_NO_CONTROL_LEAK = true`;
* uses `threaded_solve` with a bounded worker pool.

---

## 11. `src/fuzzer.rs` — ForkSploitFuzzer

* `ForkSploitFuzzer<...>` implements the libafl `Fuzzer`/`Evaluator`.
* `RUN_FOREVER: AtomicBool`, `ORACLE_OUTPUT: Mutex<Vec<serde_json::Value>>`.
* `vuln_file_base(bug_idxs)` — bounds the finding file name to 120 bytes + a
  stable hash, so that `--run-forever` does not cause "File name too long".
* `evaluate_input_events` — the core of the loop:
  * on `ExecuteInputResult::Solution`: minimization,
    `generate_test_with_full_trace`, writing `vuln_info.jsonl`,
    `vulnerabilities/<idxs>` and `<idxs>_replayable`;
  * without `--run-forever` → `exit(0)`; otherwise `ORACLE_OUTPUT.clear()` and
    continue.
* `add_input` — the libafl contract.
* Tests: `vuln_file_base_tests`.

---

## 12. `src/fuzzers/evm_fuzzer.rs` — campaign assembly

* `evm_fuzzer(config, state)` (see [DATA_FLOW.md](DATA_FLOW.md) §3).
* `exit(1)` if `fuzz_loop` returns an error.
* It builds `OracleFeedback` (objective), `ConcolicFeedbackWrapper`,
  `Sha3WrappedFeedback`, `CmpFeedback`, `DataflowFeedback`.
* `EVMMinimizer` and `SequentialMinimizer`.

---

## 13. `src/evm/solution/*` — plan.json and Solidity

| Symbol | Purpose |
|--------|-------|
| `init_cli_args(target, work_dir, onchain)` | sets the global `CLI_ARGS` |
| `generate_test` / `generate_test_with_full_trace` | writes `.t.sol` and the plan |
| `Tx` | one step (caller, contract, value, calldata, fn_selector, call_leak, ...) |
| `TemplateArgs` | data for the templates |
| `is_reentrancy_bug`, `split_reentrant_trace` | reentrancy splitting |
| `has_multiple_distinct_callers`, `trace_depends_on_control_leak` | qualifiers for `.s.sol` |
| `parse_bug_report`, `is_confirmed_bug_type`, `is_confirmed_exploitable_bug` | classification |
| `CONFIRMED_EXPLOITABLE_BUG_TYPES` | the list for an atomic `.s.sol` |
| `BUG_COUNTER` | a unique counter in the name |
| `foundry_test.hbs`, `foundry_script.hbs`, `foundry_script_reentrancy.hbs` | templates |

`src/evm/solution/script_generator.rs`:

| Symbol | Purpose |
|--------|-------|
| `PlanStep` | a plan step (contract, calldata, value, caller, fn_selector, stolen_asset, call_leak) |
| `PlanMeta` | plan metadata (see [PLAN_JSON.md](PLAN_JSON.md)) |
| `ExploitPlan` | the whole plan (contract_name, kind, needs_funding, total_value, steps, full_trace_steps, repeat_step, + meta) |
| `build_plan_meta` | builds the metadata |
| `generate_exploit_plan` | a plan with `kind="flat"` |
| `generate_reentrancy_exploit_plan` | a plan with `kind="reentrancy"` |
| `generate_script`, `generate_reentrancy_script` | `.s.sol` |
| `write_plan` | writes `{contract_name}.plan.json` |

`erc20_token_touched(tx)` determines the `stolen_asset` field.

Tests: `plan_meta_confidence_tests::control_leak_trace_is_never_sim_confirmed`,
`classify_confidence_matches_confirmed_exploitable_list`.

---

## 14. `src/evm/onchain/*`, `tokens/*`, `producers/*`, `presets/*`

### `src/evm/onchain/`
* `endpoints.rs`: `enum Chain` (24 networks + `local`), `from_str`, `to_lowercase`,
  `get_chain_id`, `get_chain_rpc` (reads `ETH_RPC_URL`),
  `get_chain_etherscan_base`, `OnChainConfig`, `RpcResponseError`,
  `is_blockscout_api`.
* `mod.rs`: the `ChainConfig` trait, the `OnChain` middleware, `BLACKLIST_ADDR`,
  `WHITELIST_ADDR`, `register_borrow_txn`.
* `flashloan.rs`: the `Flashloan` middleware.
* `offchain.rs`: `OffChainConfig`.
* `abi_decompiler.rs`: `fetch_abi_evmole` (EVMole decompilation).

### `src/evm/tokens/`
`mod.rs` (`SWAP_DEPOSIT`, `SWAP_WITHDRAW`, `BoxedABI` transformations),
`uniswap.rs`, `v2_transformer.rs`, `v3_transformer.rs`, `weth_transformer.rs`,
`aave_transformer.rs`, `balancer_transformer.rs`, `constant_pair.rs`,
`onchain_pair_discovery.rs`.

### `src/evm/producers/`
`erc20.rs` (`ERC20Producer`), `pair.rs`, `mod.rs` (the `Producer` trait in
`src/oracle.rs`).

### `src/evm/presets/`
`mod.rs`, `pair.rs` — presets for known vulnerabilities (feature `use_presets`).

### `src/evm/blaz/*`
The contract builder (`builder.rs`), `linking.rs`, `offchain_artifacts.rs`,
`offchain_config.rs`.

### `src/evm/srcmap/mod.rs`, `abi.rs`, `bytecode_analyzer.rs`,
`bytecode_iterator.rs`, `types.rs`, `utils.rs`, `cov_stage.rs`, `mutator.rs`,
`minimizer.rs`, `scheduler.rs`, `feedbacks.rs`, `multicore.rs`, `setup.rs`,
`auto_setup.rs`, `corpus_initializer.rs`, `input.rs`

| Module | Purpose |
|-------|-------|
| `abi.rs` | ABI parsing, `BoxedABI`, argument mutation |
| `bytecode_analyzer.rs`, `bytecode_iterator.rs` | bytecode analysis |
| `types.rs` | `EVMAddress`, `EVMU256`, `EVMFuzzState`, `EVMQueueExecutor` |
| `utils.rs` | `prettify_concise_inputs`, `parse_pretty_wei`, `try_write_file` |
| `cov_stage.rs` | `CoverageStage` (writing traces) |
| `mutator.rs` | `FuzzMutator` |
| `minimizer.rs` | `EVMMinimizer` |
| `scheduler.rs` | `PowerABIScheduler`, `PowerABIMutationalStage` |
| `feedbacks.rs` | `Sha3WrappedFeedback`, `Feedback` |
| `multicore.rs` | `run_supervisor`, `spawn_job`, `per_job_concolic_threads`, `clamp_jobs_to_cores`, `filter_overridden_flags`, `derive_job_seed` |
| `setup.rs` | `SetupSpec`, `SetupCall` (`setup.json`) |
| `auto_setup.rs` | `derive_setup_spec`, `scan_embedded_addresses` |
| `corpus_initializer.rs` | `EVMCorpusInitializer` |
| `input.rs` | `EVMInput`, `ConciseEVMInput`, `EVMInputTy`, `SolutionTx` |

---

## 15. Other root modules

| Module | Purpose |
|-------|-------|
| `src/oracle.rs` | the `Oracle`/`Producer` traits, `OracleCtx`, `BugMetadata` |
| `src/state.rs` | `FuzzState`, `HasCurrentInputIdx`, `InfantStateState` |
| `src/state_input.rs` | `StagedVMState` (`new_uninitialized`) |
| `src/input.rs` | `ConciseSerde`, `SolutionTx`, `VMInputT` |
| `src/feedback.rs` | `CmpFeedback`, `DataflowFeedback`, `OracleFeedback`, `CmpMetadata` |
| `src/scheduler.rs` | `SortedDroppingScheduler`, `HasReportCorpus` |
| `src/power_sched.rs` | the power scheduler |
| `src/minimizer.rs` | `SequentialMinimizer` |
| `src/mutation_utils.rs` | helpers for mutations |
| `src/executor.rs`, `src/tracer.rs`, `src/indexed_corpus.rs`, `src/cache.rs`, `src/logger.rs`, `src/sync_utils.rs` | infrastructure |
| `src/generic_vm/*` | the generic VM abstraction |

`src/sync_utils.rs`: `RacyCell` — process-global maps that are sound only under
a single-threaded assumption; that is why `--jobs` uses **processes**, not
threads.

---

## 16. Module dependency diagram

```mermaid
graph TD
    main[src/main.rs] --> mod[evm/mod.rs::evm_main]
    mod --> cu[evm/contract_utils.rs]
    mod --> as[evm/auto_setup.rs]
    mod --> ef[fuzzers/evm_fuzzer.rs]
    cu --> ep[evm/onchain/endpoints.rs]
    ef --> host[evm/host.rs]
    ef --> ci[evm/corpus_initializer.rs]
    ef --> orc[evm/oracles/*]
    ef --> con[evm/concolic/*]
    ef --> fz[fuzzer.rs]
    ef --> cov[evm/middlewares/coverage.rs]
    orc --> ora[evm/oracle.rs]
    fz --> sol[evm/solution/mod.rs]
    sol --> sg[evm/solution/script_generator.rs]
    sg --> host
    con --> host
    orc --> host
    ef --> vm[evm/vm.rs]
    vm --> revm[revm]
    mod --> cfg[evm/config.rs]
    cfg --> oracle_trait[oracle.rs]
```

---

## 17. Open / unmeasured

* **Unverified:** whether `--onchain-builder` (`BuildJob`) actually works on all
  chains — the code supports it (`blaz/builder.rs`), but this document has not
  run it.
* **Unmeasured:** performance (`exec/s`, reach depth) is not part of this
  document.
* The cheatcode middleware (`middlewares/cheatcode/*`) exists in the code, but
  is **commented out** in `src/fuzzers/evm_fuzzer.rs` (TODO: zksync-era#4581).
  Therefore `Cheatcode` is not active in the default campaign.
* `src/evm/mod.rs::test_evm_offchain_setup` is a manual harness (the `#[test]`
  is commented out), not part of the default tests.
