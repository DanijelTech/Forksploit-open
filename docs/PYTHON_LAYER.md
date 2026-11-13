# PYTHON LAYER — the execution layer module by module

> Standalone document. Related: [ARCHITECTURE.md](ARCHITECTURE.md),
> [RUST_PYTHON_WIRING.md](RUST_PYTHON_WIRING.md),
> [ATTACKWALLET.md](ATTACKWALLET.md), [DATA_FLOW.md](DATA_FLOW.md).

All paths are under `onchain_scripts/`. Every claim is verified in code.

---

## 1. Module overview

```
onchain_scripts/
├── auto_pipeline.py          orchestration of one target (3108 lines)
├── batch_pipeline.py         the same flow for many targets (464)
├── strategy_layer.py         reading/merging plans (592)
├── chains.py                 chains, RPC, identity (485)
├── wallet_policy.py          wallet locking (322)
├── gas_utils.py              gas: limits, budget (484)
├── gas_oracle.py             official gas-price oracle (483)
├── proxy_resolver.py         proxy expansion (217)
├── flashbots_bundle.py       atomic bundle (162)
├── monitor.py                post-deploy surface monitoring (478)
├── dashboard_server.py       GUI server (552)
├── materialize_plan.py       materialization worklist (425)
├── triage_findings.py        sorting by surface (273)
├── dex_arbitrage_scanner.py  DEX arbitrage scanner (671)
├── aave_flashloan_runner.py  flashloan validation (281)
├── gen_chain_fixture.py      chain fixture generator (95)
├── deploy_sepolia_demo.py    deploy demo contracts (118)
├── evaluate.py               bulk evaluation (63)
├── immunefi.py, debug_file_generator.py   helper tools
├── server_run.sh             GUI launch (186)
├── contracts/AttackWallet.sol   the on-chain primitive (346)
├── contracts/proof_w1_w2_w3.sh  proof script
├── dashboard_static/         index.html, app.js, style.css
└── test_*.py                 22 test files
```

---

## 2. `auto_pipeline.py`

### Purpose
Register → fund → fuzz → exploit → recover for **one** target. Everything except
the target identifier and the recovery wallet runs without further input.

### Key functions

| Symbol | Purpose | Input | Output |
|--------|-------|------|-------|
| `main()` | the whole flow | CLI | `int` (exit code) |
| `build_parser()` | CLI parser (introspection for the dashboard) | — | `ArgumentParser` |
| `run_fuzzer(target_address, chain, detectors, fuzz_seconds, work_dir, tee, extra_targets)` | launches the Rust binary | addresses, chain | `float` (actual seconds) |
| `execute_plan(w3, acct, nonce_box, attack_wallet, plan, recovery_wallet, tee, chain, return_units)` | executes a plan through AttackWallet | plan | 4/5-tuple of statuses |
| `gated_execute_plan(...)` | `execute_plan` behind the pre-flight gate | plan | 5-tuple |
| `preflight_skip_reason(...)` | the full pre-flight gate | finding | `str \| None` |
| `metadata_skip_reason(finding)` | layer 1 (no network) | finding | `str \| None` |
| `gas_oversized_reason(plan)` | the gas gate | plan | `str \| None` |
| `simulate_plan_on_fork(...)` | layer 2 (anvil fork) | plan | `(delta, gas, reverted, tokens) \| None` |
| `estimate_plan_gas_on_fork(...)` | gas measurement | plan | `dict \| None` |
| `_start_fork(chain, tee)` | starts an anvil fork | chain | `(proc, w3)` |
| `get_or_deploy_attack_wallet(...)` | once per chain | chain | address |
| `send_call(...)` | signs+sends a tx | — | `bool` |
| `deploy(...)`, `compile_contract(...)` | deploy/compile | — | address / bytecode |
| `build_proof(...)` | structured proof | signals | `Proof` |
| `is_chain_verified(status, delta)` | the highest level | — | `bool` |
| `determine_negative_result_verdict(...)` | "no findings" assessment | coverage | `str` |
| `report_unexecuted_findings`, `report_surface_triage`, `report_coverage`, `report_materialization` | reports | — | — |
| `run_static_analysis(sol_path, tee)` | Slither | — | — |
| `parse_pretty_wei`, `selector`, `encode_address`, `encode_uint256` | helpers | — | — |
| `attack_wallet_*_calldata(...)` | calldata construction | — | `bytes` |
| `revert_reason`, `first_failing_step_index`, `erc20_balance_of`, `aave_flashloan_premium_bps` | diagnostics | — | — |

### Dependencies (imports)
`chains`, `flashbots_bundle`, `proxy_resolver`, `gas_utils`, `wallet_policy`,
`strategy_layer`, `eth_abi`, `eth_account`, `web3`.

### Constants (from the code)

| Constant | Value | Meaning |
|-----------|----------|-------|
| `FLASHBOTS_THRESHOLD_ETH` | `10.0` | above this an atomic bundle is used |
| `BUNDLE_GAS_LIMIT` | `2_000_000` | fixed gas limit in the bundle |
| `BUNDLE_BUILDER_TIP_BPS` | `400` | 4% tip to the builder |
| `GAS_BUDGET_MARGIN` | `1.10` | budget margin |
| `REPLACEMENT_FEE_BUMP` | `1.15` | fee bump on replacement |
| `REPLACEMENT_MAX_ATTEMPTS` | `3` | replacement attempts |
| `FORK_SIM_ENABLED_DEFAULT` | `True` | pre-flight on by default |
| `FORK_SIM_PORT` | `18545` | anvil fork port |
| `FORK_SIM_ETC_HARDFORK` | `"shanghai"` | hardfork for ETC |
| `FORK_SIM_STARTUP_TIMEOUT_S` | `20.0` | waiting for anvil |
| `MIN_COVERAGE_PCT_FOR_NEGATIVE_RESULT` | `80.0` | threshold for "no findings" |
| `MIN_FUZZ_SECONDS_FOR_NEGATIVE_RESULT` | `300` | time threshold |
| `PRIVACY_REDIRECT_RPC` | `{"bsc": {...}}` | private mempool for BSC |

Statuses: `PLAN_CONFIRMED`, `PLAN_NOT_CONFIRMED`, `PLAN_INCONCLUSIVE`,
`PLAN_EXECUTED_NO_PROFIT`, `PLAN_SKIPPED_UNPROFITABLE`,
`PLAN_SKIPPED_NOT_EXTRACTABLE`, `PLAN_OVERSIZED_GAS` (see
[RUST_PYTHON_WIRING.md](RUST_PYTHON_WIRING.md) §8).
"No findings" verdicts: `SCAN_NO_BUG_BOUNDED`, `SCAN_INSUFFICIENT_COVERAGE`.

### Write-back
`main` rewrites `plan.json` with `gas_estimate`, `fits_block_gas_limit`,
`gas_headroom_pct`, `block_gas_limit` (after the fork) and `gas_used` (after
execution).

### Contact with the other layer
`run_fuzzer` is the only point of contact with the Rust binary (Popen +
`ETH_RPC_URL`).

---

## 3. `batch_pipeline.py`

* `main` reads the `--targets` file once, checks the wallet once
  (`enforce_wallet_policy`), then for each target `run_one_target`.
* An error on one target does not break the series (except a wallet-policy
  error).
* It reuses functions from `auto_pipeline` (imported at the top).
* Arguments: `--targets`, `--recovery-wallet`, `--key`, `--chain`,
  `--confirm-mainnet`, `--fund-eth`, `--fuzz-seconds`, `--detectors`,
  `--no-preflight`, `--no-gas-oracle`.

---

## 4. `strategy_layer.py`

### Purpose
Order the findings and compose one coherent, executable plan from many
independent plans.

### Key structures

| Symbol | Meaning |
|--------|-------|
| `UNLOCK_BUG_TYPES` | `frozenset` of bug types that grant capability (do not move funds) |
| `OBJECTIVE_BUG_TYPES` | `frozenset` of bug types that already mean a movement of funds |
| `_CONFIRMED_BUG_TYPE_RE` | regex for reading `.t.sol` as a fallback |
| `_APPROVE_SELECTORS` | `{0x095ea7b3, 0xa22cb465}` |
| `_TRANSFER_FROM_SELECTORS` | `{0x23b872dd}` |
| `_DEPOSIT_SELECTORS` | `{0xd0e30db0}` |
| `_WITHDRAW_SELECTORS` | `{0x2e1a7d4d, 0xba087652}` |

### Key functions

| Symbol | Purpose |
|--------|-------|
| `load_findings(work_dir)` | reads `*.plan.json` + metadata |
| `ordering_key(finding)` | orders unlock → ambiguous → objective → unclassified |
| `_steps_of(finding)` | `full_trace_steps` before `steps` |
| `_is_chainable(finding)` | `atomic_replayable` and `kind` in `("flat","reentrancy")` |
| `_dedup_steps(steps)` | removes duplicate steps |
| `order_steps_by_dependencies(steps)` | a stable topological order (approve→transferFrom, deposit→withdraw) |
| `_thread_address_arguments(steps, composed_caller)` | rewrites `from` in `transferFrom` to the composed caller |
| `compose_plan(findings, composed_caller)` | composes one plan |
| `build_composition_candidates(findings, max_attempts)` | candidate groups |
| `run_chain_attempts(execute_plan_fn, ...)` | executes the composed plans |

### Output
`compose_plan` returns a dictionary with the same schema `execute_plan`
expects: `contract_name`, `kind`, `needs_funding`, `total_value`, `steps`,
`repeat_step`, `composed_from`, `confirmed_exploitable`.

### Contact with the other layer
It reads `plan.json` (Rust output). It does not import `auto_pipeline` (to avoid
a circular import); it receives `execute_plan_fn` as a parameter.

---

## 5. `chains.py`

### Purpose
The single source for chains/RPC/identity.

### Key data

| Symbol | Meaning |
|--------|-------|
| `DEFAULT_RPC` | default RPC per chain (21 entries) |
| `TESTNET_CHAINS` | `{"sepolia", "chapel", "mordor"}` |
| `CHAIN_IDS` | name → chain id (including `local: 31337`) |
| `AAVE_V3_POOLS` | chain → Aave V3 Pool |
| `WETH_ADDRESSES` | chain → WETH (`eth`, `sepolia`) |
| `CHAIN_TITLES` | short names for the menu |
| `NATIVE_SYMBOL` | ticker (ETH/ETC/BNB/...) |
| `OVERRIDES_FILE` | `rpc_overrides.json` |

### Key functions

| Symbol | Purpose |
|--------|-------|
| `verify_rpc_identity(chain, tee, w3)` | reads the real `eth_chainId`, compares |
| `require_mainnet_confirmation(chain, confirmed, tee)` | `SystemExit` without `--confirm-mainnet` |
| `NetworkProfile` | `chain`, `chain_id`, `family`, `is_testnet`, `native_symbol`, `supports_flashbots` |
| `network_profile_for_chain_name`, `_profile_from_id`, `network_family`, `chain_name_for_id` | profiles |
| `native_symbol`, `native_symbol_for_w3` | labels |
| `chain_banner`, `chain_title` | display |
| `known_chains()`, `get_rpc_url(chain)`, `make_w3(chain)`, `set_rpc_override`, `clear_rpc_override` | RPC management |

`make_w3` always injects `ExtraDataToPOAMiddleware` (for POA chains).

### Contact with the other layer
The Rust binary gets the RPC via `ETH_RPC_URL`, which `run_fuzzer` sets from
`get_rpc_url(chain)`. The Rust side has its own table
(`src/evm/onchain/endpoints.rs::Chain::get_chain_rpc`), but reads `ETH_RPC_URL`
unconditionally.

---

## 6. `wallet_policy.py`

### Purpose
Strict locking of wallet roles per chain.

### Structures
* `WALLETS_FILE` = `wallets.json`: exactly one funding + one recovery per chain.
* `CONTRACTS_FILE` = `contracts.json`: a log of all contracts.
* `_FILE_LOCK`: a `threading.Lock` for read-modify-write.

### Key functions

| Symbol | Purpose |
|--------|-------|
| `load_policy(chain)` | reads the policy |
| `register_policy(chain, confirm_chain, funding_wallet, recovery_wallet, force, client_note)` | writes the policy |
| `enforce_wallet_policy(chain, signer_address, recovery_or_safe_wallet)` | `SystemExit` on a mismatch |
| `register_contract(chain, address, source, run_id, script, funding_wallet, recovery_wallet)` | adds a record |
| `_cmd_register`, `_cmd_show`, `_cmd_contracts`, `main` | CLI |

`register_policy` requires `--confirm-chain`, which must equal `--chain`
(anti-typo, because `eth` and `etc` are one letter apart).

### Contact with the other layer
`auto_pipeline.main` and `monitor.watch_target` call `enforce_wallet_policy`
**before** every signature.

---

## 7. `gas_utils.py`

| Symbol | Purpose |
|--------|-------|
| `DEFAULT_GAS_LIMIT_MARGIN` = `0.10` | margin |
| `MAX_GAS_LIMIT` = `8_000_000` | hard gas limit per tx |
| `BASE_FEE_LOOKAHEAD_BLOCKS` = `2` | maxFeePerGas protection |
| `GasExceedsBlockLimitError` | exception |
| `estimate_gas_limit(w3, tx, margin)` | a precise limit + cross-check |
| `get_fee_fields(w3, lookahead_blocks, chain, use_official)` | fee fields |
| `tx_worst_case_price(tx)` | worst-case price |
| `build_precise_tx(...)` | builds a tx |
| `describe_actual_cost(w3, receipt)` | cost description |
| `GasBudgetExceeded`, `GasBudget` | budget |
| `GasLedger` | a spending ledger |
| `net_profit_wei(gross, gas)`, `format_wei_signed(w3, wei)` | compute/format |
| `gas_fit(gas_estimate, block_gas_limit, margin)` | `{gas_estimate, gas_limit_with_margin, block_gas_limit, fits_block_gas_limit, gas_headroom_pct}` |

---

## 8. `gas_oracle.py`

| Symbol | Purpose |
|--------|-------|
| `BLOCKSCOUT_CHAINS` | `{"etc": ..., "mordor": ...}` |
| `ETHERSCAN_V2_URL` | `https://api.etherscan.io/v2/api` |
| `DEFAULT_TIMEOUT` = `12`, `DEFAULT_TTL_SECONDS` = `12`, `DEFAULT_LOOKAHEAD_BLOCKS` = `2` | — |
| `ENABLED`, `set_enabled(value)` | the switch (`--no-gas-oracle`) |
| `GasQuote` | a quote |
| `etherscan_v2_gas_oracle(...)`, `blockscout_v2_gas_prices(...)`, `fetch_official_gas_quote(...)` | fetching |
| `compute_fee_fields(...)`, `resolve_fee_fields(w3, chain, ...)` | computation |
| `verify_gas_oracles(...)`, `main` | verification/CLI |

Best-effort: every error of the official source degrades to the node's quote.

---

## 9. `proxy_resolver.py`

| Symbol | Purpose |
|--------|-------|
| `_slot(definition, minus_one)` | computes a slot from keccak |
| `BEACON_IMPLEMENTATION_SELECTOR` | `keccak("implementation()")[:4]` |
| `_address_from_word(word)` | parses a 32-byte word into an address |
| `minimal_proxy_implementation(code_hex)` | EIP-1167 |
| `eip7702_delegate(code_hex)` | EIP-7702 |
| `_read_slot_address(w3, address, slot)` | reads a slot |
| `_call_implementation(w3, beacon, selector)` | calls the beacon |
| `discover_implementations(w3, address)` | a list of implementations |
| `resolve_proxy_chain(w3, address, max_hops)` | a dictionary `{is_proxy, implementations, depth}` |

The slot constants are derived from keccak and cross-checked with the Rust
literals in `test_proxy_resolver.py`.

---

## 10. `flashbots_bundle.py`

| Symbol | Purpose |
|--------|-------|
| `RELAY_URLS` | `{"eth": "https://relay.flashbots.net", "sepolia": "https://relay-sepolia.flashbots.net"}` |
| `sign_request(acct, payload)` | signs per the spec |
| `_post(relay_url, acct, payload)` | POST |
| `call_bundle(relay_url, acct, raw_txs, target_block, state_block)` | `eth_callBundle` |
| `send_bundle(relay_url, acct, raw_txs, target_block)` | `eth_sendBundle` |
| `submit_bundle_and_wait(...)` | waits for inclusion |

Flashbots covers **only** ETH mainnet + sepolia (see `RELAY_URLS`).

---

## 11. `contracts/AttackWallet.sol`

Detailed in [ATTACKWALLET.md](ATTACKWALLET.md).

---

## 12. `dashboard_server.py` and `dashboard_static/`

* A FastAPI application, `uvicorn.run(app, host="127.0.0.1", port=args.port)`,
  default port `4114` (`main`).
* Endpoints: `GET /api/actions`, `GET /api/verify-chain`, `GET /api/state`,
  `POST /api/run`, `POST /api/run/{id}/input`, `POST /api/run/{id}/stop`,
  `WS /api/run/{id}/stream`, `POST /api/rpc-override`,
  `DELETE /api/rpc-override/{chain}`, `POST /api/wallet-policy`.
* `/api/state` returns `wallets`, `rpc_overrides`, `contracts`, `attack_wallets`,
  `recent_logs`, `vulnerabilities_found`, `dashboard_runs`,
  `external_processes`.
* `dashboard_static/index.html` has a sidebar with three groups
  (`Management`, `Settings and configuration`, `Results`) and views:
  `overview`, `run`, `runs`, `console`, `wallet`, `rpc`, `contracts`,
  `findings`, `logs`, `processes`.

---

## 13. `monitor.py`

| Symbol | Purpose |
|--------|-------|
| `watch_target(chain, address, args, acct, nonce_locks, stop_event)` | monitors one target |
| `attempt_rescue(trigger, current_balance)` | rescue attempt |
| `rescan(reason)` | periodic re-fuzzing |
| `build_parser()`, `main` | CLI |
| `_load_targets(args)` | reads `--config` |

Flags: `--address`, `--chain`, `--config`, `--poll-interval`,
`--balance-drop-pct`, `--large-tx-eth`, `--rescan-interval`, `--rescan-seconds`,
`--rescan-detectors`, `--key`, `--safe-wallet`, `--confirm-mainnet`.

Automatic rescue requires `--key` **and** `--safe-wallet`; otherwise monitoring
is read-only.

---

## 14. `triage_findings.py`, `materialize_plan.py`

* `triage_findings`: `surface_key`, `classify`, `triage`, levels
  `RUNNABLE`, `NEEDS_MATERIALIZATION`, `NEEDS_MULTI_SENDER`,
  `AMOUNT_UNREALISTIC`, `HEURISTIC_ONLY`.
* `materialize_plan`: `classify_selector`, `leaked_steps`,
  `is_callback_leak`, `worklist`, `RECIPES` (a mapping from a selector class to a
  recipe), `SELECTOR_CLASS`.

---

## 15. `dex_arbitrage_scanner.py`, `aave_flashloan_runner.py`,
`gen_chain_fixture.py`, `deploy_sepolia_demo.py`, `evaluate.py`,
`immunefi.py`, `debug_file_generator.py`

* `dex_arbitrage_scanner`: `get_pair`, `get_reserves`, `find_optimal_arbitrage`,
  `check_once`, `ask_human_confirmation` — it warns (does not execute
  automatically).
* `aave_flashloan_runner`: flashloan validation on `--chain`.
* `gen_chain_fixture`: generates an N-step chain fixture.
* `deploy_sepolia_demo`: deploys demo contracts on Sepolia.
* `evaluate`, `immunefi`, `debug_file_generator`: helper/legacy tools.

---

## 16. `server_run.sh`

The GUI launch. Bound to `127.0.0.1`; it picks the next free port if `4114` is
taken by a **foreign** service; it reuses `4114` if **our** dashboard already
runs there; it waits until the server accepts connections, then opens the
browser.

---

## 17. Python module dependency diagram

```mermaid
graph TD
    ap[auto_pipeline.py] --> chains
    ap --> wp[wallet_policy.py]
    ap --> gu[gas_utils.py]
    ap --> go[gas_oracle.py]
    ap --> pr[proxy_resolver.py]
    ap --> fb[flashbots_bundle.py]
    ap --> sl[strategy_layer.py]
    bp[batch_pipeline.py] --> ap
    bp --> chains
    bp --> wp
    bp --> sl
    mon[monitor.py] --> chains
    mon --> wp
    mon --> gu
    ds[dashboard_server.py] --> ap
    ds --> chains
    ds --> wp
    gu --> chains
    sl -.reads plan.json.-> fs[(work_dir)]
    ap -.Popen.-> rust[Rust binary]
    fb --> chains
```

---

## 18. Open / unmeasured

* **Unverified:** whether `dashboard_static/app.js` covers all views —
  `test_dashboard_ui.py` checks this, but this document does not repeat the
  result.
* **Unmeasured:** the number of tests (232 passed in a `requirements`-full
  environment) is not part of this document; see [TESTS.md](TESTS.md).
* `evaluate.py`, `immunefi.py`, `debug_file_generator.py` are helper tools;
  their exact usage is not documented in the code outside docstrings.
