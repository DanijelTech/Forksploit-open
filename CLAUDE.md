# CLAUDE.md

Guidance for AI coding agents (Claude Code and others) working in this
repository. Every factual claim here was verified against the source in this
repo. Where a number is measured, the command that produced it is given.

> **Working rule R1 (non-negotiable):** never write "done" / "works" / "fixed"
> without a reproducible proof (a test, a measurement, or command output).
> Anything not measured is labelled **unmeasured**.

---

## What this project is

ForkSploit is a two-layer system for EVM smart contracts:

1. **Rust core** (`src/`) — a bytecode-level, coverage-guided fuzzer with
   concolic (Z3) solving on top of `revm`, plus **47 oracle modules** that
   detect attack surfaces and, on a hit, emit a structured, replayable
   `*.plan.json`. The Rust side **never signs or sends anything**.
2. **Python orchestration** (`onchain_scripts/`) — reads every plan, merges
   them into one ordered multi-step plan, executes it through a single
   reusable `AttackWallet` contract (deploy + real calls, Aave V3 flashloan
   when needed), and sweeps recovered funds to a locked recovery wallet.

The product is the **proof**: only a plan whose execution measurably increases
the recovery wallet's real balance is reported as `CONFIRMED`. It is EVM-only
(no MoveVM/Sui), has no telemetry, and intentionally has no hand-written
invariant oracle beyond the declarative one (see below).

---

## Build & test

Rust is pinned by `rust-toolchain.toml` to **`nightly-2026-10-15`** (install
with `rustup toolchain install`; it reads the file). `z3-sys` links the
**system** Z3, so install `libz3-dev` + `pkg-config` first, or the build will
try (and often fail) to compile Z3 from source.

```bash
# Prerequisites (Debian/Ubuntu)
sudo apt-get install -y libz3-dev pkg-config clang cmake build-essential

# Build (0 project warnings expected)
cargo build --release

# Rust tests. 10 tests require live public RPC / a pinned live balance and
# fail EVEN WITH network access (measured) -- skip them, do not "fix" them:
cargo test --release -- \
  --skip onchain_pair_discovery \
  --skip uniswap::tests::test_get_pair \
  --skip uniswap::tests::test_fetch_uniswap_path \
  --skip endpoints::tests::test_get_balance
# -> 139 passed, 0 failed

# Python tests (offline; no anvil/solc needed)
cd onchain_scripts && python -m pytest -q          # -> 232 passed

# W1-W3 proof against a throwaway anvil (needs anvil + cast + solc)
bash onchain_scripts/contracts/proof_w1_w2_w3.sh   # -> 7 passed, 0 failed

# Integration tests
python3 integration_test.py offchain               # no RPC
python3 integration_test.py onchain                # needs RPC + Etherscan key
```

`forksploit.sh --doctor` prints the full environment checklist and exits 0
even when the optional `anvil`/`solc` are absent.

CI is `.github/workflows/ci.yml` (GitHub-hosted `ubuntu-22.04`, free): it runs
exactly the two green gates above. `cargo fmt --check` and `cargo clippy` are
**not** gates — the tree is not rustfmt-clean and clippy has pre-existing
warnings; both would be red and are out of scope for that workflow.

---

## Architecture

### Generic VM abstraction
- `src/generic_vm/` — `vm_executor.rs`, `vm_state.rs`: traits any VM implements.
- `src/evm/` — the EVM implementation (the whole project; MoveVM was removed).

### EVM core
- `src/evm/vm.rs` — execution engine on `revm`.
- `src/evm/host.rs` — host environment; also holds the control-leak machinery
  (`call_allow_control_leak` / `call_forbid_control_leak`) and the
  `MAX_ANALYSIS_CALL_DEPTH` static (default **15**).
- `src/evm/input.rs` — one transaction (`EVMInput`: caller, target, calldata,
  value). Multi-step behaviour arises across the **corpus genealogy**
  (`TxnTrace::from_idx`), not from one multi-tx input.
- `src/evm/contract_utils.rs` — deployment/init and **proxy expansion**
  (`from_fork` AND `from_address` both walk EIP-1967 impl/beacon, EIP-1822
  UUPS, EIP-1167 minimal proxy, EIP-7702 `0xef0100 || delegate`).

### Middlewares (`src/evm/middlewares/`) — run per opcode
`coverage.rs` (instruction coverage), `cheatcode/` (Foundry cheatcodes for
setup scripts), `reentrancy.rs`, `sha3_bypass.rs` (symbolic SHA3, `--sha3-bypass`),
`overflow.rs`, `unchecked_call.rs`, `delegatecall.rs`, `delegatecall_target.rs`,
`ecrecover.rs`, `tx_origin.rs`, `storage_collision.rs`,
`arbitrary_storage_write.rs`, `uninitialized_memory.rs`, `call_printer.rs`.

### Oracles (`src/evm/oracles/`) — 47 detection modules
The full list and grouping is in the README's "Napadalne površine" section.
Each `EVMBugResult` carries a replayable trace (`ConciseEVMInput`) and a
confidence tier (see below). Registration/selection lives in
`OracleType::from_strs` (`src/evm/mod.rs`); the `all` list has **47 entries**.

### Confidence tiers (`src/evm/oracle.rs`)
- `Confirmed` → printed as **`sim-confirmed`** — a directly observed violation
  (an unauthorized call that actually succeeded, a slot that actually
  collided, a signature that actually replayed).
- `Review` → **`sim-review`** — a heuristic with a known false-positive risk.
- The `sim-` prefix is deliberate: this tier is a **simulation** judgment, and
  it must never be confused with the Python layer's real on-chain `CONFIRMED`.
- `effective_confidence` downgrades a Confirmed finding to Review when the
  trace depended on control leak (`call_leak != u32::MAX`), so a
  `sim-confirmed` finding can never rest on a faked call return.

### Control leak
When execution yields control to the caller mid-transaction, ForkSploit saves
the post-execution state so reentrancy can be fuzzed. Control leak is a
deliberate search aid; it is disabled during concolic search
(`CONCOLIC_NO_CONTROL_LEAK`) and its traces are never presented as
`sim-confirmed`.

### Onchain support (`src/evm/onchain/`)
- `endpoints.rs` — chain config, RPC endpoints, and `Chain::from_str` with
  **25 chains**. ETC (id 61) has no Etherscan coverage; ABI fetching routes
  through Blockscout. revm has no ETC `SpecId`; `Shanghai` is the closest real
  match (ETC skipped the Merge EIPs, so `DIFFICULTY` stays PoW — a documented,
  narrow gap the binary warns about).
- Aave/Balancer do not exist on ETC (verified) — flashloan borrowing there is
  unavailable because there is no protocol, not because it is unimplemented.
- `tokens/onchain_pair_discovery.rs` — the ONLY pair-discovery mechanism:
  direct on-chain Uniswap-V2-style discovery (`getPair`/`token0`/`getReserves`
  via real `eth_call`). `KNOWN_V2_FACTORIES` covers **6 chains**: ETC, ETH,
  BSC, Polygon, Arbitrum, Celo — each with a live-verified factory and a
  regression test. Single-hop only.

### Execution flow
1. Parse args (`EvmArgs`, `src/evm/mod.rs`); load contracts (`ContractLoader`);
   extract constants (`bytecode_analyzer.rs`); seed the corpus.
2. Fuzz loop (LibAFL): input → REVM → reverted (discard) / control leak (save
   state) / success (run producers then oracles).
3. Feedback (`src/feedback.rs`): coverage, comparison (CMP), state comparison.
4. Scheduling (`src/scheduler.rs`, `src/power_sched.rs`).
5. On a hit, emit `*.t.sol` reproduction + `*.plan.json` (`src/evm/solution/`).

---

## Feature flags

Default: `cmp`, `dataflow`, `evm`, `print_txn_corpus`, `full_trace`,
`force_cache`, `real_balance`. Notable non-default: `evaluation`,
`ondisk_corpus`, `deployer_is_attacker`, `fuzz_static`, `print_logs`,
`z3_debug`, `flashloan_debug`, `no_etherscan`.

Key CLI flags (always compiled in):
- `--run-forever` — don't stop at the first bug; `auto_pipeline.run_fuzzer()`
  always passes it, so one run can find several independent bugs.
- `--max-call-depth` (default **32**) — how deep sha3-bypass taint analysis and
  concolic solving keep analysing (`MAX_ANALYSIS_CALL_DEPTH`, `host.rs`).
- `--detectors` (default **`all`**) — `high_confidence` is the old,
  noise-reduced preset; the default was widened because silently narrowing the
  search made "no bug found" read as "no bug exists".
- `--concolic`, `--concolic-caller`, `--concolic-timeout`,
  `--concolic-memory-mb`, `--concolic-num-threads`.
- `--invariants <file.json>` — declarative invariant oracle.
- `--auto-setup` — derive `setX(address)` wiring preconditions.
- `--jobs N` — process-isolated parallel fuzzing (clamped to core count).

---

## External dependencies (pinned)
- `revm` — fork `forksploit/revm` @ `1dead51`, `no_gas_measuring` (the model
  does **not** meter gas; the authoritative gas number is the node's
  `eth_estimateGas`).
- `libafl` / `libafl_bolts` — exactly `0.11.2`.
- `z3` / `z3-sys` — SMT solving; links system Z3.
- `alloy-*` — ABI/solc type handling.
- `handlebars` — renders the `.t.sol` / `.s.sol` templates.

---

## Notes an agent must not get wrong

- **Gas is not metered in the model.** Never claim the fuzzer measured gas;
  it did not. Gas reality comes from the Python layer's `eth_estimateGas` +
  `block.gasLimit`.
- **`--jobs` is process isolation, not threads.** `EVMFuzzState` is not `Send`
  and the coverage/cmp maps are process-global `RacyCell`s sound only under a
  single-threaded assumption. The one place OS threads are used is the
  concolic worker pool, which never touches a `RacyCell`.
- **The 10 network tests are the baseline.** They fail in any sandbox and also
  with egress; a *different* failure is a regression.
- **Git version is embedded at build time** (`src/build.rs`); `forksploit
  --version` prints the commit it was built from, so a stale binary is
  detectable.
- **`/cache` is populated from GitHub releases** for integration tests.
- External-data hardening (FAZA 6.1): panic-prone `.unwrap()`/`.expect()` on
  external input (RPC, solc/forge artifacts, ABIs, storage, presets) is
  converted to typed `Result`s / safe defaults across
  `onchain/endpoints.rs`, `blaz/offchain_artifacts.rs`, `blaz/linking.rs`,
  `contract_utils.rs`, `corpus_initializer.rs`, `abi.rs`, `presets/mod.rs`,
  `tokens/uniswap.rs`. Remaining `.unwrap()`s are `.parse().unwrap()` on
  static literals, `lock().unwrap()`, or inside `#[cfg(test)]`. Global state
  uses `Atomic*`/`Mutex`/`RacyCell` (`src/sync_utils.rs`).

---

## Onchain Python layer — behaviours to know

- **Gas-fee pricing** (`onchain_scripts/gas_oracle.py`): reads the market price
  from the chain's official explorer (Etherscan v2 for ETH, Blockscout v2 for
  ETC) and feeds `gas_utils.get_fee_fields()`. On ETC (no EIP-1559) a padded
  quote is paid in full, so this matters most there. Any official-source
  failure degrades to the node quote. On by default; `--no-gas-oracle` forces
  the node-only path.
- **Net profit** (`gas_utils.GasLedger`): every tx's `gasUsed *
  effectiveGasPrice` from the real receipt. `execute_plan()` returns
  `(status, recovery_delta_wei, gas_spent_wei, net_profit_wei)`;
  `net_profit_wei` can be negative and is reported as a loss, never rounded up.
- **Pre-flight profitability gate** (default ON): `metadata_skip_reason()`
  (no network) then `simulate_plan_on_fork()` (throwaway Anvil fork of the
  same node state, `--hardfork shanghai` on ETC/Mordor). Two distinct skip
  statuses: `skipped_unprofitable` and `skipped_not_extractable`. Missing
  `anvil` degrades to "attempt it"; `--no-preflight` bypasses the whole gate.
- **Surface triage** (`triage_findings.py`) and **materialization worklist**
  (`materialize_plan.py`) are offline analyses of what is already on disk.
- **Wallet policy** (`wallet_policy.py`) is enforced before any signing.

Tests: `test_gas_oracle.py`, `test_gas_ledger.py`, `test_execute_plan_net.py`,
`test_preflight_gate.py`, `test_triage_findings.py`, `test_materialize_plan.py`
— all offline.
