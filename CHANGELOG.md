# Changelog

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it. See [`DISCLAIMER.md`](DISCLAIMER.md).**

All notable changes to ForkSploit are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.1] — the open-source release

The first public, open-source tag of ForkSploit, published to invite the
community to help build one shared platform. This tag marks the project as
**open source** (multi-licensed per component — see `LICENSING.md`) and ships
the complete, documented platform.

The full release announcement, the list of capabilities, the call for
contributors and the honest list of known weak points are in
[`RELEASE_NOTES_v0.0.1.md`](RELEASE_NOTES_v0.0.1.md).

### Added

- **Open-source licensing model** — multi-licensed per component: Rust core
  `AGPL-3.0-or-later`, Python layer `Apache-2.0`, on-chain primitives
  Proprietary, dashboard `MIT`, documentation `CC-BY-4.0`. Texts in `LICENSES/`,
  map in `LICENSING.md` and `REUSE.toml`.
- **`DISCLAIMER.md`** — a prominent "use at your own risk / the authors accept
  no liability" notice, added across the `.md` documentation.
- **`RELEASE_NOTES_v0.0.1.md`** — the full open-source release announcement.

### Notes

- This is an early milestone (`0.0.1`): the engine and the proof pipeline are
  real and live-verified, while the search remains narrow and the platform is
  under active development. See `LIMITATIONS.md` and `BLOCKERS.md`.

---

## [Unreleased]

### Added

- **`forksploit.sh`: "Napredne nastavitve" (main menu 5)** — persisted
  advanced run settings (`onchain_scripts/forksploit_settings.json`,
  gitignored, no secrets): `--fuzz-seconds`, `--detectors`, `--fund-eth`,
  `--no-preflight`, `--no-gas-oracle`. Each maps 1:1 onto a real
  `auto_pipeline.py`/`batch_pipeline.py` flag; with none set, the built
  command is byte-identical to before.
- **`forksploit.sh`: "Orodja" (main menu 6)** — launches the tools the wizard
  never ran: `monitor.py`, `triage_findings.py`, `materialize_plan.py`,
  `dashboard_server.py`, `dex_arbitrage_scanner.py`, `gen_chain_fixture.py`.
- **`onchain_scripts/server_run.sh`** — the one place the dashboard GUI is
  launched. Binds `127.0.0.1` only; picks the next free port when the
  preferred port is taken by a DIFFERENT service (never hijacks it); reuses
  the port when OUR dashboard already runs there (never a second copy); waits
  until the server accepts connections, then opens the browser
  (`xdg-open`/`open`/`wslview`). Used by both the Dashboard entry and the
  Materialize entry's "open the GUI" step.
- **`test_server_run.py`** — 3 tests: starts on a free port, reuses our own
  dashboard, falls back off a foreign-owned port.

### Changed

- **Dashboard GUI redesigned into a modern sidebar shell** (projection +
  control only; no system logic). A fixed left sidebar groups everything into
  three submenus — **Upravljanje** (Pregled, Zaženi operacijo, Aktivni teki,
  Konzola), **Nastavitve in konfiguracija** (Wallet policy, RPC override-i,
  Pogodbe) and **Rezultati** (Najdbe, Dnevniki tekov, Procesi). A hash router
  makes each view linkable; the live ETH/ETC network badge + watermark are
  kept. Data the server already projected but the old UI dropped is now shown:
  `contracts`, `vulnerabilities_found` (plan.json), `dashboard_runs` (with a
  per-run stop button), plus stat cards on the overview.
- **Dashboard default port 8765 → 4114** (`dashboard_server.py --port` and the
  wizard's Dashboard entry). 8765 is commonly reserved by other local services.
- The **Materialize** tool entry now runs the materialize analysis and then
  offers to open the dashboard GUI.

### Notes

- The dashboard is a state/projection GUI; it does **not** itself render the
  materialize worklist (there is no materialize view in `dashboard_server.py`)
  — the worklist is the materialize CLI's terminal output. Documented in
  `AGENTS.md` and in the code comment.
- `test_dashboard_ui.py` pins the projection contract: every nav entry has a
  view, every `/api/state` key has a renderer, every operation endpoint has a
  UI control, and the frontend hardcodes no address/chain id (projection-only).

---

## [0.0.1] — 2026-11-09

First tagged release. ForkSploit is an audit/offensive platform for EVM
smart contracts whose defining property is that it **proves** exploitability:
it discovers attack surfaces before and after deploy, executes the exploit
against real chain state, and moves the recovered funds to the recovery
wallet as proof. Only `CONFIRMED` (a measured recovery-wallet balance
increase) is ever presented as a demonstrated attack.

### Added

**Discovery (Rust core, `src/evm/`)**

- **47 attack-surface oracles** (`src/evm/oracles/*.rs`), grouped by class:
  access control, execution/control flow, arithmetic/economics, logic and
  reliability. Every oracle emits a structured finding with a replayable
  transaction trace.
- **Confidence tiers** — `sim-confirmed` (a directly observed violation) vs
  `sim-review` (a heuristic with a known false-positive risk). The `sim-`
  prefix makes the tier impossible to confuse with the Python layer's real
  on-chain `CONFIRMED`.
- **Declarative invariant oracle** (`--invariants file.json`,
  `src/evm/oracles/invariant.rs`) — a target's own economic promise expressed
  in JSON (`native_balance` / `literal` / `call` / `sum_over_callers`, ops
  `le/lt/ge/gt/eq/ne`), evaluated after every non-reverted transaction. No
  Rust needed.
- **Concolic / Z3 solving** (`--concolic`, `--concolic-caller`) over branch
  conditions a coverage-guided mutator would not guess, with symbolic
  storage (SLOAD/SSTORE), symbolic CALL return values, and a
  bounded campaign-wide worker pool (`--concolic-num-threads`, cap
  `min(2, cores)`).
- **Multi-step (setup → attack) search** via corpus genealogy
  (`TxnTrace::from_idx`), reaching bugs that need a transaction sequence.
- **Proxy expansion** — EIP-1967 (impl/beacon), EIP-1822 (UUPS), EIP-1167
  (minimal proxy), EIP-7702 — so the implementation is fuzzed, not the
  dispatcher.
- **Auto-derived setup** (`--auto-setup`) — derives `setX(address)` wiring
  preconditions from the deployed contract set; an explicit `setup.json`
  still wins.
- **Simulated flashloan** (`-f`) — Aave V3 / Balancer V2 borrow so the
  fuzzer explores without attacker capital.
- **25 EVM chains** (`Chain::from_str`, `src/evm/onchain/endpoints.rs`) with
  live RPC defaults and an RPC-identity check.

**Execution and proof (Python, `onchain_scripts/`)**

- **`auto_pipeline.py`** — one command: register → fund → fuzz → exploit →
  recover, with every step logged to the terminal and a timestamped log file.
- **`batch_pipeline.py`** — the same flow across many targets under one
  funding wallet and one recovery wallet.
- **`AttackWallet.sol`** — one reusable on-chain execution primitive
  (deployed once per chain), driven entirely off-chain from `*.plan.json`.
- **`strategy_layer.py`** — merges independent plans into one coherent,
  ordered multi-step plan (`unlock → neutral → objective → reentrancy last`),
  with dependency-aware step ordering and argument-level data threading.
- **Pre-flight profitability gate** (on by default) — metadata checks plus a
  free throwaway Anvil fork replay; a plan that provably reverts or cannot
  out-earn its own gas is skipped before anything is signed.
- **Structured proof** (`build_proof`) per finding: `replayed`, `gas_used`,
  `net_profit_wei`, and `blockers`.
- **Aave V3 flashloan funding** (`onchain_scripts/aave_flashloan_runner.py`)
  for zero-capital execution of value-carrying plans.
- **Post-deploy watcher** (`monitor.py`) — balance-drop / new-selector /
  large-tx alerts, periodic re-fuzzing, and a race to rescue remaining funds.
- **Triage** (`triage_findings.py`) — collapses thousands of plans into the
  handful of real surfaces and names what blocks each one.
- **Materialization worklist** (`materialize_plan.py`) — for control-leak
  surfaces, names the leaked call and the real state change that replaces it.
- **Local web dashboard** (`dashboard_server.py`) — projects real state and
  launches the real CLI scripts as subprocesses.
- **Cross-DEX arbitrage scanner** (`dex_arbitrage_scanner.py`) under the same
  wallet/gas safety framework.
- **Flashbots bundles** (`flashbots_bundle.py`) — atomic multi-step inclusion
  on ETH mainnet; single-tx mempool-privacy redirects on other chains.

**Security / operator control**

- **Locked profit destination** — `AttackWallet.safeWallet` is set once and
  every sweep function takes no destination argument.
- **Two-wallet policy** (`wallet_policy.py`) — funding and recovery roles
  locked per chain; enforced before every signing path.
- **RPC identity check** — the real `eth_chainId` is read and the run is
  refused on a mismatch, before anything is signed.
- **Strict mainnet confirmation** — `--confirm-mainnet` for any non-testnet,
  with a loud, unambiguous chain name.
- **Per-plan gas budget** — measured estimate + 10% margin, clamped to the
  chain's real block limit (`MAX_GAS_LIMIT`).

**Docs and packaging**

- **New `README.md`** — a professional platform overview (what it is/is not,
  the three proof levels, the 47-surface catalogue, the proof path, the
  security model, install/build/quick-start/config/CLI, limitations, legal
  use), with verified header badges.
- **`CHANGELOG.md`** — this file.
- **`Dockerfile`** — builds the offchain / onchain / print-logs binaries with
  all system prerequisites.
- **`forksploit.sh`** — the single interactive entry point: preflight
  ("doctor"), a persistent main menu, and a 7-step run wizard, with navigation
  by word (`nazaj` / `glavni meni` / `izhod`).

### Changed

- **AttackWallet multi-step reliability (W1–W5)** — see Fixed below; the
  execution model moved from one-transaction-per-step to an atomic batch for
  multi-step `flat` plans.
- **`--detectors` default is `all`** (was `high_confidence`) — silently
  narrowing the search made a "no bug found" read as "no bug exists".
- **Native payouts use a full-gas `call`** everywhere (`sweep`,
  `sweepWithBuilderTip`, and `collectAndDestroy` in both generated exploit
  templates) instead of `.transfer()`.
- **Gas is measured authoritatively** with the node's own `eth_estimateGas`
  against the real `block.gasLimit` (the revm model has no gas metering).
- **`--jobs` is clamped to the core count** and shares the concolic cap
  rather than multiplying it.

### Fixed

- **W1 — silent step failure.** `AttackWallet.execute()` returned
  `success=false` on a failed inner call while the outer tx still succeeded,
  so the pipeline saw `receipt.status==1` and reported "every step OK, NO
  PROFIT" even though a middle step had reverted. `execute()` now reverts,
  bubbling the callee's own reason (shared `_bubbleRevert` helper), matching
  `executeOperation`.
- **W2 — no atomic multi-step.** Added
  `executeBatch(address[],bytes[],uint256[])`: an ordered sequence in one
  transaction, reverting the whole batch if any step fails.
- **W3 — `.transfer()` stranded funds.** `.transfer()` forwards only 2300
  gas, which a contract recipient (Gnosis Safe / multisig) cannot run within.
  `AttackWallet.sol` and `collectAndDestroy()` in both generated exploit
  templates (`foundry_script.hbs`, `foundry_script_reentrancy.hbs`) now use a
  full-gas `call{value}`.
- **W4 — no failure diagnosis.** A multi-step `flat` plan is now sent as one
  atomic `executeBatch` tx; on failure `revert_reason()` reads the real reason
  via `eth_call` and `first_failing_step_index()` names **which step** broke
  ("best-effort prefix replay points at step i/n").
- **W5 — dependency-blind planner.**
  `strategy_layer.order_steps_by_dependencies` stably topo-sorts prerequisites
  (approve→transferFrom, deposit→withdraw) before their consumers and reports
  cycles instead of silently reordering them.
- **X1 — fuzzer crash on long finding names.** Under `--run-forever` one
  input can trip thousands of per-pc oracle hits, and the comma-joined
  `vulnerabilities/<bug_idxs>` name could exceed the filesystem's 255-byte
  NAME_MAX — the old `File::create(...).unwrap()` then panicked the whole
  fuzzer ("File name too long" ~3s into a real ETC run). `vuln_file_base()`
  bounds the name (readable ids when they fit, else a 120-byte prefix +
  stable hash) and dump writes log-and-continue on error.
- **X2 — mislabelled estimate-time revert.** When a plan's first step
  reverts, `eth_estimateGas` raises web3's `ContractLogicError`; it used to
  escape to the generic per-plan handler and be reported as `INCONCLUSIVE`,
  hiding a genuine "reverts on real state" result. It is now caught and
  returned as `NOT CONFIRMED` with the reason.
- **FAZA 2.3 — a `sim-confirmed` finding never rests on control leak.**
  `build_plan_meta` forces `confidence = "sim-review"` whenever
  `trace_depends_on_control_leak` holds, and the same rule is enforced at the
  finding level (`effective_confidence` in `oracle.rs`).
- **FAZA 2.4 — control leak off during concolic search.** A concolic solution
  can no longer rest on a faked/intercepted call return.
- **FAZA 2.5 — symbolic CALL return values** (with a concrete fallback when
  the callee's return is not fully symbolic).

### Security

- `executeOperation` only accepts a callback from the exact Aave pool this
  contract borrowed from; repayment failure reverts the whole transaction.
- Native sends bubble the recipient's own revert instead of swallowing it.
- `setSafeWallet` is one-time and rejects the zero address.
- Every signing script prints the selected chain's unambiguous name and
  verifies the RPC's real chain ID before signing.

### Notes

- **Known environment-limited test failures.** `cargo test --release`
  includes a handful of tests that require live public RPC endpoints and
  therefore fail in a network-isolated sandbox. These are the documented
  baseline, not regressions; any *other* failure is a regression.
- **Honest limitations** (see `README.md` and `LIMITATIONS.md`): no general
  symbolic planner with arbitrary data-flow between step arguments; no gas
  metering in the revm model; no mempool/front-running model; concolic is
  only partially storage-aware (`keccak256` is not inverted); a negative
  result is bounded by the run's budget and detectors.
- **Multi-licensed per component** (see `LICENSING.md`): Rust core
  `AGPL-3.0-or-later`, Python layer `Apache-2.0`, on-chain primitives
  Proprietary, dashboard `MIT`, documentation `CC-BY-4.0`.

[0.0.1]: https://github.com/DanijelTech/ForkSploit/releases/tag/v0.0.1
