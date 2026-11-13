# ForkSploit v0.0.1 — the open-source release

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.** ForkSploit is
> provided "AS IS", without warranty of any kind. It is an offensive-security
> tool that signs and sends **real** transactions and can move **real** funds.
> You use it entirely at your own risk and under your own full responsibility;
> the authors and copyright holders accept **NO** liability whatsoever for any
> consequences of its use, misuse or inability to use it. Use it only on
> contracts you own, on contracts for which you have the owner's written
> permission, or on test networks. Unauthorised use against third-party
> contracts is illegal. See [`DISCLAIMER.md`](../../DISCLAIMER.md).

**ForkSploit is now open source. v0.0.1 is the first public tag of the project.**
The community is warmly invited to join and help build one shared, large
platform — **every contribution counts**.

---

## What ForkSploit is

ForkSploit is an **audit-and-offensive platform for EVM smart contracts** that,
under strict operator control, **proves** a contract is vulnerable — and proves
it by action: it discovers attack surfaces, **executes the exploit against the
real chain state**, and **moves the recovered funds to the recovery wallet as
proof**.

It is not a fuzzer that stops at *"this could be vulnerable"*. It separates three
levels and never conflates them:

| Level | Where it arises | What it means | How it is reported |
|---|---|---|---|
| **Finding (attack surface)** | Rust core (revm + 47 oracles) | An observable pattern or a directly observed violation **in simulation** | `sim-confirmed` / `sim-review` |
| **Replayable proof** | `*.plan.json` | Every finding carries a **reproducible transaction trace** (who, what, calldata, value) | `evidence: "replayable_transaction_trace"` |
| **On-chain proof** | Python execution layer | A real transaction was sent and the **recovery wallet really received funds** | `CONFIRMED` + measured `recovery_delta_wei` |

> **Only `CONFIRMED` (a measured recovery-wallet balance increase) is ever
> presented as a demonstrated attack.** `sim-confirmed` is a *simulation* label,
> never a bare "confirmed".

---

## Why v0.0.1 (and why "0.0.1")

This is an **early, honest milestone**. The engine and the proof pipeline are
real and live-verified on real networks, but the search is still narrow and the
platform is under active development. We tag `v0.0.1` — not `v1.0.0` — to say
plainly: **the foundation is solid and open, and there is a lot of room to build
together.** See the "Where we need you" section for the exact gaps.

---

## Headline capabilities

### Two-layer architecture (Rust core + Python execution)

**Rust never signs. Python never decides whether a pattern is a vulnerability.**

- **Rust core** (`src/`) — a bytecode-level, coverage-guided fuzzer over `revm`,
  with concolic (Z3) solving and **47 oracle modules**. On a hit it emits a
  machine-readable, reproducible `*.plan.json` and a reproduction `.t.sol`.
- **Python execution layer** (`onchain_scripts/`) — reads every plan, merges
  them into one ordered multi-step plan, executes it through one reused
  `AttackWallet` contract (deploy + real calls, an Aave V3 flashloan when
  needed), and sweeps the recovered funds to the locked recovery wallet.

The boundary is **process-based and file-based** (`subprocess` + files), not
in-process — so the two layers are legally and technically separate works, each
with its own license (see [Licensing](#licensing)).

### First-class support: ETH + ETC, testnet + mainnet, all assets

- **Live-verified** on **Ethereum (ETH)** mainnet (id 1) + **Sepolia**
  (11155111) and **Ethereum Classic (ETC)** mainnet (id 61) + **Mordor** (63) —
  in **both testnet and mainnet** variants.
- **Assets:** native currency (ETH/ETC) and **all ERC tokens** — ERC-20,
  ERC-721, ERC-1155, ERC-4626.
- **25 chains** in the Rust core; **21 chains** in the Python orchestration.

### 47 attack surfaces (oracles)

Implemented in `src/evm/oracles/`, each a bytecode-level pattern detector with a
confidence tier (`Confirmed` = directly observed violation; `Review` = heuristic
with a known false-positive risk):

- **Access & authorization** — `access_control`, `tx_origin`,
  `initializer_front_run`, `ecrecover`, `signature_malleability`,
  `signature_replay`, `forged_proof`, `centralization_risk`.
- **Execution & control flow** — `reentrancy`, `readonly_reentrancy`,
  `arbitrary_storage_write`, `storage_collision`, `proxy_integrity`,
  `proxy_upgrade_hijack`, `delegatecall`, `delegatecall_target`, `arb_call`,
  `arb_transfer`, `unchecked_call`, `selfdestruct`, `gas_stipend`,
  `assert_violation`, `uninitialized_memory`, `transient_guard`.
- **Arithmetic & economics** — `overflow`, `precision_loss`, `preview_rounding`,
  `token_accounting_mismatch`, `unbacked_mint`, `forced_eth_accounting`,
  `eth_backing`, `erc20`, `nft_transfer`, `erc4626`, `curve_virtual_price`,
  `twap_manipulation`, `price_feed_staleness`, `imbalanced_pair`.
- **Logic & reliability** — `unbounded_loop`, `revert_in_loop`, `stale_guard`,
  `self_referral`, `zero_address_setter`, `weak_randomness`, `invariant`.

### Declarative invariant oracle (`--invariants file.json`)

Express a target's own economic invariant in JSON (no Rust): operands
`native_balance`, `literal`, `call`, `sum_over_callers`; operators
`le/lt/ge/gt/eq/ne`. Violations are reported at `sim-confirmed` tier.

### Proof pipeline and safety controls

- **Pre-flight gate** (ON by default): a metadata layer (no network) + a fork
  simulation layer that measures the **real** recovery-wallet delta and gas.
- **Locked profit destination** (`AttackWallet.safeWallet`, set once; `sweep*`
  has no destination parameter) — even a compromised owner key cannot redirect
  payouts.
- **Two-wallet rule** (`wallet_policy.py`) — funding and recovery roles locked
  per chain, checked before every signature.
- **Automatic network detection** — reads the real `eth_chainId` and refuses a
  mismatch (closes the `eth`/`etc` one-letter trap).
- **Mandatory mainnet confirmation** and a **per-plan gas budget**
  (`MAX_GAS_LIMIT = 8_000_000`, the real ETC block limit).
- **Flashbots bundle** (atomic) and **Aave V3 flashloan** (zero-capital
  execution) paths.

### Interactive entry point and tooling

- **`forksploit.sh`** — one interactive entry point: logo, a pre-flight
  "doctor", a persistent main menu, and a 7-step wizard (chain → RPC → key →
  targets → recovery wallet → wallet policy → mainnet confirmation) with a
  read-back summary before anything runs.
- **Helper tools** (`onchain_scripts/`): `monitor.py` (post-deploy monitoring),
  `strategy_layer.py` (multi-step plan composition), `triage_findings.py`,
  `materialize_plan.py`, `proxy_resolver.py`, `gas_utils.py`, `gas_oracle.py`,
  `flashbots_bundle.py`, `chains.py`, `wallet_policy.py`,
  `aave_flashloan_runner.py`, `dex_arbitrage_scanner.py`, `dashboard_server.py`
  (a local GUI projection + control surface), `deploy_sepolia_demo.py`,
  `gen_chain_fixture.py`.
- **Dashboard GUI** — a modern sidebar shell that projects real state and runs
  the real CLI scripts as subprocesses; binds `127.0.0.1` only.

### Multi-step (setup → attack) search

`EVMInput` is one transaction, but multi-step bugs are reached **across the
corpus genealogy**: every execution records `TxnTrace::from_idx` (parent) and
`cov_stage`/`minimizer` replay the sequence (root → setup → attack). Measured
depth on generated fixtures: 2–6 steps 8/8, 8 steps 6/6, 10–16 steps 4/4.

### External-data hardening and bounded reliability

- `revm` is pinned; concolic runs on a **bounded, campaign-wide worker pool**
  (`MAX_CONCOLIC_THREADS = 2`) with a Z3 memory cap.
- `--jobs N` uses **process isolation** (not threads), clamped to the core count.
- Concolic no longer crashes on unsupported opcodes / unexpected symbolic shapes
  (graceful degradation).
- Fuzzer finding-dump names are bounded (no more "File name too long" panic).

---

## Verified evidence (R1 — proof before claim)

ForkSploit is held to a strict **proof-before-claim** rule. Representative,
measured evidence shipped in this release:

- **Echidna vs ForkSploit** (`benchmarks/echidna_vs_forksploit/`) — on **one and
  the same real deployed contract** (`CyberScratchLottery` on ETC Mordor), both
  tools independently find the contract's real bug (**SWC-120 weak randomness**)
  in the same 120 s budget.
- **Full live run** (`benchmarks/forksploit_full_live_mordor/`) — a full
  pipeline run directly against live Mordor (no fork), two independent seeds,
  finding the **same 9 finding types** (100% reproducible at the type level),
  each checked against the verified source (1 real, the rest false positives or
  benign heuristics — reported honestly).
- **Rust tests** — `cargo test --release` reports **140 passed, 10 failed**; all
  10 are network/state-dependent and fail even with network access (the CI
  workflow skips exactly those).
- **Python tests** — `pytest onchain_scripts` reports **232 passed** in a full
  environment (without `anvil`/`solc`).

---

## Licensing

ForkSploit is **multi-licensed per component** — the Rust core and the Python
layer are separate works (they communicate over a subprocess + files, not by
linking), so each can carry its own license:

| Component / path | License |
|---|---|
| **Rust core** — `src/`, `benches/` | **AGPL-3.0-or-later** |
| **Python execution layer** — `onchain_scripts/**/*.py` | **Apache-2.0** |
| **On-chain primitives** — `onchain_scripts/contracts/**/*.sol`, `onchain_scripts/llm_poc/contracts/**/*.sol` | **Proprietary (All Rights Reserved)** |
| **Dashboard** — `onchain_scripts/dashboard_static/**`, `server/**` | **MIT** |
| **Documentation** — `docs/**`, `skills/**`, root prose `.md` | **CC-BY-4.0** |
| **Third-party** — `vendor/**` | upstream (**MIT OR Apache-2.0**) |

- The **Rust core is AGPL-3.0-or-later**: anyone who distributes a modified
  version, **or runs a modified version as a network service (SaaS)**, must
  release their modified source under the AGPL. This keeps the engine open and
  prevents closed forks, while remaining a genuine, OSI-approved open-source
  license.
- The **Python layer is Apache-2.0**: build tooling and integrations freely, with
  legal clarity for corporate contributors.
- Full texts are in [`LICENSES/`](../../LICENSES/); the map is in
  [`LICENSING.md`](../../LICENSING.md) and [`REUSE.toml`](../../REUSE.toml).

---

## Call for the community — join us

**ForkSploit is an open invitation to build one shared, large platform for
proving smart-contract exploitability. Every contribution counts — code, docs,
tests, bug reports, ideas, benchmarks, or a single well-written issue.**

Ways to help, from easiest to deepest:

1. **Star the repo** and **enable watch** — it helps others find the project.
2. **Report bugs and false positives.** We especially want reports of
   *false positives* and *false negatives*, with the exact command and fixture.
3. **Add oracle fixtures** (`tests/evm/<name>/`) — small, self-contained
   contracts that trigger (or must NOT trigger) a detector.
4. **Contribute oracles and features** — see the roadmap in
   [`skills/forksploit-contract-audit/references/new-oracle-roadmap.md`](../../skills/forksploit-contract-audit/references/new-oracle-roadmap.md)
   and the analysis in [`BLOCKERS.md`](BLOCKERS.md).
5. **Improve the docs** (`docs/`), the wiki, and the examples.
6. **Benchmark it** against Echidna/Foundry on real contracts and publish the
   honest result (like `benchmarks/`).
7. **Help with the hard research problems** listed below — these are open,
   well-scoped, and high-value.

**Ground rule R1 — proof before claim.** No "done"/"fixed" without a
reproducible proof (a test, a measurement, or command output). Anything not
measured is labelled **unmeasured**. Read [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
before your first PR.

> We ask for contributions under the license of the component you touch. Because
> the project may offer alternative/commercial licensing, the maintainer may ask
> for a CLA or a `Signed-off-by:` (DCO) line.

---

## Where we need you — known weak points

These are the honest, documented gaps where community attention helps most.
Each is described with the current state and why it matters.

### A. Search depth and multi-step reach

- **The unit of fuzzing is one transaction** (`EVMInput`). Multi-step behaviour
  arises only across the corpus genealogy, so a class that requires an exact
  sequence (set up → fund → attack) is reached **probabilistically**, not by a
  planner. **We need a directed sequence planner** (known dependency families
  first, then general data-flow between arguments).

### B. Concolic (Z3) is narrow

- Symbolic **storage** (by address, persistent across frames) and symbolic
  **call return values** exist; **`keccak256` is not inverted**, so a mapping
  entry from imported state is unreachable.
- **Still open:** symbolic **`CALL` targets** and symbolic **balances**.
- We need help modelling `keccak256` (hard) or a storage-layout-based approach
  to reading known `(contract, slot)` pairs from imported state.

### C. Gas reality

- The `revm` model has **no gas metering**; the authoritative number comes from
  the node's `eth_estimateGas` against the real `block.gasLimit` (Python side).
  A simulation-valid trace can exceed the block limit on-chain. We need a gas
  metering model or a more robust pre-flight classification.

### D. Control leak and false positives

- For **non-concolic** search the control leak remains on by design (it helps
  find deep paths); such traces are tagged and downgraded, but they create noise.
- The `sim-confirmed` tier can still produce **false positives** (see the honest
  Mordor analysis). We need better separation and more ground-truth fixtures.
- **Owner-impersonation** plans (the fuzzer "becoming" the owner from storage)
  are tagged and skipped — but the underlying conflation of attacker and
  privileged party is only partly solved.

### E. Determinism, reproducibility and scale

- The fuzzer's mutation/scheduling strategy is not fully deterministic across
  runs; concolic depth depends on the Z3 timeout budget.
- **Multi-core** is process isolation (`--jobs`), not threads; the speedup
  factor "N cores → ~N× more cases/s" is **unmeasured**.
- We need reproducible seeds, a stable campaign summary, and a measurement of
  scaling.

### F. Reporting and severity

- There is **no `severity`/CVSS** field; only `confidence`, `net_profit_wei`,
  `gas_spent_wei`, `recovery_delta_wei` and the `chain-verified` predicate.
- The structured proof is **per plan**; there is **no aggregate** across a whole
  run.

### G. Robustness and hardening

- `.unwrap()`/`.expect()` remain outside `#[cfg(test)]` on some paths (e.g.
  `--fetch-tx-data`); we want a `clippy::unwrap_used` gate in CI so it does not
  grow back.
- ABI quality for unverified contracts depends on the decompiler (EVMole).

### H. Coverage of modern attack surfaces

- **EIP-7702 delegation** is partly handled (designator resolution); the
  **ERC-4337 `validateUserOp`/paymaster** flow is **not** covered — a 0%-covered
  modern attack surface.
- Transient-storage guards, read-only reentrancy and several control-leak-
  dependent oracles detect correctly but **report rarely** (a mutation-strategy
  limitation, not a detection bug).

### I. Ecosystem and interoperability

- **No plugin/extension API** yet; oracles are compiled in.
- **No machine-readable report schema** beyond `plan.json`/`vuln_info.jsonl`.
- A **package registry presence** (crates.io / PyPI) and a stable CLI contract
  are not yet established.

### J. Dead test networks and chain quirks

- `goerli`, `mumbai`, `zkevm_testnet` are in the enum but have no default RPC in
  the Python layer.
- **ETC needs `--spec-id Shanghai` and `anvil --hardfork shanghai`** (documented
  in `docs/CHAINS_AND_RPC.md`).

> The full, continuously maintained list is in [`LIMITATIONS.md`](LIMITATIONS.md)
> and [`BLOCKERS.md`](BLOCKERS.md), and the current per-phase status is in
> [`PLAN.md`](PLAN.md). The open plan for new oracle types is in
> [`skills/forksploit-contract-audit/references/new-oracle-roadmap.md`](../../skills/forksploit-contract-audit/references/new-oracle-roadmap.md).

---

## How to get started

```bash
# 1) System prerequisites (Debian/Ubuntu)
sudo apt-get install -y libz3-dev pkg-config clang cmake build-essential

# 2) Build the Rust core
cargo build --release

# 3) Python dependencies
pip install -r onchain_scripts/requirements.txt

# 4) Interactive entry point
./forksploit.sh
```

See [`README.md`](../../README.md) for the full guide, [`docs/00_INDEX.md`](../00_INDEX.md)
for the complete technical documentation, and the
[wiki](https://github.com/DanijelTech/Forksploit-open/wiki) for a guided tour.

---

## What's in v0.0.1

- The complete two-layer platform (Rust core + Python execution layer) and the
  on-chain `AttackWallet` primitive.
- 47 oracles, the declarative invariant oracle, the proof pipeline and the
  safety controls.
- The interactive entry point, the helper tools and the dashboard GUI.
- Complete English documentation, the multi-license model, and this disclaimer.
- Honest, measured benchmarks and an explicit list of limitations.

---

## A note on honesty

ForkSploit deliberately reports what it **cannot** do as loudly as what it can.
"Nothing found" means "nothing found in this budget with these oracles" — never
"the contract is safe". A `sim-review` finding is never presented as a proven
attack, and only a measured on-chain fund movement is `CONFIRMED`. We invite the
community to hold the project to that standard, and to help raise it.

**Join us. Every contribution counts.**

---

*Copyright (c) 2026 Dany Tech. Multi-licensed per component — see
[`LICENSING.md`](../../LICENSING.md).*
