# PLAN.md — ForkSploit state by phase

> Rule (R1/R2): anything not measured is marked **unmeasured**; anything not
> verified in code is marked **unverified**. This document is a **status and
> open-work overview**, not a diary. The change history is kept in
> `CHANGELOG.md`.

ForkSploit is an **audit-and-offensive platform for EVM smart contracts**: it
discovers attack surfaces and **proves** exploitability by executing the exploit
against the real chain state and moving the extracted funds to the recovery
wallet. It works on **Ethereum (ETH)** and **Ethereum Classic (ETC)**, each in a
**testnet** and **mainnet** variant (Sepolia, Mordor / ETH id 1, ETC id 61), and
covers the **native currency and ERC tokens**.

---

## 1. Phases — what is closed, what is open

| Phase | Priority | State |
|---|---|---|
| **1 — Gas reality** | critical | **Partial.** The `revm` model does not measure gas. The authoritative measurement is on the Python side (`eth_estimateGas` + live `block.gasLimit`, `gas_utils.estimate_gas_limit`), and the pre-flight gate marks an oversized plan with `oversized_gas`. *Missing:* measurement in the model. |
| **2 — Storage-aware SMT** | critical | **Partial.** Symbolic storage (by address, persistent across frames) and symbolic call return values are closed (PHASE 2.1/2.5). *Missing:* symbolic `CALL` target, symbolic balances, `keccak256` preimage. |
| **3 — Attacker / privileged party** | critical | **Partial.** `owner_impersonation` + structured `owner_impersonation_detail` + semantic `owner_gated`. *Missing:* a general semantic test of privileged conditions beyond "an address from its own storage". |
| **4 — Semantic analysis** | medium | **Open.** The built-in oracles are pattern-bound; the declarative invariant covers only expressible shapes. |
| **5 — Proof gate (3 gates)** | critical | **Mostly.** `simulate_plan_on_fork` + gas reality + `atomic_replayable`/`owner_impersonation`; a structured `Proof` (`build_proof`) with `blockers`. *Missing:* a proof aggregate at the level of the whole run. |
| **6 — Reliability / parallelism** | medium | **Solved.** External-data boundaries hardened (`Result`); multi-core via process isolation (`multicore.rs`, `--jobs`, clamp to cores); concolic on a bounded pool (`MAX_CONCOLIC_THREADS = 2`). |
| **7 — Reporting** | medium | **Partial.** `chain-verified` exists (`is_chain_verified`, test `test_chain_verified.py`). *Missing:* `severity`/CVSS. |
| **8 — Documentation** | mandatory | **In progress** — this document, `README.md`, `LIMITATIONS.md`, `BLOCKERS.md`, `CLAUDE.md`, `AGENTS.md`. |

---

## 2. The nine original gaps (from the task) — state

| # | Gap | State |
|---|---|---|
| 1 | No gas measurement in the model | Open in the model; replaced on the Python side (+ `oversized_gas`). |
| 2 | No mempool / front-running | Open (outside the model). |
| 3 | Narrow concolic | Partial — storage + return closed; CALL target/balance/keccak open. |
| 4 | Control leak injects a fake return value | Bounded: concolic does not use the leak; `sim-confirmed` never rests on the leak. |
| 5 | Conflation of privileged party and attacker | Partly solved: `owner_impersonation`/`owner_gated` tag + a structured record. |
| 6 | Pattern-based, not semantic | Open (PHASE 4). |
| 7 | Single-threaded | Solved: process isolation (`--jobs`). |
| 8 | Panic-prone `.unwrap()` on external data | Mostly solved; the remainder is not on external data. |
| 9 | No formal reporting | Partial: `confidence`/`net_profit_wei`/`chain-verified`; `severity`/CVSS missing. |

---

## 3. Success criteria (task section 4)

Goal: **at least one** plan that passes all three gates on a test target (state
replay, gas reality, independence from a fake) and executes with a **measured
net profit**.

**State: PARTIALLY VERIFIED.**
- In the **clean sandbox** of this repository there is no RPC egress, so the
  measurement is not possible there.
- **Outside the sandbox it was measured:** `benchmarks/forksploit_full_live_mordor/`
  is a full run directly against live ETC Mordor (`CyberScratchLottery`), two
  independent seeds; `benchmarks/echidna_vs_forksploit/` compares it with
  Echidna on the same real contract — both independently find the same real bug
  (weak randomness, SWC-120). See also `LIMITATIONS.md` §C2.

---

## 4. Baseline measurement (measured)

- **Build:** `cargo build --release` → 0 errors, 0 project warnings.
- **Rust tests:** `cargo test --release` → **140 pass, 10 fail**. All 10 are
  network/state dependent (`onchain_pair_discovery::*` (8),
  `uniswap::{test_get_pair, test_fetch_uniswap_path}`, `endpoints::test_get_balance`)
  and fail **even with egress**; CI skips them with `--skip`.
- **Python tests:** `pytest onchain_scripts` → **232 pass** (without `anvil`/`solc`).
- **CI:** `.github/workflows/ci.yml` (GitHub-hosted Linux, free) runs the two
  green gates above.

---

## 5. Open work (prioritised)

1. **PHASE 2.2/2.6** — symbolic `CALL` target and symbolic balances (concolic).
2. **PHASE 4** — semantic analysis beyond patterns (storage layout, general invariants).
3. **PHASE 5** — an aggregate structured proof across a whole run.
4. **PHASE 7** — `severity`/CVSS.
5. **Gas metering model** in `revm` (or a persistent write of gas fields into `PlanMeta`).
6. **Measurement of the multi-core speedup** on a real target (currently unmeasured).

---

## 6. What we deliberately do NOT do

- We do not add new oracles until phases 1–3/5 are closed (task).
- We do not remove the harvest heuristic (task) — we only tag it.
- We claim nothing without a measurement (R1). "Not found" ≠ "not vulnerable".
