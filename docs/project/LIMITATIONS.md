# LIMITATIONS.md — what ForkSploit does not yet do (and why)

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it. See [`DISCLAIMER.md`](../../DISCLAIMER.md).**

> Rule R3: a limitation is **written down**, not hidden. Anything not measured is
> marked **unmeasured**. There are deliberately no `file:line` references here
> (they go stale); where it matters, a **symbol** (the name of a function or
> constant) is given, since it does not move as easily.

This document is a **list of limitations**, not a list of achievements. For
achievements see `README.md` and `CHANGELOG.md`. Every item says: what does not
work, why, and what would close it.

---

## A. Execution model

**A1. The `revm` fork does not measure gas.** The model executes contracts
without gas metering (`no_gas_measuring`). Consequence: a plan that succeeds in
simulation can exceed `block.gasLimit` on the real chain.
*Mitigation:* the Python layer uses the authoritative `eth_estimateGas` + live
`block.gasLimit` (`gas_utils.estimate_gas_limit`), and the pre-flight gate
(`gas_oversized_reason`) marks a plan that does not fit in a block with a
separate status `oversized_gas` (`PLAN_OVERSIZED_GAS`). The same measurement is
also in `batch_pipeline.py`.
*What is missing:* the measurement is still on the **Python** side, not in the
`revm` model, so it depends on a reachable fork; without a fork there is no
measurement and we do **not** label the plan (`None`, we do not guess).
Regression test: `test_gas_oversized_gate.py`.

**A2. No mempool / ordering / front-running.** Sandwich, backrun, JIT liquidity
and MEV are **outside the model**. No fix is planned.

**A3. Concolic (Z3) is narrow.** Symbolic are calldata, `callvalue`, `caller`,
`origin` and memory. **Closed (PHASE 2.1, 2026-11-07):** symbolic storage
(`SymbolicStorage`) is now keyed by **contract address** and **persistent across
calls** (previously per-frame); the SSTORE operand swap was also fixed.
**Measured:** a slot the contract writes in a **previous call** is now solved by
concolic (`violations:1`), without concolic it is not (`violations:0`).
**Closed (PHASE 2.5):** symbolic call return values (see A4).
**STILL OPEN:** the symbolic `CALL` target (PHASE 2.2) and symbolic balances.
`keccak256` is **not inverted**, so a mapping entry that was in state **before
the transaction** (`require(m[k]==1)`) remains unreachable — see A5.

**A4. Symbolic call return values (PHASE 2.5) — closed.** Previously the result
of a `CALL` was always concrete, so a gate of the form
`(ok, ret) = target.call(...); require(abi.decode(ret) == SECRET)` could not be
solved by concolic. Now `RETURN` takes the callee's symbolic memory, `on_return`
splices it into the caller's memory at `return_offset`, and
`RETURNDATASIZE`/`RETURNDATACOPY` read `last_return_bytes`. The essence: the
spliced bytes are the **callee's own symbolic memory**, tied to the caller's
input — so the solver inverts the callee's computation (`y*2 == SECRET`), rather
than guessing a free constant. If the callee's `RETURN` is not fully symbolically
tracked, the **concrete** value is used (never an invented one). Boundary: it
covers only **synchronous** `CALL`/`STATICCALL`/`DELEGATECALL` in the same
transaction. Regression tests: `tests/evm/concolic_retval/` (positive) and
`tests/evm_never_pass/concolic_retval_unsat/` (negative, odd secret).
*Reliability:* with a LARGE constant the solution needs more than the default
1000 ms; deterministic at `--concolic-timeout 5000`.

**A5. A mapping entry from imported state remains unreachable (PHASE 2.1
incomplete).** Symbolic storage solves a slot the contract **writes** during the
transaction with a symbolic key. It does not solve reading `m[k]` where the entry
`m[k]` already exists in the imported state: the slot address is
`keccak256(k . p)`, and concolic does **not** invert `keccak256`. *What would
close it:* a `keccak256` model in Z3 (expensive) or special-case handling of
reading a known `(contract, slot)` pair from imported state (requires a storage
layout, not a heuristic).

**A6. A false positive of the invariant oracle on uninitialized concolic state
— found and fixed (2026-11-07).** The concolic stage also ran on raw corpus seed
inputs, which carry an empty world state (every slot reads 0); a gate
`require(x*x == secret)` passed with `x = 0`, and the concolic solutions
inherited that empty state so the oracle saw a post-state write even though the
real transaction reverts. Fix: the stage **skips** a testcase with
`!initialized` (`concolic_stage.rs`). Proof: fixture
`tests/evm_never_pass/concolic_uninit_state/` (before: `violations:1`; after: `0`)
+ a pair of regression tests in `test_invariant_oracle.py` (the second prevents a
vacuous pass of the first).

---

## B. Attacker vs. privileged party (PHASE 3)

**B1. The harvest heuristic remains** (deliberately). It is tagged with
`owner_impersonation`, expanded into a structured record
`owner_impersonation_detail` (`{caller, harvested_from_contract,
harvested_from_slot}`) and into a **semantic** test `owner_gated` (the step calls
the contract AS an identity read from that contract's **own** storage — exactly
`require(msg.sender == owner)`). A plan with `owner_gated`/`owner_impersonation`
is tagged with a blocker in the report and is **never presented as an attack**
(`build_proof`). *What is missing:* a more general semantic test of an arbitrary
privileged condition, not only "an address from its own storage".

---

## C. Proof of feasibility (PHASE 5)

**C1. A structured proof exists** (`build_proof` → `Proof` with `replayed`,
`gas_used`, `net_profit_wei`, `blockers`). The signals are combined into one
object per plan. *What is missing:* a single schema at the level of the **whole
run** (an aggregate across all plans) — currently the proof is per-plan.

**C2. The success criterion (at least one plan passes three gates on a test
target with a measured net profit) was verified in environments with RPC access,
but in a clean sandbox it remains UNVERIFIED.** In this environment there is no
live RPC to the target. Measured: 10 of 10 network/state-dependent Rust tests
fail **even with egress** (`onchain_pair_discovery::*`, `uniswap::{test_get_pair,
test_fetch_uniswap_path}`, `endpoints::tests::test_get_balance`), because they
rely on live public RPCs or on pinned live state. This is not a code bug, but a
limitation of the environment and of the nature of these tests.

---

## D. Reliability (PHASE 6)

**D1. Panic-prone `.unwrap()`/`.expect()` on external data — mostly fixed.**
External-data boundaries (RPC response, solc/forge output, ABI, storage,
presets) are hardened in `onchain/endpoints.rs`, `blaz/offchain_artifacts.rs`,
`corpus_initializer.rs`, `contract_utils.rs`, `abi.rs`, `blaz/linking.rs`. The
remainder is **not** on external data: `.parse().unwrap()` on static literals,
`lock().unwrap()` and `#[cfg(test)]`. *What is missing:* `clippy::unwrap_used`
as a CI lint, so the remainder does not grow back.

**D2. Multi-core (PHASE 6.2) — implemented.** `src/evm/multicore.rs`
(`run_supervisor`) splits the seed space into `--jobs N` **separate processes**
(not threads) with isolated state; `--jobs` is clamped to the number of cores.
Process isolation was chosen because `EVMFuzzState` is not `Send` and the
coverage and cmp maps are process-global `RacyCell`s (sound only under a
single-threaded assumption).
*What is missing (R1):* a measurement of "N cores → ~N times more cases/s" on a
real target; the speedup factor remains **unmeasured**.

**D3. Concolic runs on a bounded, campaign-wide worker pool.** Each solve runs
on its own OS thread, and at most `num_threads` solvers are alive at once in the
process-global pool `ALL_WORKER_THREADS`; when the pool is full, `threaded_solve`
first `join`s the oldest worker. `--concolic-num-threads` is **not ignored**:
`resolve_concolic_num_threads` resolves the value against the cap
`min(MAX_CONCOLIC_THREADS, cores)` (`MAX_CONCOLIC_THREADS = 2`). `0`/unset = the
cap; `1` = a single sequential solver; more is cut off with a warning.
`--jobs N --concolic` **shares** the cap (`per_job_concolic_threads(jobs) =
max(1, cap / jobs)`), it does not multiply it. Proof:
`evm::test::concolic_threads_are_bounded_by_the_campaign_cap`,
`evm::test::concolic_cap_never_exceeds_two_or_cores`,
`evm::multicore::tests::per_job_concolic_threads_never_multiplies_the_cap`.
*Note (R3):* with more jobs than the cap (e.g. `--jobs 4`, cap 2) every worker
still has at least one solver, so the total equals the number of jobs, not
`N * cap`.

---

## E. Reporting (PHASE 7)

**E1. No `severity` / CVSS.** There are `confidence`
(`sim-confirmed`/`sim-review`), `net_profit_wei`, `gas_spent_wei`,
`recovery_delta_wei` and the **`chain-verified`** predicate
(`is_chain_verified(status, recovery_delta_wei)`), which is awarded **only** on
`PLAN_CONFIRMED` and a measured positive delta (test
`test_chain_verified.py`). *What is missing:* a structured `severity`/CVSS field.

---

## F. Scientific honesty: what we deliberately do NOT claim

- **We do not claim a contract is free of vulnerabilities** when there are no
  findings. "Not found" means "not found in this budget with these oracles".
- **We do not claim a finding is real until funds move.** The `sim-confirmed`
  level is a **simulation**; only `CONFIRMED` (a measured increase of the
  recovery wallet) is proof.
- **We do not claim a control-leak trace reflects the real chain.** Such a trace
  is never presented as `sim-confirmed` (PHASE 2.3/2.4).
- **We do not claim the speed of a multi-core run**, because we have not
  measured it (D2).

---

## G. Blockers (summary from `BLOCKERS.md`)

The biggest structural blocker is that **the unit of fuzzing is one transaction**
(`EVMInput`); multi-step behaviour arises only across the corpus genealogy. For
classes that require an exact sequence (set up → fund → attack), the reach is
probabilistic. Details and measurements in `BLOCKERS.md`.

---

## H. Fix log (for balance)

Former limitations that have been closed (with proof):

- Symbolic storage (PHASE 2.1) — a slot written in a previous call is solvable.
- Symbolic call return values (PHASE 2.5).
- False positive of the invariant oracle on uninitialized state (A6).
- Control leak off during concolic search (PHASE 2.4).
- `sim-confirmed` never rests on a control leak (PHASE 2.3).
- Wrong proxy slot constants (`BEACON_SLOT`, `UUPS_SLOT`) — beacon and EIP-1822
  proxies are now resolved.
- A stale negative oracle cache on a control-leak intermediate state (the oracle
  permanently suppressed a later real report) — fixed in `feedback.rs`.
- Fuzzer panic "File name too long" on a very long finding name (X1).
- Wrong classification of an `eth_estimateGas` revert as `INCONCLUSIVE`
  (X2 → now `NOT_CONFIRMED`).
- Concolic pool (D3) and `--jobs` clamp to cores.
