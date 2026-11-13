# BLOCKERS.md — why ForkSploit does not (yet) handle a "hidden deep hole"

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it. See [`DISCLAIMER.md`](DISCLAIMER.md).**

> Rule R1: every claim has a reproducible measurement (or a symbol, not a fragile
> `file:line`). Rule R3: a limitation is written down, not hidden.
> Purpose: this is a **work plan** for P1–P5, not an excuse.

---

## 0. Diagnosis in one sentence

ForkSploit has a **strong and honest proof layer** (proof = a measured increase
of the recovery wallet balance on the real chain) and a **weak search layer**
(a single-transaction, pattern-driven fuzzer with manual setup and narrow
concolic). The proof is good; the search is narrow. That is why the scenario
"a seemingly clean contract with a hidden deep hole" is **not reliably covered**.

---

## 1. What IS good (so we do not fix it unnecessarily)

- **The proof is conservative and measured.** `auto_pipeline.execute_plan`
  (`if delta > 0 or gained_tokens`) accepts `PLAN_CONFIRMED` **only** if the
  *recovery* wallet balance **actually increases** on the real chain; otherwise
  `EXECUTED, NO PROFIT` or `NOT CONFIRMED`. That is the real "proof-before-claim"
  standard.
- **`chain-verified` is derived, not declared.** `auto_pipeline.is_chain_verified`
  (`status, recovery_delta_wei`).
- **A structured `Proof`** with `blockers`. `auto_pipeline.build_proof`.

We do **not** change these layers — we build on them.

---

## 2. Blockers (with evidence)

### B1. The input is ONE transaction (the biggest blocker)
`struct EVMInput` (`src/evm/input.rs`) describes **one** transaction
(`caller`, `contract`, `data`, `txn_value`, `env`). Multi-step behaviour arises
only indirectly through the corpus genealogy (`sstate`), never as a planned
sequence. The scenario "set up → fund → attack" is therefore **probabilistic**,
not **directed**.

**Measurement (P2, 2026-11-07):** the genealogy mechanism (`TxnTrace::from_idx` +
`cov_stage` replay) **works and is on by default** (`full_trace` +
`print_txn_corpus`). On a sequential-holes generator
(`onchain_scripts/gen_chain_fixture.py`) we reliably find sequences up to **16
steps** (see P2 below for the table). The blocker is therefore not "multi-step
does not work", but: (a) the sequence is a **consequence of evolution**, not a
plan; (b) with all oracles the throughput is low, so deep chains are slow.

### B2. `setup.json` is HAND-WRITTEN (and reachable only from a fixture)
`src/evm/setup.rs` documents the intent, but `setup.json` is loaded **only**
when it is in the fixture directory: `contract_utils.rs`
(`path_str.ends_with("setup.json")`), and it is used via `loader.setup_spec` in
`corpus_initializer.rs`. The `--target 0x...` path (a live target) **does not
have** this: `from_address` (`contract_utils.rs`) sets `setup_spec: None`.

**Important nuance (correction of the first assessment):** the `--target` path
does **not** start from empty state — SLOAD is **forked lazily from RPC**
(`StorageFetchingMode::OneByOne`, `src/evm/onchain/mod.rs`), so the *existing*
state is real. The gap is therefore **not** "wrong state" but **the absence of
preconditions**: the fuzzer cannot itself perform the sequence of actions that
*creates* the state a hole needs (e.g. "first deposit, then attack").
**Proof of the difference:** in `README.md` (§Automatic precondition
derivation) — on `tests/evm/erc4626/` without `setup.json`, **986k executions
find nothing**; with it, the oracle fires.

### B3. Concolic (Z3) is narrow
`src/evm/concolic/concolic_host.rs` models symbolically only `BALANCE`,
`CALLVALUE`, `CALLER`, `ORIGIN`, `calldata` and memory. SLOAD/SSTORE
(opcode `0x54`/`0x55`) read/write `symbolic_state`. **PHASE 2.1 (2026-11-07,
partial):** `symbolic_state` is now `HashMap<EVMAddress, SymbolicStorage>` —
keyed by **address** and persistent across frames — with a symbolic key
(`SymbolicStorage::load`/`store`), and the SSTORE operand swap has been fixed
(revm: the key is on top). Measured: a slot the contract writes in a
**previous call** is now solvable with concolic (measured in a previous
session: concolic 1, without 0). **PHASE 2.5 (2026-11-07):** symbolic
**call return values** are now covered — `RETURN` (0xf3) stores the callee's
symbolic memory in the frame, `on_return` splices it into the caller's memory
at the CALL's `return_offset`, and `RETURNDATASIZE`/`RETURNDATACOPY` (0x3d/0x3e)
expose them. The essence: the spliced bytes are the **callee's own** symbolic
memory (tied to the caller's input through the calldata), so the solver inverts
the callee's computation instead of guessing a constant; if `RETURN` is not
fully tracked, it falls back to the **concrete** value. Measured (before→after,
same `--seed`): `this.helper(y)` returns `y*2`, gate `require(r == EVEN)` →
before 0 finds, after `sim-confirmed`; negative control (the gate demands an
ODD value, unreachable) → 0 finds (no false positive). **What remains (R3):**
there are no symbolic `CALL` targets (PHASE 2.2) nor symbolic **balances**;
`keccak256` is not inverted, so a mapping entry from **imported** state remains
unreachable (measured: 0 with and without concolic). Value-conditioned holes
(`require(f(x)==C)` within one frame) were and remain reachable; **state**-
conditioned holes across frames now are too, except through a hash; **return-
value**-conditioned holes across a call now are too. The fixed fixtures:
`tests/evm/concolic_retval/` (positive) and
`tests/evm_never_pass/concolic_retval_unsat/` (negative); note: a large
constant needs `--concolic-timeout` > the default 1000 ms (see LIMITATIONS 3c).

### B4. The economic oracles exist, but EACH is narrowly tied to a PATTERN
`src/evm/oracles/` has 47 files. Invariant oracles **do exist**, but each checks
**one concrete, narrowly recognized pattern**: `eth_backing.rs` (sum of
`balances(addr)` > native balance; requires a `totalSupply()` fingerprint),
`unbacked_mint.rs` (`totalSupply()` grows without a native inflow),
`token_accounting_mismatch.rs` (`transferFrom` + SSTORE with an unverified
amount), `arb_transfer.rs` (unjustified `transferFrom`). **Correction (P4,
2026-11-07):** there now EXISTS a general, configurable invariant — the
declarative oracle `--invariants <file.json>` (`src/evm/oracles/invariant.rs`),
where the user writes the invariant in JSON (operands `native_balance`,
`literal`, `call`, `sum_over_callers`), with no Rust. **What is still missing
(R3):** the built-in economic oracles remain pattern-bound; the declarative
invariant covers only shapes expressible with these operands (e.g.
`sum_over_callers(balanceOf)` vs. `native_balance`), not arbitrary
contract-specific logic.

### B5. Control leak during search (closed for concolic, PHASE 2.4)
`src/evm/host.rs` `call_allow_control_leak`; the choice branch is now
`control_leak_bypassed()` (`host.rs`). For **non-concolic** search the fuzzer
**may** use a faked return value; such a trace is tagged
(`input.call_leak != u32::MAX`) and the pre-flight rejects it as NOT EXTRACTABLE,
but during search it still creates noise (deliberately — it helps find deep
paths).

**PHASE 2.4 (2026-11-07): for concolic the leak is OFF during search.**
`concolic_stage.rs` raises `CONCOLIC_NO_CONTROL_LEAK` for the duration of each
testcase's `vm.execute`, so every call during a concolic execution runs through
the real callee code (`call_forbid_control_leak`) — exactly as on-chain.
Concolic can therefore no longer "solve" a branch reachable only through a
faked return value. Proof: unit test
`host::control_leak_bypass_tests::concolic_flag_forces_control_leak_bypass`
+ E2E `tests/evm/concolic-2/` (cross-contract `CALL`) still finds
`sim-confirmed` `0x3322`; comparison with the baseline at the same `--seed`
shows no regression. **What remains (R3):** for non-concolic search the leak
remains (deliberately); there the label + downgrade still prevent a
`sim-confirmed` presentation.

### B6. No time / ordering / mempool
`src/evm/oracle.rs` (note on the model). Sandwich, backrun, JIT, MEV and
multi-block bugs (TWAP, staleness) are outside the model.

### B7. Empirical "found + proved" evidence — PARTIALLY measured (outside the sandbox)

In the **clean** sandbox of this repository there is no RPC egress, so no run
there can demonstrate "found a real bug on a live target and proved it".

**But the proof WAS measured outside the sandbox:**
`benchmarks/forksploit_full_live_mordor/` is a **full** ForkSploit run directly
against live ETC Mordor (`CyberScratchLottery`, no anvil fork), two independent
seeds of 300 s each, and `benchmarks/echidna_vs_forksploit/` compares ForkSploit
with Echidna on the **same** real contract — both independently find the same
real bug (weak randomness, SWC-120). That is real "found + proved" evidence on a
live target; see also `LIMITATIONS.md` §C2.

---

## 3. Fix plan (by priority)

| # | Fix | Addresses | Difficulty | Status |
|---|---|---|---|---|
| **P1** | Automatic derivation of `setup.json` from a live target | B2 | medium | **DONE (partial)** |
| **P2** | Planner of multi-step sequences (set up→attack) | B1 | high | **DONE (partial)** |
| **P3** | Concolic on storage + return values | B3 | high | **DONE (partial, 2026-11-07)** — symbolic storage by address, persistent across frames (PHASE 2.1); symbolic call return values (PHASE 2.5); balances and `CALL` target still TODO |
| **P4** | A general, configurable invariant oracle (not just a new pattern) | B4 | medium | **DONE** |
| **P6** | Concolic without control leak during search | B5 | low | **DONE (PHASE 2.4, 2026-11-07)** — `CONCOLIC_NO_CONTROL_LEAK`; symbolic `CALL` target (PHASE 2.2) remains TODO |
| **P5** | Empirical proof (found + proved) on a target | B7 | medium | **PARTIAL — measured outside the sandbox** (`benchmarks/`) |

**Execution order:** P1 → P4 → P2 → P3 → P5.
Rationale: P1 unlocks practical use on a live target; P4 adds the most-missed
blind spot (invariants); P2 and P3 are core Rust changes; P5 is the closing
measurement.

### P1 — done (partial, 2026-11-07)

`--auto-setup` (`src/evm/auto_setup.rs`) derives the *wiring* preconditions
(`setX(address)` between deployed contracts) directly from the deployed
contract set -- with no manual `setup.json` and also on the `--target 0x...`
path, which has no fixture directory. The address is chosen: first the one the
contract already contains (`PUSH20`, skipping precompiles `0x01..0x0a`/zero),
otherwise another deployed contract. An explicit `setup.json`/`--setup-file`
always wins.

**Proof (E2E, real binary, no mocks)** —
`python -m unittest onchain_scripts/test_auto_setup.py -v` (2/2 OK):
- on `tests/evm/erc4626/` **without** `setup.json` it derives exactly
  `Vault.setAsset(address)` and executes it before fuzzing;
- without the flag it derives nothing (excludes a false positive).

5 offline unit tests in `src/evm/auto_setup.rs` (PUSH20 scanner, address choice,
rejection of view/non-address setters).

**Limitation (R3):** it does NOT derive value-moving calls (`mint`, `deposit`)
-- a guessed wrong precondition would be misleading; such targets still need a
manual `setup.json`. It only derives `set*(address)` with exactly one `address`
argument. See `LIMITATIONS.md §I` (item 18).

### P2 — done (partial, 2026-11-07)

**Measurement outcome:** multi-step search **already works** via the corpus
genealogy (`TxnTrace::from_idx` recorded in `src/fuzzer.rs`, on by default
under `full_trace` + `print_txn_corpus`; `cov_stage`/`minimizer` reproduce the
sequence). P2 therefore did **not** add a new mechanism, but **measured and
proved** it, and honestly recorded where the boundary is.

**Proof for 2 steps** — `onchain_scripts/test_multistep_planner.py` (3/3 OK)
on `tests/evm/two_step/` (`arm()` then `fire()`; a single transaction never
breaks `value() <= 1`):
- positive: it fires **and** the printed trace contains both `arm()` and
  `fire()` (proof that the right *pair* was found, not one transaction);
- negative (bound `value() <= 2`) does not fire;
- probe fires (proof that the negative result is not a silent non-execution).

**Measured depth** (`onchain_scripts/gen_chain_fixture.py <N> <dir>`,
`-d invariant`, 30 s/run):

| N | 2 | 3 | 4 | 5 | 6 | 8 | 10 | 12 | 16 |
|---|---|---|---|---|---|---|---|---|---|
| Found | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | 6/6 | 4/4 | 4/4 | 4/4 |

**Limitations (R3):** the sequence is a consequence of **corpus evolution**, not
a plan -- there is no targeted construction of preconditions; with **all**
oracles every transaction is more expensive, so deep chains are slow
(**unmeasured** how much less than with `-d invariant`); without
`full_trace`/`print_txn_corpus` there is no genealogy. See `LIMITATIONS.md §I`
(item 19).

### P4 — done (2026-11-07)

Added a declarative, user-configurable invariant oracle:
`src/evm/oracles/invariant.rs`, launched with `--invariants <file.json>`.
The user writes the invariant in JSON (no Rust): operands `native_balance`,
`literal`, `call`, `sum_over_callers`; operators `le/lt/ge/gt/eq/ne`.
A violation is reported as `Invariant Violation` at `sim-confirmed` tier.

**Proof (E2E, real binary, no mocks)** —
`python -m unittest onchain_scripts/test_invariant_oracle.py -v`. The original
P4 proof was a **3-scenario** set; today the file has **9** tests (concolic
regression tests for A6 and PHASE 2.5 were added):
- positive: `tests/evm/eth_backing/` (`creditMyself` without an inflow) → the
  invariant fires (`lhs=1 Le rhs=0 does not hold`);
- negative: `tests/evm_never_pass/invariant_safe/` (a properly backed bank) →
  the invariant does **not** fire (no false alarm);
- probe: a deliberately wrong invariant fires on the **same** safe fixture →
  proves the negative result is a true negative, not a silent non-execution.

5 new offline unit tests in `invariant.rs`; the total `cargo test --release` is
now **140 passed, 10 failed** (10 = the existing network/state-dependent tests).

---

## 4. Success criteria (how we know a fix is real)

- P1: `--target 0x...` with no manual `setup.json` produces pre-fuzz calls from
  live state; measured on a fixture where nothing was found before.
- P4: at least one new oracle fires on a known test case (regression test).
- P2: the fuzzer finds a pair (set up, attack) that the single-transaction model
  does not. **MET (2026-11-07):** `test_multistep_planner.py` (a 2-step pair) +
  measured depth up to 16 steps.
- P3: z3 solves a `require(sload(k)==C)` condition in a test.
- P5: one reproducible "found + proved" run on a target (or a documented,
  honest obstacle if the environment does not allow it).

**R1/R4:** every step is finished only once it is measured. Anything not
measured stays labelled **unmeasured**.

---


## 5. Detailed analysis and fix plan for ALL blockers (P1–P5)

**Everything in this chapter is written in bold text (a requirement of the task).**

**The chapter does NOT change code — it is exclusively analysis and a plan.**

**All effort numbers are ENGINEERING ESTIMATES, not measurements; they are marked [ESTIMATE]. What is verified from code is marked [CODE].**

---

### 5.1 Estimation methodology

**Every blocker is broken down into concrete subtasks. Each subtask has: (a) what exactly needs to be done, (b) where in the code it touches, (c) an effort estimate [ESTIMATE], (d) risk, (e) dependencies, (f) proof of success (R1). The subtasks are sorted into three classes: ENGINEERING (a known recipe, estimable), RESEARCH (an open problem, high risk) and OPERATIONS (execution on a live target).**

**The shared code the blockers touch [CODE]: concolic_host.rs (2195 lines), host.rs (2877), fuzzer.rs (797), setup.rs (360), auto_setup.rs (253), invariant.rs (435), multicore.rs (419), concolic_stage.rs (343). Total repository: 49,318 lines of Rust + 13,677 lines of Python [CODE].**

---

### 5.2 B1 — The input is ONE transaction (the biggest blocker)

**Current state [CODE]: struct EVMInput (src/evm/input.rs) describes one transaction. Multi-step behaviour arises indirectly through the corpus genealogy (TxnTrace::from_idx in fuzzer.rs, on by default under full_trace + print_txn_corpus). Measured depth: up to 16 steps on a generated fixture. There is no planner that would targetedly construct preconditions.**

**Breakdown into subtasks:**

**B1.1 [ENGINEERING] — An explicit "sequence planner" for KNOWN dependency families. What: in strategy_layer.py (Python) order_steps_by_dependencies already exists (approve→transferFrom, deposit→withdraw); the Rust side would need the same logic when generating a plan, so that it places preconditions IN THE SAME plan, not only at merge time. Where: src/evm/solution/script_generator.rs, onchain_scripts/strategy_layer.py. Effort: [ESTIMATE] 3–4 weeks. Risk: medium. Proof: a new fixture where success is possible only with a targeted order; the regression test test_multistep_planner.py extended.**

**B1.2 [RESEARCH] — A general planner with data flow between arguments (output of step A → input of step B). What: a model that tracks how a value (address, amount) is carried from one step to the next, not just the order of selectors. Where: a new component in Rust + strategy_layer._thread_address_arguments extended. Effort: [ESTIMATE] 4–8 weeks for "lite" (limited families); OPEN for the general case. Risk: very high. Proof: a fixture where the output of A (e.g. a newly deployed address) must really be inserted into the calldata of B.**

**B1 fix plan: first B1.1 (known families) — this covers most real multi-step attacks (unlock→use→drain, approve→transferFrom, deposit→withdraw); B1.2 (general data flow) is NOT promised, but documented as long-term research. Success criterion: one merged plan that by itself breaks an invariant where a single transaction cannot.**

---

### 5.3 B2 — setup.json is HAND-WRITTEN

**Current state [CODE]: setup.json is loaded only from the fixture directory (contract_utils.rs, path_str.ends_with("setup.json")); the --target 0x… path sets setup_spec: None. --auto-setup (auto_setup.rs) derives ONLY set*(address) with exactly one address argument (filters: is_static, is_payable, is_constructor excluded; abi == "(address)"; name starts with set). It does NOT derive value seeds (mint, deposit) nor constructor arguments; auto_pipeline.py has no --constructor-args (only Rust EvmArgs has it).**

**Breakdown into subtasks:**

**B2.1 [ENGINEERING] — Derivation of value seeds from ABI + state. What: for mint(address,uint256)/deposit(uint256,address) derive the amount from existing state (e.g. totalSupply(), balanceOf), do not guess. Where: src/evm/auto_setup.rs (derive_setup_spec). Effort: [ESTIMATE] 1–2 weeks. Risk: medium (a guessed wrong precondition is worse than none — that is why the code deliberately skips this). Proof: on tests/evm/erc4626/ with --auto-setup (no manual setup.json) the oracle fires.**

**B2.2 [ENGINEERING] — Constructor arguments on the --target path. What: auto_pipeline.py should support --constructor-args (already exists in Rust EvmArgs, missing in the Python orchestration). Where: onchain_scripts/auto_pipeline.py (build_parser, deploy). Effort: [ESTIMATE] 2–4 days. Risk: low. Proof: deploy a fixture with a non-trivial constructor.**

**B2.3 [ENGINEERING] — Derivation of wiring beyond set*(address). What: support initialize(address,address), setPair(token0,token1) with two addresses. Where: auto_setup.rs. Effort: [ESTIMATE] 1 week. Risk: medium. Proof: a fixture with two address arguments.**

**B2 fix plan: B2.1 + B2.2 + B2.3 together ≈ 2–3 weeks; this closes practically most "wiring + funding" preconditions. A manual setup.json remains only for fully specific protocol sequences.**

---

### 5.4 B3 — Concolic (Z3) is narrow

**Current state [CODE]: symbolic are calldata, callvalue, caller, origin, memory, storage (symbolic key, persistent across frames) and call return values (PHASE 2.1/2.5). In concolic_host.rs: SHA3 (0x20) is concrete_eval!(2, 1) → keccak256 is NOT inverted; BALANCE (0x31) is concrete_eval!(1, 1) → balances are not symbolic; push_ctx reads the address from the concrete stack → the CALL target is not symbolic.**

**Breakdown into subtasks:**

**B3.1 [ENGINEERING] — Symbolic CALL target (PHASE 2.2). What: if the address on the stack is symbolic, model it as a BV and constrain it to "a deployed contract / a known address". Where: concolic_host.rs (push_ctx, construct_input_from_abi). Effort: [ESTIMATE] 1–2 weeks. Risk: medium (combinatorial explosion of possible targets). Proof: a gate that requires a call to exactly one contract out of several; concolic solves it.**

**B3.2 [ENGINEERING] — Symbolic balances (PHASE 2.6). What: BALANCE (0x31) should return a symbolic BV tied to symbolic_state/balance_cache, not a concrete one. Where: concolic_host.rs opcode 0x31. Effort: [ESTIMATE] ~1 week. Risk: low–medium. Proof: a gate require(self.balance == C); concolic solves it.**

**B3.3 [RESEARCH] — keccak256 preimage (a mapping entry from imported state). What: Z3 has no native keccak; modelling it as a bit circuit is explosive. Where: concolic_host.rs opcode 0x20. Effort: [ESTIMATE] months / possibly UNREACHABLE. Risk: very high. Recommendation: do NOT promise; document as a permanent limitation (already in LIMITATIONS.md §A5). Alternative [ESTIMATE] 2–3 weeks: special-case reading a known (contract, slot) pair from imported state via storage-layout (PHASE 4), not via hash inversion.**

**B3 fix plan: B3.1 + B3.2 ≈ 2–3 weeks and open cross-contract paths (the biggest practical value). B3.3 is NOT planned as an engineering fix — it is a research problem; instead the storage-layout alternative (PHASE 4) covers the most common real case.**

---

### 5.5 B4 — The economic oracles are pattern-bound

**Current state [CODE]: 47 oracles, each checks one pattern (eth_backing, unbacked_mint, token_accounting_mismatch, arb_transfer). The declarative invariant (invariant.rs, --invariants) has been added (P4), but it supports only the operands native_balance, literal, call, sum_over_callers — there is no operand for reading an arbitrary storage slot nor for multi-step expressions.**

**Breakdown into subtasks:**

**B4.1 [ENGINEERING] — A new operand storage_slot(contract, slot). What: the invariant should read an arbitrary storage slot as an operand. Where: src/evm/oracles/invariant.rs (Operand, evaluation). Effort: [ESTIMATE] ~1 week. Risk: low. Proof: an invariant comparing a slot to totalSupply().**

**B4.2 [ENGINEERING] — Arithmetic expressions between operands (addition, multiplication). What: e.g. sum_over_callers(balanceOf) * price <= native_balance. Where: invariant.rs (a new Expr layer). Effort: [ESTIMATE] 1–2 weeks. Risk: medium. Proof: an invariant with a product.**

**B4.3 [RESEARCH] — General semantic understanding of the protocol. What: it would require understanding a SPECIFIC protocol (Aave collateral factor vs. Compound) — contrary to the "bytecode-only" identity. Effort: [ESTIMATE] open. Recommendation: NO (out of scope per new-oracle-roadmap.md).**

**B4 fix plan: B4.1 + B4.2 ≈ 2–3 weeks; this extends the declarative invariant to most economic shapes, without going into protocol-specific semantics (B4.3 is rejected as out of scope).**

---

### 5.6 B5 — Control leak during search

**Current state [CODE]: for concolic the leak is off (CONCOLIC_NO_CONTROL_LEAK, PHASE 2.4); for non-concolic search it remains (deliberately), but is tagged (input.call_leak != u32::MAX) and the pre-flight rejects it as NOT EXTRACTABLE, and sim-confirmed never rests on it (PHASE 2.3).**

**Breakdown into subtasks:**

**B5.1 [ENGINEERING] — Rerouting the "leak" path into materialization. What: when the search uses a leak, automatically trigger the materialize_plan.py logic (already exists) to replace the faked call with a real state change. Where: onchain_scripts/auto_pipeline.py + materialize_plan.py. Effort: [ESTIMATE] 1–2 weeks. Risk: medium. Proof: a plan with a leak that is successfully materialized and confirmed.**

**B5.2 [ENGINEERING] — Reducing noise in non-concolic search. What: a depth limit / early exit so the leak does not create too many plans. Where: concolic_stage.rs, host.rs. Effort: [ESTIMATE] 1 week. Risk: low. Proof: a measurement of the decline in the number of leak plans.**

**B5 fix plan: B5.1 (automatic materialization) is key — it turns "leak = useless" into "leak = candidate for materialization". B5.2 is quality of life. ≈ 2–3 weeks.**

---

### 5.7 B6 — No time / ordering / mempool

**Current state [CODE]: the revm model has no mempool, ordering, front-running, multi-block time. Sandwich, backrun, JIT, MEV and multi-block bugs (TWAP, staleness) are outside the model.**

**Breakdown into subtasks:**

**B6.1 [RESEARCH] — A multi-block time model. What: let the fuzzer vary block.timestamp/block.number across blocks (for TWAP/staleness). Where: src/evm/input.rs (Env), host.rs. Effort: [ESTIMATE] 2–3 weeks. Risk: medium. Proof: a TWAP oracle fires only with time variation.**

**B6.2 [RESEARCH] — A mempool/front-running model. What: simulation of competing transactions in the same block. Effort: [ESTIMATE] 4–6 weeks. Risk: high. Recommendation: LOW priority (the task does not require this; oracle.rs already marks it as outside the model).**

**B6 fix plan: B6.1 (time) makes sense for TWAP/staleness oracles; B6.2 (mempool) is a large, low-priority project — document it, do not plan it now.**

---

### 5.8 B7 — Empirical "found + proved" evidence

**Current state [CODE]: in a clean sandbox there is no RPC egress; outside the sandbox it IS measured (benchmarks/forksploit_full_live_mordor/ — a full run on live ETC Mordor; benchmarks/echidna_vs_forksploit/ — a comparison with Echidna, both find the same real bug SWC-120).**

**Breakdown into subtasks:**

**B7.1 [OPERATIONS] — Reproducible "found + proved" on a testnet (Sepolia/Mordor). What: a scripted E2E run with a known vulnerable demo contract. Where: a new script in benchmarks/. Effort: [ESTIMATE] ~1 week. Risk: medium (requires a funded wallet). Proof: a measured increase of the recovery wallet.**

**B7.2 [OPERATIONS] — Automated proof report. What: an aggregate Proof across the whole run (per-plan build_proof already exists). Where: auto_pipeline.py. Effort: [ESTIMATE] 3–5 days. Risk: low.**

**B7 fix plan: B7.1 + B7.2 ≈ 1–1.5 weeks; this closes "the proof was measured" into a reproducible, scripted artifact.**

---

### 5.9 Combined fix plan and priorities

**The table below is entirely bold.**

| **Blocker** | **Class** | **Effort [ESTIMATE]** | **Priority** |
|---|---|---|---|
| **B2.1–B2.3** | **ENGINEERING** | **2–3 weeks** | **1 (highest — practical value)** |
| **B3.1 + B3.2** | **ENGINEERING** | **2–3 weeks** | **2** |
| **B1.1** | **ENGINEERING** | **3–4 weeks** | **3** |
| **B4.1 + B4.2** | **ENGINEERING** | **2–3 weeks** | **4** |
| **B5.1 + B5.2** | **ENGINEERING** | **2–3 weeks** | **5** |
| **B7.1 + B7.2** | **OPERATIONS** | **1–1.5 weeks** | **6** |
| **B6.1** | **RESEARCH** | **2–3 weeks** | **7** |
| **B1.2** | **RESEARCH** | **4–8 weeks / open** | **8** |
| **B6.2** | **RESEARCH** | **4–6 weeks** | **9 (low)** |
| **B3.3 (keccak)** | **RESEARCH** | **months / open** | **10 (document, do not plan)** |
| **B4.3** | **RESEARCH** | **open** | **rejected (out of scope)** |

**Total estimate [ESTIMATE] for the whole engineering part (B2, B3.1–B3.2, B1.1, B4.1–B4.2, B5, B7): ≈ 12–17 weeks of focused work by one engineer. The research part (B1.2, B6.2, B3.3) is OPEN and cannot be honestly time-committed.**

---

### 5.10 Rationale (why this order)

**1. B2 first, because it unlocks practical use on a LIVE target (without a manual setup.json), where the biggest obstacle currently is. 2. B3.1+B3.2 second, because they open cross-contract paths — the most common real attacks are cross-contract. 3. B1.1 third, because multi-step already works (up to 16 steps), only the "directed" construction of preconditions is missing. 4. B4 extends the declarative invariant — cheap, high value. 5. B5 turns a leak from "useless" into "materialize it". 6. B7 closes the proof into a reproducible artifact. 7. The research items (B6.2, B1.2, B3.3) are NOT promised; they are documented as long-term.**

---

### 5.11 Note on the reliability of estimates (R1)

**ALL effort numbers in this chapter are [ESTIMATE] — engineering judgement, NOT measurements. I have not yet attempted to complete any of these blockers, so I mark them as estimates. For a more accurate estimate each subtask would have to be broken down further into sub-subtasks and actually implemented (only then would the estimate be [MEASURED]). What is [CODE] in this chapter is verified from the original code and is fact.**
