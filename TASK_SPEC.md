# AGENT PROMPT — ForkSploit: from a pattern fuzzer to a serious exploitation system

> **Note (2026-11-09):** this is the **original task** (input document), not a
> description of the current state. The list of "known gaps" below reflects the
> state **before** the work; several of them have since been closed or partly
> closed. For the **current, verified** state see `PLAN.md` (phases),
> `LIMITATIONS.md` (open items) and `CHANGELOG.md` (history).

> This document is a **task** for an agent (OpenHands or another). Copy the
> entire content below the line into a new conversation. The purpose is concrete,
> measurable and split into phases that end with evidence (tests, measurements,
> commits), not with promises.

---

## 0. Context and starting point

You are working in the `ForkSploit` repository (Rust + Python, LibAFL, a custom
`revm` fork, z3). The current state is a **bytecode-level searcher for known
patterns with an execution layer** — not a system for discovering and executing
economically real exploits. This has been established and documented; do not
repeat the diagnosis, instead **remove the causes**.

Known, confirmed gaps (verify each one yourself in the code before you start):

1. **No gas measurement.** The `revm` fork runs without gas metering
   (`CLAUDE.md`, "Critical External Dependencies"). Consequence: a plan that
   succeeds in simulation can exceed `block.gasLimit` on the real chain. This has
   already happened (plan `C9f53_2`).
2. **No mempool / ordering / front-running.** Therefore sandwich, backrun, JIT
   liquidity and MEV are outside the model.
3. **Symbolic reasoning (z3) is narrow** (`src/evm/concolic/concolic_host.rs`):
   it covers calldata, `callvalue`, `caller`, `origin`, symbolic *memory*. It
   does **not** cover symbolic storage, symbolic `CALL` targets, symbolic return
   values, symbolic balances.
4. **Control leak**: the fuzzer can intercept a call and *inject* its own return
   value (`call_allow_control_leak` in `src/evm/host.rs`). A trace found this way
   can "prove" a passage through a `require` that does not exist on-chain.
5. **Conflation of the privileged party and the attacker**: the harvest
   heuristic (`HARVESTED_STORAGE_ADDRESSES` in `src/evm/host.rs`) collects
   addresses from the target's storage into the caller pool; the fuzzer can
   become the owner and call owner-only functions. Partly addressed with
   `owner_impersonation`, but the pattern is deeper.
6. **Pattern-based, not semantic**: ~48 oracles recognise ~37 pre-coded bytecode
   patterns. There is no AST/source-level semantics for on-chain targets, no
   understanding of protocol logic, no understanding of storage layout.
7. **Single-threaded** (`src/sync_utils.rs`): the main loop is single-threaded;
   multi-core is not implemented.
8. **Panic-prone** `.unwrap()`/`.expect()` on external data (`CLAUDE.md`: "known
   outstanding hardening work ... not yet addressed").
9. **No formal reporting**: no severity/CVSS, no proof of loss.

Goal: **ForkSploit must become a system that, on the ETH or ETC network, can
execute a found real plan to the last step** — with a reproducible, provable,
gas-evaluated result — and that **never presents an infeasible finding as
feasible**.

---

## 1. Non-negotiable rules (working discipline)

These rules are part of the task. A violation = an unfinished task.

- **R1 — Proof before claim.** Every claim in a commit message, documentation or
  report must be backed by reproducible proof: a test, a measurement, output
  from a real run. No "should work", "probably", "in principle".
- **R2 — No invented results.** If you cannot verify something, write that
  explicitly. Never cite a number you have not measured.
- **R3 — Do not hide limitations.** If you cannot do something in this task,
  write it clearly in `LIMITATIONS.md` with a reason, rather than silently
  omitting it.
- **R4 — Every phase ends with proof.** A phase is not "done" until the tests
  run and a measurement record (before/after) exists.
- **R5 — Backwards compatible.** The existing tests (Rust + Python) must keep
  running. Currently: 8 Rust `solution::` tests (sequential), 33 Python
  `test_preflight_gate` + 19 other suites.
- **R6 — Security is a technical requirement, not decoration.** See section 6. A
  system that executes real transactions must have hard limits, otherwise it is
  dangerous even to its own operator.

---

## 2. Target architecture (what must emerge)

The system must have **five separate, verifiable layers**. Every layer must have
a clear interface so it can be tested independently.

```
[1] SEMANTIC ANALYSIS       -> understands the contract, not just patterns
[2] SEARCH (fuzz+concolic)  -> finds candidates with real constraints
[3] PROOF (gas + state)     -> proves feasibility on real state
[4] EXECUTION (build+send)  -> executes to the last step, with proof
[5] REPORTING               -> severity, proof, reproduction
```

Key principle: **layer 3 is a mandatory gate between 2 and 4.** No plan may
reach layer 4 unless it has passed layer 3 with real gas measurement and real
state replay.

---

## 3. Work phases (by priority; each is a standalone, finished step)

### PHASE 1 — Gas metering and execution reality (CRITICAL, first)

**Problem:** without gas, the simulation lies.

**Task:**
1. Embed **gas metering** into the execution path, so that every generated plan
   carries a **gas estimate and actual gas used** (`gas_estimate`, `gas_used`).
   If the `revm` fork does not allow metering, use `eth_estimateGas` on the fork
   as the authoritative source and document this clearly.
2. Every plan should carry the fields `fits_block_gas_limit: bool` and
   `gas_headroom_pct`.
3. A plan that does not fit in a block must be **tagged** (`oversized_gas`), not
   executed.
4. **Proof:** a test that takes a plan of `C9f53_2`-like shape (exceeds
   `block.gasLimit`) and proves it is now tagged, not "confirmed". Write down a
   before/after measurement.

**Acceptance criterion:** a `sim-confirmed` plan that exceeds gas is never
presented as feasible.

---

### PHASE 2 — Storage-aware symbolic execution (CRITICAL)

**Problem:** z3 does not see storage, so owner-gated and state-dependent paths
are unreachable or fake.

**Task:**
1. Extend `concolic_host.rs`: **symbolic SLOAD/SSTORE** — at least for keys the
   contract reads from calldata (mappings).
2. **Symbolic `CALL` target** — when the call target depends on calldata, model
   it symbolically (up to a predefined depth limit).
3. **Remove or limit the control leak as default behaviour.** Injecting a faked
   return value must be **explicitly off** for `sim-confirmed`; allowed only in
   `sim-review` research and always tagged (`requires_control_leak`, which
   already exists).
4. **Proof:** a test where the path to `require` depends on a value from
   storage; prove that concolic now finds the solution **without** a faked return
   value, or explicitly reports that it cannot be found.

**Acceptance criterion:** a `sim-confirmed` plan never rests on a control leak.

---

### PHASE 3 — Strict separation of attacker / privileged party (CRITICAL)

**Problem:** the fuzzer becomes the owner and reports it as an intrusion.

**Task:**
1. Introduce a **tag for the origin of every address** in a plan:
   `attacker_supplied` | `harvested_from_storage` | `hardcoded_constant`
   | `privileged_role`.
2. Determine `privileged_role` by checking whether the function the address
   calls contains `require(msg.sender == <that address>)` or an equivalent
   (owner/admin/role). This is a **semantic** test, not a heuristic.
3. A plan where **any** caller is `privileged_role` **and** the function is not
   intended for that party to call as part of an attack gets
   `privileged_caller: true` → **never** `sim-confirmed`.
4. **Proof:** a test on an `escapeHatch`-like contract: `owner_impersonation` and
   `privileged_caller` must be `true`, the plan `sim-review`.
5. Upgrade `owner_impersonation` from a boolean into a **structured record**
   (who, from which slot, which `require`), so the report is usable.

**Acceptance criterion:** no plan that relies on a privileged caller is
presented as a feasible attack.

---

### PHASE 4 — Semantic analysis (medium priority)

**Problem:** ~37 bytecode patterns do not cover business logic.

**Task:**
1. For targets with **available source code** (verified bytecode, solc
   artifacts) introduce an **AST path**. `src/evm/blaz/offchain_artifacts.rs`
   already reads solc output — connect it with the analysis.
2. Recognise **economic invariants**: the sum of balances == `totalSupply`,
   collateral >= debt, the AMM `k` must not decrease. Any finding that breaks an
   invariant is **higher** priority than a pattern hit.
3. Recognise the **storage layout** (solc `storage-layout` is already in the
   `--combined-json` list in `offchain_artifacts.rs`) and use it to read
   `owner`/admin slots exactly, **not** to heuristically collect addresses.
4. **Proof:** on a target with a known intentional bug (e.g.
   `ERC20TokenChallenge` or `DEXChallenge` from `test/`) prove that the semantic
   layer finds a bug the pattern layer misses.

**Acceptance criterion:** at least one bug class the pattern layer overlooks is
now found with proof.

---

### PHASE 5 — Proof of feasibility on real state (CRITICAL, "the last step")

**Problem:** "confirmed" in simulation is not "feasible on-chain".

**Task:**
1. Every plan that is a candidate for execution must pass **three gates**:
   - **(a) State replay** on a byte-identical fork of the real state at the
     moment of execution (already exists: `simulate_plan_on_fork`).
   - **(b) Gas reality**: `eth_estimateGas` + `block.gasLimit` + `baseFee` +
     priority fee → the plan must have a positive net profit **after** gas.
   - **(c) Independence from a fake**: no `control_leak`, no
     `privileged_caller`, no `owner_impersonation`.
2. The gate result is a **structured proof**: `{replayed: bool, gas_used,
   net_profit_wei, blockers: [...]}`.
3. **Proof:** a run on target `0x9f5304DA62A5408416Ea58A17a92611019bD5ce3` (ETC)
   — the report must show that **none** of the previous "Fund Loss" plans passes
   the gates (which is the truth: the ledger is empty).
4. **Proof:** on a control test where exploitation *is* possible (e.g. a
   purpose-built `DEXChallenge` with a flash loan), prove that the gates **let
   the plan through** and that it is executed to the end with a real net profit.

**Acceptance criterion:** there exists **at least one** plan that passes all
three gates on a test target and is executed to the last step with a measured
net profit — and **no** false plan does so on the ETC target.

---

### PHASE 6 — Reliability and parallelism (medium priority)

**Task:**
1. Remove all panic-prone `.unwrap()`/`.expect()` on **external** data (RPC,
   ABI, storage, solc output). Each must return a `Result` with a clear message.
2. Introduce **multi-core** fuzzing (LibAFL supports it; currently it is
   deliberately single-threaded). Every thread must have isolated state; global
   state should be `Atomic`/`Mutex` (already partly done).
3. **Proof:** a test that, on a deliberately corrupted RPC response (e.g. an
   empty `result`, `null`, wrong hex), does not panic but returns an error.
4. **Proof:** a speed measurement: N cores → at least ~N times more executed
   cases/second (with a measured number, not a claim).

**Acceptance criterion:** no panic on external data; a parallelism measurement
exists.

---

### PHASE 7 — Reporting and reproduction (medium priority)

**Task:**
1. Every finding gets a **structured report**: `severity` (per
   `VulnerabilityRegistry` categories, if it exists), `confidence_tier`
   (`sim-review`/`sim-confirmed`/`chain-verified`), `proof`
   (`{replay_tx, gas, net_profit}`), `reproduce` (exact steps).
2. Introduce a new, highest label **`chain-verified`** — reserved exclusively
   for a plan that was **really executed on-chain** and moved funds (measured,
   not estimated).
3. **Proof:** a comparison of the report for a false plan (ETC target) and a
   real plan (test target) — the difference must be obvious from the report
   itself.

**Acceptance criterion:** `chain-verified` is never awarded without a measured
movement of funds.

---

### PHASE 8 — Documentation of truth (mandatory, last)

1. Update `CLAUDE.md`, `SKILL.md` and `RUNNING.md` with the **actual** state
   after each phase (not with plans).
2. Write `LIMITATIONS.md`: what the system **still** cannot do, with a reason and
   a suggestion for the next step.
3. Never claim "perfect" or "everything solved" — list what is measured.

---

## 4. Order and success criteria

| Phase | Priority | Blocks execution? |
|------|-----------|------------------|
| 1 — Gas metering | CRITICAL | YES |
| 2 — Storage-aware SMT | CRITICAL | YES |
| 3 — Attacker/privileged | CRITICAL | YES |
| 5 — Proof gate (3 gates) | CRITICAL | YES |
| 4 — Semantic analysis | medium | NO |
| 6 — Reliability/parallelism | medium | NO |
| 7 — Reporting | medium | NO |
| 8 — Documentation | mandatory | NO |

**The task is successful when:** there exists at least one plan that on a **test**
target passes all three gates (state replay, gas reality, independence from a
fake) and is executed to the last step with a **measured net profit**; and when
**no** false plan from the ETC target can do so. Everything else is an
intermediate step.

---

## 5. What not to do

- **Do not** remove the harvest heuristic just because it makes false positives
  — without it the fuzzer does not reach owner-gated code. Instead **tag** it and
  **limit** it to the research level (phases 2 and 3).
- **Do not** add new oracles until phases 1–3 and 5 are closed. More patterns on
  a false execution model mean more false positives, not more truth.
- **Do not** report "confirmed" without gas and a real state replay.
- **Do not** write "done" in a commit message unless you have run the tests and
  written down the measurements.

---

## 6. Security requirements (technically mandatory)

The system will sign and send **real** transactions. It must therefore have:

1. **An authorization scope.** Execution is allowed **only** for targets
   pre-registered in the `wallet_policy.py` register, and only for registered
   chains. Default: **reject**. (`enforce_wallet_policy` already exists — extend
   it to targets, not only wallets.)
2. **Pre-flight is mandatory.** No plan goes on-chain without passing layer 3.
   `--no-preflight` should be **removed** or renamed to
   `--i-know-what-i-am-doing` with additional confirmation.
3. **Hard spending limits.** Maximum gas per transaction, maximum gas per run,
   maximum `value` per transaction — all configurable, all **conservatively by
   default**, all checked **before** signing.
4. **Simulation before every signature.** Every transaction is first simulated
   (`eth_call` / fork replay) and signed only on success.
5. **Idempotency / nonce discipline.** The nonce is managed explicitly; on error
   it is not blindly retried.
6. **Audit log.** Every real transaction is recorded: when, on what, which plan,
   hash, outcome, gas. Without exception.
7. **Never send to a target that is not explicitly listed in the task.** The
   default mode of operation is **fork-only**; real execution is opt-in per
   target.
8. **No hiding of errors.** If the gates reject a plan, the reason must be
   written and visible, not silently omitted.

These requirements are not decoration: without them, "a system that executes any
plan" means "a tool that can lose money on a bug". A serious system has limits
**because** it is serious.

---

## 7. Report format at the end

When you finish (or when you finish an individual phase), report
**structurally**:

```
PHASE <n>: <name>
STATUS: done | partial | blocked
CHANGES: <files, commits>
PROOF: <test, before/after measurement, output from a real run>
LIMITATIONS: <what still does not work and why>
NEXT STEP: <concrete>
```

Without this format the report is not accepted.

---

## 8. The first step to take immediately

1. Read `CLAUDE.md`, `SKILL.md`, `README.md`, `onchain_scripts/auto_pipeline.py`
   and `src/evm/host.rs`.
2. Verify **each** of the 9 gaps from section 0 in the code — and write down
   exactly where it is (file:line).
3. Make a `PLAN.md` with a step-by-step breakdown of phases 1–8, with an effort
   estimate and dependencies.
4. Start with **PHASE 1** (gas metering), because it blocks everything else.
5. After each phase: tests, measurements, a commit with proof in the message.

Start now.
