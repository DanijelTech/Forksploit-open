# PLAN_JSON — reference for the `*.plan.json` schema

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it. See [`DISCLAIMER.md`](../DISCLAIMER.md).**

> Standalone document. Related: [RUST_PYTHON_WIRING.md](RUST_PYTHON_WIRING.md),
> [ATTACKWALLET.md](ATTACKWALLET.md), [ORACLES.md](ORACLES.md).

The schema is defined in `src/evm/solution/script_generator.rs` (the
`ExploitPlan` and `PlanMeta` structs, `write_plan`) and in `PlanStep`. Every
`*.plan.json` is written with `serde_json::to_writer_pretty` (pretty-printed
JSON).

---

## 1. Location and name

* Directory: `<work_dir>/vulnerabilities/`
* Name: `{contract_name}.plan.json`, where `contract_name` comes from
  `src/evm/solution/mod.rs::TemplateArgs::new`
  (`format!("{}_{}", make_contract_name(cli_args), BUG_COUNTER.fetch_add(1, ...))`).

`make_contract_name(cli_args)` derives the base name from the target address or
path; `BUG_COUNTER` is a global `AtomicU64` that ensures the name is not
duplicated.

---

## 2. Top-level schema (`ExploitPlan`)

```json
{
  "contract_name": "C1Bac_3",
  "kind": "flat",
  "needs_funding": false,
  "total_value": "0",
  "steps": [ /* PlanStep[] */ ],
  "full_trace_steps": [ /* PlanStep[] */ ],
  "repeat_step": null,
  "bug_types": ["Unauthorized ERC20 Transfer"],
  "confidence": "sim-confirmed",
  "confirmed_exploitable": true,
  "atomic_replayable": true,
  "requires_control_leak": false,
  "distinct_callers": 1,
  "callers": ["0x…"],
  "owner_impersonation": false,
  "owner_impersonation_detail": [],
  "owner_gated": false,
  "owner_gated_detail": [],
  "step_count": 2,
  "target": "0x…",
  "chain": "sepolia"
}
```

The fields from `#[serde(flatten)] meta: PlanMeta` are at the same level as
`contract_name`/`kind`/... (that is why `bug_types`, `confidence`, ... are not
nested).

---

## 3. Fields — description and source

| Field | Type | Source in code | Description |
|-------|-----|-----------|------|
| `contract_name` | str | `TemplateArgs::contract_name` | a name with a unique counter |
| `kind` | `"flat"` \| `"reentrancy"` | `generate_exploit_plan`/`generate_reentrancy_exploit_plan` | the attack shape |
| `needs_funding` | bool | `TemplateArgs::needs_funding` | whether the trace carries `value > 0` |
| `total_value` | str | the sum of `Tx::value` | total value (wei, as a string) |
| `steps` | PlanStep[] | `Tx::from` on the minimized trace | the minimal proof |
| `full_trace_steps` | PlanStep[] | the unminimized trace | for merging |
| `repeat_step` | PlanStep \| null | `split_reentrant_trace` | the repeated call for `receive()` |
| `bug_types` | str[] | `parse_bug_report(&args.solution)` | all bug types of the finding |
| `confidence` | `"sim-confirmed"` \| `"sim-review"` | `build_plan_meta` | the confidence level |
| `confirmed_exploitable` | bool | `is_confirmed_exploitable_bug` | whether it is exploitable |
| `atomic_replayable` | bool | `!requires_control_leak` | whether AttackWallet can replay it |
| `requires_control_leak` | bool | `trace_depends_on_control_leak` | dependency on a faked return |
| `distinct_callers` | int | `callers.len()` | the number of distinct callers |
| `callers` | str[] | unique `Tx::caller` | ordered, deduplicated |
| `owner_impersonation` | bool | `is_harvested_storage_address` (any) | a caller from the target's storage |
| `owner_impersonation_detail` | ImpersonatedCaller[] | `harvested_address_origin` | the origin |
| `owner_gated` | bool | `is_harvested_sender_for` (per step) | the semantic owner-gated test |
| `owner_gated_detail` | ImpersonatedCaller[] | `is_harvested_sender_for` | the origin |
| `step_count` | int | `trace.len()` | the number of steps |
| `target` | str | `CliArgs::target` | the target address/path |
| `chain` | str | `CliArgs::chain` | the chain name |

---

## 4. `PlanStep`

```json
{
  "contract": "0x…",
  "calldata": "0x…",
  "value": "0",
  "caller": "0x…",
  "fn_selector": "0x23b872dd",
  "stolen_asset": null,
  "call_leak": 4294967295
}
```

| Field | Type | Description |
|-------|-----|------|
| `contract` | str | the target address of the call |
| `calldata` | str | calldata (hex, `0x`) |
| `value` | str | value (wei, as a string) |
| `caller` | str | the `msg.sender` the step was recorded with |
| `fn_selector` | str | the 4-byte selector (hex, `0x`) |
| `stolen_asset` | str \| null | the ERC-20 address if the step is a recognised money-mover (`erc20_token_touched`) |
| `call_leak` | u32 | `4294967295` (`u32::MAX`) = no control leak; anything else = found with a faked return |

---

## 5. `ImpersonatedCaller`

```json
{
  "caller": "0x…",
  "harvested_from_contract": "0x…",
  "harvested_from_slot": "0x000…000"
}
```

If the origin was not recorded, the label `"unknown"` is used.

---

## 6. Rules the schema encodes

1. **`confidence` = `sim-review` if `requires_control_leak`** — regardless of
   bug_type (`build_plan_meta`, PHASE 2.3). `bug_types` is still populated as an
   honest proof.
2. **`atomic_replayable` = `!requires_control_leak`** — AttackWallet cannot
   replay a faked return.
3. **`owner_impersonation`** is `any`, not `all` — a single harvested caller is
   enough (the documented real case had two callers).
4. **`owner_gated`** is stricter than `owner_impersonation`: it requires the
   caller to be harvested from the **same** contract being called.
5. **A `plan.json` is written for every finding**, including Review-tier and
   multi-caller; the "execute or not" decision is on the Python side.

---

## 7. Fields Python adds (the feedback loop)

After reading a plan, `auto_pipeline.main` **rewrites** `plan.json` and adds:

| Field | Source |
|-------|-----|
| `gas_estimate` | `estimate_plan_gas_on_fork` (the largest single step) |
| `fits_block_gas_limit` | `gas_fit` |
| `gas_headroom_pct` | `gas_fit` |
| `block_gas_limit` | fork `eth.get_block("latest")["gasLimit"]` |
| `gas_used` | the actual gas units used (or the fork estimate if nothing was sent) |

These fields are **not** present in the original Rust output.

---

## 8. The difference between `steps` and `full_trace_steps`

* `steps` is the output of `SequentialMinimizer` — the smallest sequence that
  re-fires the oracle. Suitable for a `forge test` reproduction.
* `full_trace_steps` is the **unminimized** trace (`generate_test_with_full_trace`
  receives `full_trace`). The minimizer removes early setup calls (approve,
  ownership transfer) that a composed attack needs.
* `strategy_layer._steps_of` prefers `full_trace_steps`.
* The metadata (`step_count`, `distinct_callers`) describes the **same** trace
  the plan serializes (`build_plan_meta` receives `meta_source`, which is
  `full_trace` when it exists).

---

## 9. Diagram: how plan.json comes to be

```mermaid
flowchart TD
    A[oracle returns a bug_idx] --> B[OracleFeedback → Solution]
    B --> C[SequentialMinimizer.minimize]
    C --> D[prettify_concise_inputs]
    D --> E[generate_test_with_full_trace]
    E --> F[write .t.sol]
    E --> G{reentrancy?}
    G -->|yes| H[generate_reentrancy_exploit_plan]
    G -->|no| I[generate_exploit_plan]
    H --> J[write_plan → *.plan.json]
    I --> J
    E --> K{Confirmed + no leak + one caller?}
    K -->|yes| L[generate_script → *.s.sol]
```

---

## 10. Open / unmeasured

* **Unverified:** whether any consumer reads the `composed_from` field (it is
  added only by `strategy_layer.compose_plan` in Python, not Rust). It is not in
  the Rust schema.
* **Unmeasured:** this document does not state plan sizes nor the number of
  plans per run.
* The `evidence` field in `vuln_info.jsonl` (not in `plan.json`) is
  `"replayable_transaction_trace"` (`src/evm/oracle.rs::EVMBugResult::to_value`).
