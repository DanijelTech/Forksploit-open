# AGENTS.md — ForkSploit repository knowledge

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it. See [`DISCLAIMER.md`](DISCLAIMER.md).**

Persistent, repository-specific context for agents. See `CLAUDE.md` for the
full architecture and `TASK_SPEC.md` for the task specification
(in Slovenian). `PLAN.md` tracks progress per phase; `LIMITATIONS.md` lists
what the system still cannot do (and why).

## Working rule R1 — proof before claim

Never write "done" in a commit, doc, or report without a reproducible proof
(test, measurement, or command output). Anything not measured is labelled
**neizmerjeno** (unmeasured).

## Build and test

```bash
cargo build --release            # must end with 0 errors, 0 project warnings
cargo test --release             # see "Known failing tests" below
cd onchain_scripts && python -m pytest -q   # Python side: 232 passed
```

Rust is pinned via `rust-toolchain.toml` to **`nightly-2026-10-15`**. Long
test runs exceed the terminal soft timeout; run them in the background and
poll a log file.

### Known failing tests (not code bugs)

`cargo test --release` reports **140 passed, 10 failed**. All 10 depend on a
live public RPC endpoint **or** on a pinned live balance, and fail **even with
network egress** (measured) — they are not usable as gates:

- `evm::tokens::onchain_pair_discovery::tests::*` (8 tests)
- `evm::tokens::uniswap::tests::{test_get_pair, test_fetch_uniswap_path}`
- `evm::onchain::endpoints::tests::test_get_balance` (compares a hardcoded
  live balance that has since changed)

The CI workflow skips exactly these (`--skip ...`). Treat them as the
baseline. Any *other* failure is a regression.

The offline (network-free) test count only grows as phases add tests
(`src/evm/oracles/invariant.rs`, `src/evm/auto_setup.rs`,
`src/evm/multicore.rs` per-job concolic-thread budget + cap tests, and others);
re-read the actual `cargo test` summary rather than trusting a number written
here.

### Build is warning-clean

`cargo build --release` emits **zero project warnings** for the default build
and for every CI/Docker feature combination
(`cmp dataflow evm print_txn_corpus full_trace force_cache real_balance`,
`... print_txn_corpus full_trace`, `... print_logs`). The only remaining
output is the third-party future-incompat notice for `libafl 0.11.2` /
`nom 2.2.1`, which is not this repository's code. Keep it that way: treat any
new warning as a regression. `cargo test --release` additionally reports the
pre-existing `unused dependency criterion` manifest lint (criterion is used
only by `benches/`); it is present on the unmodified tree too.

### Interactive entry point (`forksploit.sh`)

`forksploit.sh` is the one interactive entry point: a logo banner, then a
preflight "doctor" (OS/package-manager detection, checks for
z3/pkg-config/clang/cmake, Rust, python3 + `onchain_scripts/requirements.txt`,
and the built binary), then a **persistent MAIN MENU** whose entries open
their own submenus/pages, then -- for a run -- a 7-step wizard (chain menu ->
RPC -> funding key -> targets -> recovery wallet -> wallet policy -> mainnet
confirm), then a read-back summary the user confirms before `auto_pipeline.py`
/ `batch_pipeline.py` is `exec`'d. The main menu is the usability layer the
tool was missing: it no longer assumes the user re-reads the source to know
what to do.

Main menu (entry numbers are also the `MAIN_*` constants in the test):

```
1) New run           -> the 7-step run wizard
2) Settings          -> set the default key file / a per-chain RPC override
3) Check environment -> the FULL doctor report on its own page
4) Help              -> what the tool does and what each step means
5) Advanced settings -> advanced run settings (persisted)
6) Tools             -> the OTHER onchain_scripts/ tools (monitor, triage,
                        materialize, dashboard, DEX scanner, chain fixture)
exit / q             -> quit
```

Entries 1–4 and the `Settings` submenu's three entries are UNCHANGED (the
wizard test pins those numbers). The two new entries were APPENDED (5, 6) so
no existing number moved.

**Advanced settings (entry 5).** A small JSON file
(`onchain_scripts/forksploit_settings.json`, gitignored, never holds secrets)
persists: `FUZZ_SECONDS`, `DETECTORS`, `FUND_ETH`, `NO_PREFLIGHT`,
`NO_GAS_ORACLE` and the default key path. Each maps 1:1 onto a REAL
`auto_pipeline.py` / `batch_pipeline.py` flag. An empty value means "unset",
so `build_advanced_flags` adds NOTHING and the built command is byte-identical
to before this feature. Verified by
`test_forksploit_wizard.py::test_default_command_is_unchanged_without_advanced_settings`.

**Tools (entry 6).** Launches `monitor.py`, `triage_findings.py`,
`materialize_plan.py`, `dashboard_server.py`, `dex_arbitrage_scanner.py` and
`gen_chain_fixture.py` -- the tools the wizard never ran. Each prints the exact
command and runs it only after an explicit `da`. The **Materialize** entry runs
the materialize analysis, then offers to open the dashboard GUI; the
**Dashboard** entry starts the GUI on port **4114** (never 8765) and opens the
browser.

**`onchain_scripts/server_run.sh`** is the one place the GUI launch lives
(both the Dashboard entry and Materialize's "open the GUI" call it). It binds
`127.0.0.1` only, picks the next free port when 4114 is taken by ANOTHER
service (never hijacks a foreign port), reuses 4114 if OUR dashboard already
runs there (never starts a second copy), waits until the server accepts
connections, then opens the browser (`xdg-open`/`open`/`wslview`; if none,
prints the URL). `dashboard_server.py --port` default is 4114.

**Dashboard GUI = projection + control only.** `dashboard_static/`
(`index.html`/`app.js`/`style.css`) is a modern sidebar shell: a fixed left
nav with three submenus -- *Management* (Overview, Run an operation, Active
runs, Console), *Settings and configuration* (Wallet policy, RPC overrides,
Contracts), *Results* (Findings, Run logs, Processes) -- a hash router, and
the live ETH/ETC network badge + watermark. It holds NO system logic: every
view renders a `/api/state` key and every button calls a server endpoint that
runs the real CLI script as a subprocess. The frontend hardcodes no address or
chain id. `test_dashboard_ui.py` pins this contract (every nav entry has a
view, every state key has a renderer, every operation has a control, no
hardcoded address/chain id).

`Settings`, `Check environment` and `Help` render on their own page
(`new_page` + `matrix_logo`) and return to the main menu; the doctor page
prints the full checklist by setting `CHECK_FULL=1` for the duration of
`check_env` (the wizard preflight keeps the compact form). `reset_run_state`
clears every wizard answer before each run, so a second run started from the
menu can never inherit a stale chain/key/target. When the wizard's final
`exec` would run in `--dry-run` it prints the command and returns to the main
menu; a real (non-dry-run) run `exec`s and never returns.

Navigation is by WORD: `back`/`0` (previous), `main menu`/`MM`, and
`exit`/`q`. `menu()` takes `--root` for the main menu (which has no "back"
and no "main menu"), and `menu()`/`prompt_nav` treat a `read` failure (EOF) as
"quit" so the wizard can never spin on a closed stdin.

**Bug fixed while adding the menu (2026-11-09):** `menu()` used to bind the
nav shortcuts to the numbers `1`/`2`/`3` as well as the words, so the first
three entries of ANY menu were unreachable by number -- and the network-kind
submenu has exactly two entries, so it could not be selected at all (the `1`
went to "back", the `2` to "main menu"). Numbers now select entries only;
nav is word-only (`0` is the sole numeric alias, for "back"). The wizard
steps distinguish `quit` (2) from `main_menu` (3) so "main menu" actually
returns to the menu instead of aborting the run.

It only ever *offers* installs (exact
per-OS command, one y/n each) -- nothing is installed silently; `--no-install`
reports only, `--dry-run` prints the final command instead of running it, and
`--doctor` runs just the preflight. User input is passed to Python as
`sys.argv` (never interpolated into a `-c` string), so a key path or RPC URL
containing a quote is safe. `prompt_nav`/`menu` treat a `read` failure (EOF)
as "quit" so the wizard can never spin on a closed stdin.

Presentation (kept readable for a first-time user, not just an expert):
the preflight prints the FULL pass/fail checklist only under `--doctor`; in
the wizard it prints only what needs attention (plus a one-line verdict), so
the first menu is not buried under a wall of `ok` rows. Prose lines are
hard-wrapped to the terminal width (`gut_wrap`) and fixed-width list rows are
truncated, never wrapped (`gut_fit`), so text never overflows or overlaps.
The chain menu is a two-level submenu, each level on its own page: page 1
picks the network kind ("Test networks" / "Main networks"); choosing one
opens page 2 (`new_page`, breadcrumb `1/7 · CHAIN › …`) listing that kind's
chains in a compact multi-column grid (`menu()` fills as many `NN) Name`
columns as the width allows), so 21 chains are a few short rows, not a
single-column wall. Chain names are short and human (`CHAIN_TITLES` /
`chain_title()` in `chains.py`, e.g. "Ethereum Classic", not the raw slug);
the kind is the page, so rows carry no `[testnet]`/`[mainnet]` tag, and the
loud ETH/ETC warning is not repeated (the short title already disambiguates;
the warning is still enforced at the mainnet confirmation step and by
`require_mainnet_confirmation()`). `0`/`back` steps back one level, `q`
quits. Every `prompt_nav` prompt carries a `(back = previous step · exit =
abort)` hint, so navigation is discoverable without the removed intro line.
A bare Enter at page 1 defaults to testnets; at page 2 to `sepolia`
(`MENU_DEFAULT_VAL`).

Proof: `python -m unittest onchain_scripts/test_forksploit_wizard.py -v`
(17/17) drives the real script over stdin with `--dry-run --no-install` (no
network, no wallet) and asserts on its actual output: the main menu lists its
entries and a submenu entry is selected by number (the nav-key regression),
the kind submenu opens on its own page, the help/doctor pages render, and the
wizard still builds the exact `auto_pipeline.py` / `batch_pipeline.py`
command. It also checks that the removed intro lines are gone and that the
menu titles appear.

### Auto-derived setup (`--auto-setup`)

`src/evm/auto_setup.rs` derives the *wiring* preconditions (`setX(address)`
links between deployed contracts) directly from the deployed contract set,
so a multi-contract target no longer needs a hand-written `setup.json` -- and
the `--target 0x...` path, which has no fixture directory, gets them too.
An address already referenced by the contract's own bytecode (`PUSH20`,
skipping precompiles `0x01..0x0a` and zero) is preferred; otherwise another
deployed contract is used. An explicit `setup.json`/`--setup-file` always
wins. It deliberately does NOT guess value-moving seeds (`mint`, `deposit`) --
those depend on the target's economics and a wrong guess is worse than none.

Proof: `python -m unittest onchain_scripts/test_auto_setup.py -v` (2/2) on
`tests/evm/erc4626/` with `setup.json` removed -- derives `Vault.setAsset`.

### Multi-step (setup -> attack) search

`EVMInput` is one transaction, but multi-step bugs are still reached: every
execution records `TxnTrace::from_idx` (parent) + a concise tx record in
`src/fuzzer.rs` (default features `full_trace` + `print_txn_corpus`), and
`cov_stage`/`minimizer` replay the sequence (root -> setup -> attack). Proof:
`python -m unittest onchain_scripts.test_multistep_planner -v` (3/3) on
`tests/evm/two_step/` -- `arm()` then `fire()` is the only way to break
`value() <= 1`; the fired trace must contain BOTH calls. Measured depth (chain
fixtures from `onchain_scripts/gen_chain_fixture.py <N> <dir>`, `-d invariant`,
30s): 2-6 steps 8/8, 8 steps 6/6, 10-16 steps 4/4. The sequence is an
evolution by-product, not a planner; with all oracles it is slower.

### Declarative invariant oracle (`--invariants <file.json>`)

`src/evm/oracles/invariant.rs` lets a user express a target's own economic
invariant in JSON (no Rust), evaluated after every non-reverted transaction.
This closes the gap where an economic bug outside the built-in fingerprints
(`eth_backing`, `unbacked_mint`, `token_accounting_mismatch`, ...) is simply
unchecked. Operands: `native_balance`, `literal`, `call`, `sum_over_callers`;
ops `le/lt/ge/gt/eq/ne`. A violation is reported at `sim-confirmed` tier.

**`sim-confirmed` is only as sound as the state the transaction ran against.**
A false positive was found and fixed (2026-11-07): the concolic stage used to
run on raw corpus seeds, which carry `StagedVMState::new_uninitialized()` --
an EMPTY world state where every storage slot reads 0. A gate like
`require(x * x == secret)` then passes with `x == 0`, and the emitted
concolic solution (evaluated directly, not through the mutator's
`get_infant_state`) made the oracle see a post-state write that never happens
on-chain. The stage now skips uninitialized testcases
(`src/evm/concolic/concolic_stage.rs`). This closes THAT path; it does not
make concolic fully storage-aware (PHASE 2 remains partly open -- see below).

**Symbolic storage, PHASE 2.1 (2026-11-07).** `symbolic_state` is now
`HashMap<EVMAddress, SymbolicStorage>` on `ConcolicHost` (NOT per-frame in
`ConcolicCallCtx`): EVM storage is addressed by contract, so a slot written
in one call must stay readable from a later call in the same transaction
(`this.f()` self-call, DELEGATECALL). `SymbolicStorage` keeps the old
concrete map (R5) and adds a symbolic-keyed list matched by structural
equality. Two bugs fixed along the way:

1. **SSTORE operands were swapped.** revm's handler is
   `pop!(interpreter, index, value)` -- the KEY is on top (`peek(0)`), the
   VALUE beneath (`peek(1)`). The old code read them the other way, so every
   symbolic store was filed under the wrong slot and no SLOAD found it.
   (`src/evm/concolic/concolic_host.rs`, opcode 0x55.)
2. **Storage was per-frame.** `push_ctx` reset it, losing the symbolic link
   across a call boundary.

Measured (R1, release binary, `--concolic` vs without):
`a(x){ stored = x*2; this.b(); } b(){ require(stored == BIG); solved = 1; }`
with a 32-byte BIG: concolic finds it (`violations: 1`), without concolic
does not (`violations: 0`) -- so the find is genuinely concolic. A mapping
keyed by calldata and WRITTEN in the same tx (`m[k] = v*2; require(m[k]==BIG)`)
is also solved. STILL OPEN: `keccak256` is `concrete_eval!` (not modelled),
so a mapping entry that existed BEFORE the tx (`require(m[k]==1)` for
attacker-chosen `k`) stays unreachable -- inverting the hash would be needed.
See `LIMITATIONS.md` 3/3b and `BLOCKERS.md` B3.

**PHASE 2.3 (2026-11-07):** `build_plan_meta`
(`src/evm/solution/script_generator.rs`) now forces `confidence = "sim-review"`
whenever `trace_depends_on_control_leak` holds, even for a Confirmed-tier
bug_type -- a `sim-confirmed` plan must never rest on control leak. The SAME
rule is now enforced at the finding level in `EVMBugResult::to_value`
(`src/evm/oracle.rs`) via `effective_confidence`: a finite `input.call_leak`
downgrades the tier to Review before the JSON is printed/re-parsed
(`parse_bug_report`), so the two paths cannot disagree. Regression tests:
`script_generator.rs::plan_meta_confidence_tests::control_leak_trace_is_never_sim_confirmed`
and `oracle.rs::effective_confidence_tests` (3 tests). NOTE (R3): concolic may
STILL use a faked call return while searching; the label + downgrade only
guarantee such a trace is never PRESENTED as `sim-confirmed`.

End-to-end proof (real binary, no mocks):
`python -m unittest onchain_scripts/test_invariant_oracle.py -v`
- positive: `tests/evm/eth_backing/` fires the invariant;
- negative: `tests/evm_never_pass/invariant_safe/` (correctly-backed bank)
  does NOT fire;
- probe: a deliberately-false invariant fires on the SAME safe fixture,
  proving the negative result is a true negative, not a never-run oracle;
- concolic regression: `tests/evm_never_pass/concolic_uninit_state/` (a gate
  that needs a keccak preimage) does NOT fire WITH `--concolic`, and the
  companion test asserts the stage actually ran (no vacuous pass).

**PHASE 2.4 (2026-11-07): control leak OFF during concolic search.**
`concolic_stage.rs` raises `CONCOLIC_NO_CONTROL_LEAK` (`src/evm/host.rs`)
for the duration of each testcase's `vm.execute`, so `control_leak_bypassed()`
routes every call to `call_forbid_control_leak` -- the real callee, exactly
as on-chain. A concolic solution can therefore no longer rest on a
faked/intercepted call return (a state the chain cannot produce). The normal
fuzzing loop leaves the flag unset, so its deliberate leak-based exploration
is unchanged. Proof: `host::control_leak_bypass_tests::
concolic_flag_forces_control_leak_bypass`, plus E2E `tests/evm/concolic-2/`
(cross-contract `CALL`) still finds `sim-confirmed` `0x3322`, and a fixed-seed
baseline comparison shows no regression. Still open (R3): for non-concolic
search the leak remains on by design; there the PHASE 2.3 label + downgrade
still prevent a `sim-confirmed` presentation.

**PHASE 2.5 (2026-11-07): symbolic CALL return values.** The result of a
`CALL`/`STATICCALL`/`DELEGATECALL` is no longer blindly concrete. `RETURN`
(0xf3) captures the callee's own symbolic memory window via
`SymbolicMemory::get_slice_tracked` into `ConcolicCallCtx::return_bytes`;
`on_return` pops the frame and splices those bytes into the CALLER's
symbolic memory at the CALL's `return_offset` (`SymbolicMemory::insert_bytes`);
`RETURNDATASIZE`/`RETURNDATACOPY` (0x3d/0x3e) expose `last_return_bytes`. The
spliced bytes are the callee's OWN symbolic memory, tied to the caller's
input through the calldata the CALL passed -- so the solver inverts the
callee's computation (`r = this.helper(y); require(r == C)` solves
`y*2 == C`), not a free constant. If the callee's `RETURN` is not fully
symbolic, `get_slice_tracked` returns `None` and the caller falls back to
the concrete return (never an invented value). The CALL-family stack order
matters: CALL/CALLCODE are `(gas,addr,value,argsOff,argsLen,retOff,retLen)`
so `retOff=peek(5)`, `retLen=peek(6)`; DELEGATECALL/STATICCALL shift by one.
Measured (R1, same `--seed`, real binary, `--concolic`):
`this.helper(y) = y*2`, gate `require(r == EVEN_SECRET)` -- before the fix
0 finds (timeout), after `sim-confirmed 0x3322`; negative control (gate
demands an ODD value, unreachable) -- 0 finds, so no false positive.
Unit tests: `concolic_host.rs::return_data_tests` (5). RELIABILITY (R3):
with a LARGE constant the solve needs more than the 1000ms default Z3 budget
(measured: flaky at 1000ms, deterministic at `--concolic-timeout 5000`; A/B
4 runs each with the higher budget: before 0/4, after 4/4). The permanent
fixtures are `tests/evm/concolic_retval/` (positive) and
`tests/evm_never_pass/concolic_retval_unsat/` (negative, odd secret);
`test_invariant_oracle.py::TestConcolicReturnValue` runs them with
`--concolic-timeout 5000`. The concolic source map (`combined.json`) is
gitignored, so that test regenerates it from the committed `.sol` with the
pinned solc (`~/.svm/0.8.24`) and skips (never fails) if solc is absent.
Still open (R3): symbolic CALL targets (PHASE 2.2), symbolic balances, and the
`keccak256` preimage case (3b). See `LIMITATIONS.md` 3c.

### Concolic runs on a bounded, campaign-wide worker pool

Concolic (Z3) solving is **parallel but tightly bounded**: each solve runs on
its own OS thread, and at most `num_threads` solvers stay alive at once in a
process-wide `ALL_WORKER_THREADS` pool. `threaded_solve()`
(`src/evm/concolic/concolic_host.rs`) joins the oldest worker before spawning a
new one once the pool is full, so a campaign never spawns one solver per core
(the historical `num_cpus::get()` default that started 15 concurrent solvers
and froze a 15-core host). Only pure, `Send` data crosses the thread boundary
(`input_bytes` / `constraints` are cloned `Vec<Box<Expr>>`); every Z3 object is
built inside the worker from that thread's own thread-local Z3 context
(`z3`'s `Context::thread_local`).

`--concolic-num-threads` is **not ignored**: `resolve_concolic_num_threads()`
(`src/evm/mod.rs`) resolves the CLI value against a campaign-wide cap of
`min(MAX_CONCOLIC_THREADS, cores)` (`MAX_CONCOLIC_THREADS = 2`,
`src/const.rs`). `0`/unset means "use the cap"; a smaller value is honoured
(`1` = a single sequential solver); a larger one is clamped to the cap with a
warning. Tests: `evm::test::concolic_threads_are_bounded_by_the_campaign_cap`
and `evm::test::concolic_cap_never_exceeds_two_or_cores`.

`--jobs N` shares the cap rather than multiplying it: `spawn_job`
(`src/evm/multicore.rs`) passes each worker `--concolic-num-threads`
`per_job_concolic_threads(jobs)` = `max(1, cap / jobs)`, and
`--concolic-num-threads` is stripped from the inherited argv
(`filter_overridden_flags`). Test:
`evm::multicore::tests::per_job_concolic_threads_never_multiplies_the_cap`.
NOTE (R3): process isolation only divides the cap among the jobs it can; with
more jobs than the cap (e.g. `--jobs 4`, cap 2) every worker still runs at
least one solver, so the campaign total is the job count, not `N * cap`.

The `concolic: testcase #N (i/total) -- bounded pool of M Z3 solver(s)` log
lines are a SEQUENTIAL loop over the corpus (`concolic_stage.rs`); the pool is
drained to completion before the loop advances, so they are per-corpus-entry
progress, not one line per solver.

**Correction (2026-11-09).** This file previously claimed concolic was
"strictly sequential (single Z3 solver)", that `--concolic-num-threads` was
ignored, and that a test `evm::test::concolic_is_always_a_single_solver` proved
it. None of that matched the code: the flag is honoured up to the cap, and that
test does not exist (the real tests are the three named above).

## Architecture notes

- **AttackWallet execution model (W1–W5).** `onchain_scripts/contracts/AttackWallet.sol`
  is the one reusable on-chain primitive. `execute()` reverts (bubbling the
  callee's reason) when its inner call fails -- it must never silently return
  `success=false`, or the pipeline reads a clean `receipt.status==1` for a
  plan whose middle step reverted. `executeBatch(address[],bytes[],uint256[])`
  runs a whole sequence atomically in one tx; `auto_pipeline.execute_plan`
  uses it for multi-step `flat` plans and the pre-flight fork replay mirrors
  that choice. Native payouts go through `_safeSend` (full-gas `call`), never
  `.transfer()`, so a contract recovery wallet (multisig) is reachable -- and
  the SAME fix is in `collectAndDestroy()` of both generated exploit templates
  (`foundry_script.hbs` / `foundry_script_reentrancy.hbs`), which previously
  still used `beneficiary.transfer(...)`; Rust test
  `evm::solution::tests::generated_exploit_scripts_use_full_gas_call_not_transfer`.
  `strategy_layer.order_steps_by_dependencies` stably topo-sorts prerequisites
  (approve→transferFrom, deposit→withdraw) before their consumers and reports
  cycles instead of reordering them. W4 also NAMES the failing step:
  `auto_pipeline.first_failing_step_index` replays growing prefixes of the
  batch via `eth_call` and reports `best-effort prefix replay points at step
  i/n` (diagnostic only -- a single-step `eth_call` cannot reproduce an
  inter-step dependency). Proof:
  `onchain_scripts/contracts/proof_w1_w2_w3.sh` (needs `anvil`+`cast`+`solc`;
  7/7) and the `W4`/`W5` Python tests. A general symbolic planner is NOT
  implemented -- see `LIMITATIONS.md`.

- **Fuzzer finding-dump name is bounded (X1).** `vuln_file_base` in
  `src/fuzzer.rs` bounds the `vulnerabilities/<comma-joined bug_idxs>` file
  name to 120 bytes + a stable hash when the raw id list would exceed NAME_MAX
  (a `--run-forever` input can trip thousands of per-pc oracle hits), and the
  dump `File::create(...).unwrap()`s were replaced with logged `error!`s --
  previously a >255-byte name panicked the whole fuzzer ("File name too long"
  ~3s into a real ETC run). Test: `fuzzer::vuln_file_base_tests`.

- **Estimate-time revert is NOT CONFIRMED, not INCONCLUSIVE (X2).** When a
  plan's FIRST step reverts, `eth_estimateGas` raises web3's
  `ContractLogicError`; `auto_pipeline.execute_plan` now catches it and returns
  `PLAN_NOT_CONFIRMED` with the reason, instead of letting it escape to the
  generic per-plan handler and be mislabelled `INCONCLUSIVE` (which hides a
  genuine "reverts on real state" result). W1 made this reachable (execute()
  now bubbles the inner revert). Test:
  `test_execute_plan_net.py::X2EstimateRevertClassificationTest`.
- `src/evm/contract_utils.rs` — proxy expansion. `from_fork` AND
  `from_address` both call `expand_proxy_targets`, which walks
  `proxy_implementations_of` across EIP-1967 (impl/beacon), EIP-1822 (UUPS),
  EIP-1167 (minimal proxy), and EIP-7702 (`0xef0100 || delegate`). The pure
  byte-layout cores (`minimal_proxy_implementation_from_bytes`,
  `eip7702_delegate_from_bytes`) are split out so they are unit-testable
  with no RPC.
- `onchain_scripts/proxy_resolver.py` — the Python mirror of the same four
  conventions, used by `auto_pipeline.main()` to log and pass implementations
  as extra `-t` targets. Slot constants are re-derived from keccak and
  cross-checked against the Rust literals by `test_proxy_resolver.py`, so a
  drift cannot go unnoticed (a wrong slot reads 0, indistinguishable from
  "not a proxy").
- `onchain_scripts/chains.py` — `NetworkProfile` + `verify_rpc_identity`
  read the endpoint's REAL `eth_chainId` and refuse to run on a mismatch
  before any signing. Never trust the `--chain` string alone.
- PHASE 1 gas reality (`onchain_scripts/auto_pipeline.py`): the revm model has
  no gas metering, so the authoritative number is the node's own
  `eth_estimateGas` against the real `block.gasLimit`
  (`estimate_plan_gas_on_fork`). Those fields are stamped on the plan, and the
  pre-flight gate (`gas_oversized_reason` → status `oversized_gas`) flags a
  plan that cannot fit in one block so it is never sent — the guard for the
  real C9f53_2 incident (~49.6M gas vs an 8,000,000 block limit).
  `batch_pipeline.py` measures gas the same way. Test:
  `test_gas_oversized_gate.py`.
- `src/evm/multicore.rs` — PHASE 6.2 multi-core via **process isolation**
  (`--jobs N`). Processes, not threads: `EVMFuzzState` is not `Send` and the
  coverage/cmp maps (`src/sync_utils.rs`) are process-global `RacyCell`s that
  are sound only under a single-threaded assumption. (The concolic worker pool
  is the one place that does use OS threads; it is safe precisely because it
  never touches a `RacyCell` -- see the concolic section below.)
- Concolic runs on a bounded worker pool, not strictly sequential.
  `--concolic-num-threads` is honoured up to the campaign-wide cap
  `min(MAX_CONCOLIC_THREADS, cores)` (`MAX_CONCOLIC_THREADS = 2`); `0`/unset
  means the cap, `1` forces a single sequential solver, more is clamped.
  `threaded_solve` (`src/evm/concolic/concolic_host.rs`) spawns one OS thread
  per solve and keeps at most `num_threads` alive in the process-wide
  `ALL_WORKER_THREADS` pool. Parallel Z3 solvers were the freeze cause when the
  default was one-per-core (observed: 15 concurrent on the test machine); the
  fix is the cap, not removing the parallelism. Tests:
  `evm::test::concolic_threads_are_bounded_by_the_campaign_cap`,
  `evm::test::concolic_cap_never_exceeds_two_or_cores`.
- `--jobs` shares the concolic cap, never multiplies it. `spawn_job`
  (`src/evm/multicore.rs`) passes each worker `--concolic-num-threads`
  `per_job_concolic_threads(jobs)` = `max(1, cap / jobs)`, and
  `--concolic-num-threads` is stripped from the inherited argv
  (`filter_overridden_flags`). Test:
  `evm::multicore::tests::per_job_concolic_threads_never_multiplies_the_cap`.
- `--jobs` is clamped to the core count (`clamp_jobs_to_cores` in
  `src/evm/multicore.rs`), with a warning when a larger value is reduced: each
  worker is ~one fully busy core, so more workers than cores oversubscribes the
  host and can freeze it (the same failure class as the old `num_cpus` concolic
  default). Test: `evm::multicore::tests::jobs_are_clamped_to_core_count`.
- Each Z3 solve is bounded in MEMORY, not only in wall-clock time:
  `--concolic-memory-mb` (default 2048 MiB, 0 = unlimited) sets Z3's
  `memory_max_size`, so a hard path condition that blows memory up while still
  returning inside `--concolic-timeout` degrades to `unknown` (skip) instead of
  exhausting host RAM. Tests:
  `evm::concolic::concolic_host::concolic_memory_cap_tests`.
- External-data hardening (PHASE 6.1): never `.unwrap()`/`.expect()` on data
  from outside the process (RPC responses, solc/forge artifacts, ABIs,
  storage, user presets). Return a typed `Result` or a safe default. The
  remaining `.unwrap()`s are `.parse().unwrap()` on static literals,
  `lock().unwrap()`, or inside `#[cfg(test)]`.

## Full live run on Mordor (no anvil fork)

`benchmarks/forksploit_full_live_mordor/` holds a **full** ForkSploit run
(concolic + concolic-caller + flashloan + `--jobs 3` + `--invariants` +
`--auto-setup`, Shanghai) directly against the live Mordor RPC on the same
`CyberScratchLottery`, no anvil fork. Two independent seeds, 300 s each, found
the **same 9 finding types** (100% reproducible at the type level). The
installed bytecode matches the verified source (`deployed_bytecode ==
eth_getCode`, 4427 B, solc 0.8.20 no-optimizer), so every finding was checked
against the source: only **Weak Randomness (SWC-120)** is real; the six
`sim-confirmed`/`sim-review` hits (Invariant Violation, Fund Loss, Arbitrary
Storage Write, Unchecked ecrecover(0), Integer Overflow, Zero Address Setter)
are false positives or misleading labels, and Stale Guard Counter / Unbounded
Loop are benign heuristics. Key causes: `native_balance` in Address mode reads
the sim's `post_state.balance[target]`, which `from_address` leaves at 0
(`contract_utils.rs`); the caller pool contains `0x…01`, so the prize
`payable(msg.sender).call` looks like an ecrecover call; and the pc-level
oracles (arbitrary-slot, overflow) fire on constant slots / compiler helpers.
See the README for the per-finding proof table.

## Cross-tool benchmark (real target)

`benchmarks/echidna_vs_forksploit/` records an Echidna-vs-ForkSploit
comparison on the **same real contract**: `CyberScratchLottery`
`0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee` on ETC Mordor (verified,
Solidity 0.8.20 + OpenZeppelin `ReentrancyGuard`). ForkSploit ran in Address
mode against the live bytecode via an Anvil fork of Mordor; Echidna ran a
property harness that only wraps the real contract. Both independently found
the contract's real bug -- weak/predictable randomness (SWC-120). Reproduce
with `benchmarks/echidna_vs_forksploit/run_benchmark.sh`. Note: the ETCMC
Mordor PoW faucet stopped paying out (last on-chain payout 2026-08-08, queue
stuck at 220), so the benchmark forks existing testnet state rather than
depending on faucet funds.

## Conventions

- Match the surrounding code style; keep changes minimal and focused.
- Comments: only for genuinely non-obvious invariants, workarounds, or
  trade-offs. Do not narrate the diff or restate the code.
- Proof tests live in a `#[cfg(test)] mod tests` beside the module they
  cover, tagged with the phase they belong to (e.g. `PHASE 6.1`).
