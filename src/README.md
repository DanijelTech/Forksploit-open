# src/ — Rust core

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it.**

Source of the ForkSploit Rust core: a bytecode-level, coverage-guided fuzzer
with concolic (Z3) solving on top of `revm`, plus the oracle set and the
exploit-plan / `.t.sol` generators. The Rust side **never signs or sends
transactions** — that is the Python layer's job (`onchain_scripts/`).

## Structure

Folders:
- `generic_vm/` — generic traits any VM implements (`vm_executor.rs`,
  `vm_state.rs`).
- `evm/` — the EVM implementation (the whole project; MoveVM was removed).
  - `evm/vm.rs` — execution engine on `revm`.
  - `evm/host.rs` — host environment, control-leak machinery, harvest
    heuristic, `MAX_ANALYSIS_CALL_DEPTH`.
  - `evm/input.rs` — one transaction (`EVMInput`).
  - `evm/oracles/` — **47** detection modules (attack surfaces).
  - `evm/middlewares/` — per-opcode hooks (coverage, cheatcodes, reentrancy,
    sha3 bypass, overflow, delegatecall, ecrecover, tx.origin, …).
  - `evm/concolic/` — concolic/Z3 host + bounded worker pool.
  - `evm/onchain/` — chain config, RPC, pair discovery.
  - `evm/solution/` — `*.plan.json` + `.t.sol` / `.s.sol` generation.
  - `evm/tokens/`, `evm/oracles/`, `evm/producers/`, `evm/presets/`.
- `fuzzers/` — fuzzer orchestration (`evm_fuzzer.rs`).

Files:
- `main.rs` — CLI entry (`forksploit evm`).
- `executor.rs` — LibAFL `Executor` trait.
- `feedback.rs` — LibAFL `Feedback` (coverage, comparison, state comparison).
- `oracle.rs` — `Oracle` trait.
- `scheduler.rs` / `power_sched.rs` — infant scheduler + power scheduling.
- `state.rs` / `state_input.rs` — `State` trait + VM-state input.
- `indexed_corpus.rs` — corpus with a self-incrementing testcase id.
- `input.rs` — LibAFL `Input` trait.
- `tracer.rs` — state-snapshot traces (regenerate the transactions that led
  to a VM state).
- `fuzzer.rs` — the main fuzz loop; records `TxnTrace::from_idx` genealogy and
  dumps findings.
- `minimizer.rs` — input minimisation.
- `mutation_utils.rs` — mutation helpers.
- `cache.rs`, `sync_utils.rs` — caching and global-state primitives
  (`Atomic*`/`Mutex`/`RacyCell`).
- `const.rs` — constants (`MAX_CONCOLIC_THREADS`, gas caps, …).
- `build.rs` — embeds the git commit into the binary (`forksploit --version`).

See `../CLAUDE.md` for architecture detail and `../README.md` for the
user-facing overview.
