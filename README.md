# ForkSploit

<div align="center">

**An audit-and-offensive platform for EVM smart contracts that, under strict operator control, proves a contract is vulnerable — and proves it by action.**

**Built and verified for Ethereum (ETH) and Ethereum Classic (ETC) — on both testnets (Sepolia, Mordor) and both mainnets — and for all asset types: native currency (ETH/ETC) and all ERC tokens (ERC-20, ERC-721, ERC-1155, ERC-4626 and others).** ForkSploit works on both networks in both variants (testnet and mainnet) and on every asset the contract uses.

<!-- Badges: all values are VERIFIED against the source in this repo (R1).
     47 = entries in OracleType::from_strs "all" (src/evm/mod.rs);
     25 = arms of Chain::from_str (src/evm/onchain/endpoints.rs);
     toolchain = rust-toolchain.toml; license = LICENSE. The CI badge points
     at the "CI" workflow (.github/workflows/ci.yml), which runs on main. -->
[![CI](https://github.com/DanijelTech/ForkSploit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DanijelTech/ForkSploit/actions/workflows/ci.yml)
[![Rust nightly](https://img.shields.io/badge/Rust-nightly--2026--10--15-000000?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Detectors](https://img.shields.io/badge/attack%20surfaces-47%20oracles-blue)](#attack-surfaces-forksploit-covers)
[![Chains](https://img.shields.io/badge/chains-25%20EVM-627EEA)](#chains)
[![Proof](https://img.shields.io/badge/proof-100%25%20on--chain%20exploitability-2ea043)](#why-proof-is-different-from-guessing)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary%20(All%20Rights%20Reserved)-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-555)](#installation)

</div>

ForkSploit is not a fuzzer. It is a complete platform that answers the question no static tool and no fuzzer can answer with certainty: *"Is this contract really vulnerable, where exactly, what is exploitable, and does an attacker actually walk away with the funds?"* The answer is not probabilistic — it is a **deterministic proof**, because ForkSploit does not merely find the exploit: it **executes it against the real chain state** and **moves the extracted funds to the recovery wallet as proof**.

> **Unique advantage:** ForkSploit is the only known system of its kind that links *discovery* and *proof of execution* into one unbroken chain — from the attack surface in the bytecode to a real movement of funds into the recovery wallet. And it does so **on both networks — Ethereum (ETH) and Ethereum Classic (ETC) — both on testnet (Sepolia, Mordor) and on mainnet (id 1 / 61) — and for all assets the contract uses: native currency (ETH/ETC) and ERC tokens (ERC-20, ERC-721, ERC-1155, ERC-4626).** The result is not "we found a pattern that could be a vulnerability" but **"this contract lost X ETH/ETC or X ERC-20/721/1155/4626 tokens in this way, here is the path, here is the proof."**

---

## Table of contents

1. [What ForkSploit is (and is not)](#what-forksploit-is-and-is-not)
2. [Support scope: ETH + ETC, testnet + mainnet, all assets](#support-scope-eth--etc-testnet--mainnet-all-assets)
3. [Why proof is different from guessing](#why-proof-is-different-from-guessing)
4. [Where in the contract lifecycle it fits](#where-in-the-contract-lifecycle-it-fits)
5. [Architecture: two layers](#architecture-two-layers)
6. [Attack surfaces ForkSploit covers](#attack-surfaces-forksploit-covers)
7. [The proof path: from finding to recovery wallet](#the-proof-path-from-finding-to-recovery-wallet)
8. [Security model and operator control](#security-model-and-operator-control)
9. [Installation](#installation)
10. [Quick start](#quick-start)
11. [Configuration](#configuration)
12. [CLI reference](#cli-reference)
13. [Helper tools](#helper-tools)
14. [Development, tests and build](#development-tests-and-build)
15. [Limitations (honest)](#limitations-honest)
16. [Legal and ethical use](#legal-and-ethical-use)

---

## What ForkSploit is (and is not)

**It is:**

- **An attack-surface discovery platform** for EVM smart contracts — before deploy (on local bytecode from `.sol`/`.bin`) and after it (on a live deployed contract over RPC, with or without source code).
- **An exploitability prover.** For every real finding it generates a **structured, reproducible plan** (`*.plan.json`) and attempts to execute it. If it succeeds and the recovery wallet balance really increases, that is a **proof** — not an estimate.
- **An executor.** It executes the plan through one reused `AttackWallet` contract (deploy + real calls, with an Aave flashloan when needed for zero capital), then **sweeps the extracted funds to the locked recovery wallet**.
- **A post-deploy monitor.** `monitor.py` continuously watches a live contract and, on suspicion of an outflow, attempts to rescue the remaining funds with already-known plans.

**It is not:**

- **Not a false-alarm generator.** Every claim of exploitability is tied to a measured movement of funds. Anything that does not move value is reported as `EXECUTED, NO PROFIT` or `SKIPPED`, never as a confirmed attack.
- **Not a replacement for Foundry/Echidna, but it complements them.** For fuzz testing *your own* Solidity source with hand-written harnesses, [Foundry](https://github.com/foundry-rs/foundry) and [Echidna](https://github.com/crytic/echidna) remain excellent choices — but ForkSploit is **not limited to already-deployed bytecode**. It also reviews **pre-deploy contracts**: local `.sol` (it compiles it itself) or `.bin` (already-compiled bytecode) — such a contract is **deployed and attacked in a run on fresh state**, before it ever goes to mainnet. In addition it has **its own declarative invariant oracle** (`--invariants file.json`, no Rust), so you can express economic invariants directly in ForkSploit. It works on **Ethereum (ETH)** and **Ethereum Classic (ETC)**, on **testnet and mainnet**, and on **native currency and ERC tokens** — on local bytecode (pre-deploy), on local/fork state, and on a live deployed contract (with or without source code).
- **Not an unsupervised tool.** It signs and sends **nothing** without the operator's explicit confirmation; see [Security model](#security-model-and-operator-control).

---

## Support scope: ETH + ETC, testnet + mainnet, all assets

This is **key information** about where ForkSploit works and what it covers.

### Networks — Ethereum and Ethereum Classic, each in both variants

| Network | Type | Chain ID | Role |
|---|---|---|---|
| **Ethereum (ETH)** | **mainnet** | 1 | First-class, live-verified |
| **Sepolia** | ETH **testnet** | 11155111 | First-class, live-verified |
| **Ethereum Classic (ETC)** | **mainnet** | 61 | First-class, live-verified |
| **Mordor** | ETC **testnet** | 63 | First-class, live-verified |

Against these **four**, both plan generation and exploit execution have been live-verified. For each of the two networks ForkSploit works **both on testnet and on mainnet** — testnet for safe development and rehearsal, mainnet for real validation (with `--confirm-mainnet`).

In addition, the Rust core supports **25 chains** (BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, Fantom, Gnosis, Celo, Scroll, Linea, Blast, zkEVM, Iotex, Vana, Story, …), but ETH and ETC are the only two the project treats as first-class and against which execution has been live-confirmed.

### Assets — native currency and ERC tokens

ForkSploit tracks and extracts the assets the target contract uses:

- **Native currency** — ETH (on Ethereum) and ETC (on Ethereum Classic), including funds the contract holds as `address(this).balance`. Extracted by `AttackWallet.sweep()` (no destination parameter).
- **ERC-20** — automatic: every step that is a raw ERC-20 call (`transfer`/`transferFrom`/`approve`/`mint`/`burn`/`skim`) on a token contract is tagged with `stolen_asset`, and after execution `AttackWallet.sweepToken()` extracts the remainder from `AttackWallet` to the recovery wallet.
- **ERC-721 / ERC-1155 / ERC-4626** — **detection** of attack surfaces is covered by oracles (`Unauthorized NFT Transfer`, `Unauthorized ERC1155 Transfer`, `ERC4626 Share Inflation`, `ERC4626 Rounding Favors User`, `nft_transfer`, `erc4626`), including `safeTransferFrom`/`setApprovalForAll` (which `strategy_layer` recognises when ordering dependencies). Note (R3): the automatic `sweepToken` is tied to ERC-20 selectors; for NFTs the extraction is performed through the exploit plan itself (transfer to the recovery wallet), not through a separate "sweep NFT" call.
- **Wrapped native** (WETH9 / WETC) — unwrap/wrap for flashloan funding.
- **Aave V3 / Balancer V2** — flashloan for execution without attacker capital.

### Both-phase coverage

Everything above holds **before deploy** (on a local `.sol`/`.bin`) and **after it** (on a live deployed contract on ETH/ETC mainnet or Sepolia/Mordor testnet), with or without source code.

---

## Why proof is different from guessing

Classic security tools stop at *"this could be vulnerable"*. ForkSploit goes a step further and separates three levels that it never conflates:

| Level | Where it arises | What it means | How it is reported |
|---|---|---|---|
| **Finding (attack surface)** | Rust core (revm + 47 oracles) | An observable pattern or a directly observed violation in simulation | `sim-confirmed` / `sim-review` (always with the `sim-` prefix) |
| **Replayable proof** | `*.plan.json` | Every finding carries a **reproducible transaction trace** (who, what, calldata, value) | field `evidence: "replayable_transaction_trace"` |
| **On-chain proof** | Python execution layer | A real transaction was sent and the **recovery wallet really received funds** | `CONFIRMED` + measured `recovery_delta_wei` |

The key point: level 1 is a **simulation**. That is why the label is `sim-confirmed`, never a bare `confirmed`. Level 3 is **truth** — the only moment ForkSploit claims a contract is vulnerable is when an asset has actually moved into the recovery wallet.

---

## Where in the contract lifecycle it fits

ForkSploit's goal is a **timely, proven exploitation path — before the owner loads the main funds** into the contract:

```
   development          BEFORE DEPLOY              DEPLOY            AFTER DEPLOY
 ─────────────        ─────────────────────        ──────────        ────────────────────
   .sol/.bin  ───────►  ForkSploit proves  ───────►  contract  ───────►  monitor.py guards
                        exploitability                goes to           and on outflow rescues
                        WITHOUT risk                  the chain         the remaining funds
                             │
                             ▼
                  "will this contract lose
                   funds when I load them?"
                             │
                    YES ─────┴────── NO
                     │               │
             proof + exploit    negative result
             on testnet         (bounded, honest)
```

ForkSploit thus answers a key business question: **is it safe to load funds into this contract** — and if not, exactly where the hole is and how to close it.

---

## Architecture: two layers

The split is strict and deliberate. Rust **never** signs; Python **never** decides whether a pattern is a vulnerability.

### 1. Rust core — discovery and plan synthesis

- **The unit of fuzzing is one transaction** (`EVMInput`: caller, target contract, calldata, value). Multi-step behaviour arises **across the corpus genealogy** — each new testcase descends from the stored VM state of the previous one, so state accumulates across generations (`full_trace` + `print_txn_corpus` are default features).
- **Coverage-guided fuzzer** over `revm`, with **concolic/Z3 solving** (`--concolic`, `--concolic-caller`) over branches that random mutation would not reach.
- **47 oracles** (see [attack surfaces](#attack-surfaces-forksploit-covers)) — on each finding Rust emits `*.plan.json` with the exact observed steps.
- **Addresses and callers are biased**: `addresses_pool` prefers deployed contracts (75%), while callers are fresh identities — so cross-contract classes (a vault reading `token.balanceOf(self)`, a pair calling both of its tokens) are reachable.
- **Proxy expansion**: `from_address()` unwraps EIP-1967 (impl/beacon), EIP-1822 (UUPS), EIP-1167 (minimal proxy) and EIP-7702, so it fuzzes the **implementation, not the ~45-byte dispatcher**.

### 2. Python orchestration — wallets, execution, proof

`auto_pipeline.py` reads **all** plans from `work_dir/vulnerabilities/`, via `strategy_layer.compose_plan()` **merges them into a single logical, ordered multi-step plan** (`unlock → neutral → objective → reentrancy last`), executes it through `AttackWallet`, and **moves all obtained funds to the recovery wallet**.

---

## Attack surfaces ForkSploit covers

ForkSploit checks **47 attack surfaces**, implemented as oracles in `src/evm/oracles/`. Each is tagged with its confidence level (`Confirmed` = directly observed violation, `Review` = heuristic with a known false-positive risk).

**Access and authorization**

- `access_control` — unauthorized ownership change, pause toggle, proxy upgrade
- `tx_origin` — `tx.origin` phishing bypass
- `initializer_front_run` — initializer front-running
- `centralization_risk` — central points of failure (Review)
- `ecrecover` — unchecked `ecrecover(0)`
- `signature_malleability`, `signature_replay` — signature malleability and replay
- `forged_proof` — forged Merkle/proof

**Execution and control flow**

- `reentrancy`, `readonly_reentrancy` — classic and read-only reentrancy
- `arbitrary_storage_write` — write to an arbitrary storage slot
- `storage_collision`, `proxy_integrity`, `proxy_upgrade_hijack` — storage collisions and proxy integrity
- `delegatecall`, `delegatecall_target` — delegatecall injection and arbitrary target
- `arb_call`, `arb_transfer` — arbitrary calls and transfers
- `unchecked_call` — unchecked low-level calls
- `selfdestruct` — self-destruct
- `gas_stipend` — hard-coded gas limit (SWC-134)
- `assert_violation`, `uninitialized_memory` — `assert` violation and reading uninitialized memory
- `transient_guard` — bugs in transient storage guards

**Arithmetic and economics**

- `overflow` — integer overflow
- `precision_loss`, `preview_rounding` — precision loss and rounding in the user's favour
- `token_accounting_mismatch`, `unbacked_mint`, `forced_eth_accounting` — accounting mismatches, unbacked mint
- `eth_backing` — promised native value exceeds the real balance
- `erc20`, `nft_transfer`, `erc4626` — bugs in ERC20/721/1155 and ERC4626 (share inflation)
- `curve_virtual_price`, `twap_manipulation`, `price_feed_staleness` — price manipulation and stale data
- `imbalanced_pair` (v2_pair) — imbalanced Uniswap pair

**Logic and reliability**

- `unbounded_loop`, `revert_in_loop` — unbounded loops and revert inside a loop (DoS)
- `stale_guard` — stale guard counter (Review)
- `self_referral` — payment regardless of validation (observed two-way — Confirmed)
- `zero_address_setter` — setting to the zero address
- `weak_randomness` — weak/predictable randomness (SWC-120)
- `invariant` — **user-declared economic invariants** (`--invariants file.json`), evaluated after every transaction

> **Note on coverage:** ForkSploit deliberately runs with `--detectors all` by default. An early version defaulted to `high_confidence`, but that caused the user to read "nothing found" as "no vulnerability" on a contract whose only real finding was excluded from `high_confidence`. Silently narrowing the search is a worse mistake than an occasional false positive.

---

## The proof path: from finding to recovery wallet

ForkSploit performs the following chain — every step is visible in the terminal **and** in a time-stamped file under `onchain_scripts/logs/`:

1. **Registration / deploy.** From `.sol`/`.bin` (fresh deploy) or `0x…` (already deployed). Optionally static analysis (Slither) and funding of the target.
2. **Proxy resolution.** `resolve_proxy_chain()` unwraps the stack and adds each implementation as an extra target.
3. **Fuzzing.** Launch the Rust core with `--run-forever` (it does not stop at the first finding) and concolic solving.
4. **Plan merging.** `strategy_layer` merges all plans into one coherent multi-step plan; each plan is also attempted **on its own**.
5. **Pre-flight profitability gate (ON by default).** Before any plan is sent for real, it is evaluated in two layers:
   - *Metadata (no network):* a plan with `atomic_replayable=false`, with more than one `msg.sender`, or with `confirmed_exploitable=false` is skipped immediately.
   - *Fork simulation:* if `anvil` is available, a temporary fork of the node's **same** state is started, the plan is replayed step by step, and the **real** recovery-wallet delta **and** real gas used are measured. The plan is skipped if it reverts or if it extracts less than its gas costs.
6. **Execution.** Via `AttackWallet.executeBatch` (atomic, in one transaction) or sequentially (reentrancy), with an **Aave V3 flashloan** when needed (zero attacker capital).
7. **Extraction.** `sweep()` / `sweepToken()` — **no destination parameter**, always to the locked recovery wallet.
8. **Report.** For each plan a status + measured proof (see [statuses](#statuses-and-proof)).

### Statuses and proof

Each plan gets one of the following statuses, and **only `CONFIRMED` is a proven attack**:

| Status | Meaning |
|---|---|
| `CONFIRMED` | A real, on-chain reproduced execution — the recovery wallet **measurably** received funds (`recovery_delta_wei`) |
| `EXECUTED, NO PROFIT` | All steps succeeded without reverting, but the recovery wallet balance did not rise — **not** a confirmed attack |
| `NOT CONFIRMED` | Revert against real state — likely a false positive or it needs different preconditions |
| `INCONCLUSIVE` | Not actually attempted (e.g. an unrealistic amount) — no signal either way |
| `SKIPPED, UNPROFITABLE` | The free pre-flight already proved a revert or unprofitability — **no** transaction was signed |
| `SKIPPED, NOT EXTRACTABLE` | Found, but with no executable extraction step (Review-tier heuristic, non-replayable or multi-caller trace) |
| `OVERSIZED GAS` | Measured gas exceeds the block gas limit — physically not includable in one block |

For each finding a structured proof is also written (`build_proof`): `replayed`, `gas_used`, `net_profit_wei`, and `blockers` (e.g. `owner_gated`, `owner_impersonation`, `atomic_replayable=false`).

---

## Security model and operator control

ForkSploit signs and sends real transactions, so operator control is built into every layer — not as a recommendation, but as hard rules in code.

### 1. Locked profit destination (`safeWallet`)

`AttackWallet.sol` has `safeWallet` — an address set **once**, on first use, via `setSafeWallet()` (a second call reverts). Every function that extracts funds (`sweep()`, `sweepToken()`, `sweepWithBuilderTip()`) **has no destination parameter** — they all unconditionally send to `safeWallet`. No call data, not even from a compromised owner key, can redirect the profit elsewhere. Changing the destination means deploying a new `AttackWallet`, never calling into this one.

### 2. Two-wallet rule (`wallet_policy.py`)

Before any script signs anything, exactly two roles must be locked once, **per chain**. Every call of `auto_pipeline.py`, `batch_pipeline.py`, `monitor.py` (with `--key`/`--safe-wallet`), `aave_flashloan_runner.py` and `dex_arbitrage_scanner.py` (with `--execute`) checks before every signing:

1. that the address the `--key` file resolves to matches the registered `funding_wallet` for that chain,
2. that `--recovery-wallet`/`--safe-wallet` matches the registered `recovery_wallet`.

`--confirm-chain` is mandatory and you must **manually type** the same chain name as in `--chain` — an anti-typo measure, because `eth` and `etc` are one letter apart and both are real mainnet chains.

### 3. Automatic network detection

On every launch ForkSploit reads the **actual `eth_chainId`** from the configured RPC (`chains.verify_rpc_identity`) and **refuses** to run on a mismatch with `--chain` — before anything is signed. It then adapts every mechanism that behaves differently per network (Flashbots relay, mempool-privacy rerouting, native-token label, mainnet confirmation, `--hardfork` for the Anvil fork) to the **detected** network, not the typed name. This closes the `eth`/`etc` trap from both sides: a wrong name on the right RPC and a right name on the wrong RPC.

### 4. Strict mainnet confirmation

For every chain not in `TESTNET_CHAINS` (`sepolia`, `chapel`, `mordor`), `--confirm-mainnet` is mandatory. It prints the loud, unambiguous chain name (e.g. `ETHEREUM CLASSIC (ETC) mainnet -- this is NOT Ethereum (ETH)`) and requires explicit confirmation.

### 5. Per-plan gas budget

Gas spending is limited per plan to the real, pre-run estimate + a 10% margin (`GAS_BUDGET_MARGIN = 1.10`) — one plan, one gasfee unit, never unlimited. Every transaction gas limit is additionally clamped to `MAX_GAS_LIMIT = 8_000_000` (the real ETC block limit).

### 6. Reporting with proof (R1)

ForkSploit never reports "confirmed" without a **measured** movement of funds. Anything not measured is labelled unmeasured. This holds for the code, the documentation and every individual output.

---

## Installation

### Prerequisites

ForkSploit links the system **Z3**. If `z3-sys` cannot find it, it tries to build all of Z3 from source — which takes very long and often fails. So install the system Z3, `pkg-config` and the C/C++ toolchain before building.

**Debian / Ubuntu:**

```bash
sudo apt-get install -y libz3-dev pkg-config clang cmake build-essential
pkg-config --modversion z3        # must print a version (e.g. 4.13.3.0)
```

**macOS (Homebrew):**

```bash
brew install z3 pkg-config
```

**Optional, recommended** (for pre-flight fork simulation and the W1–W3 proof):

- [Foundry](https://github.com/foundry-rs/foundry) (`anvil`, `cast`) — without `anvil` the pre-flight gate silently degrades to "try it" (a missing optional tool never stops a run, it just makes it less frugal).
- `solc` (0.8.24) — needed for `.sol` targets and to redeploy `AttackWallet`; Python calls it on the fly.

### Cloning

```bash
git clone https://github.com/DanijelTech/ForkSploit.git
cd ForkSploit
```

### Build

Rust is pinned via `rust-toolchain.toml` (nightly):

```bash
rustup toolchain install          # reads rust-toolchain.toml
cargo build --release
./target/release/forksploit evm --help
```

The binary embeds the git HEAD (`src/build.rs`), so you can check it is fresh:

```bash
git rev-parse HEAD
./target/release/forksploit --version    # must print the same revision
```

### Python dependencies

```bash
pip install -r onchain_scripts/requirements.txt
```

### Docker (alternative)

The `Dockerfile` already contains all prerequisites (`libz3-dev libssl-dev pkg-config cmake`) and builds three binary variants:

```bash
docker build -t forksploit .
```

---

## Quick start

### Interactive (recommended): `forksploit.sh`

A single entry point: logo, then a pre-flight environment check (doctor), then the **main menu** and a 7-step wizard.

```bash
./forksploit.sh              # wizard + pre-flight environment check
./forksploit.sh --doctor     # only check the environment and print status, no wizard
./forksploit.sh --dry-run    # check everything and build the command, but do NOT run it
./forksploit.sh --no-install # pre-flight only REPORTS, installs nothing
```

Main menu:

```
1) New run          -> the 7-step wizard
2) Settings         -> default key file / per-chain RPC override
3) Check environment-> the full doctor report
4) Help             -> what the tool does and what the steps mean
exit / q            -> quit
```

The wizard requires exactly **three roles** before it signs anything — *who funds* (a private-key file), *what is being reviewed* (address or path), *where the funds go* (the recovery wallet) — plus the chain, RPC and wallet-policy lock. At the end it prints a summary you confirm before `auto_pipeline.py` / `batch_pipeline.py` is launched.

### Direct: `auto_pipeline.py` (one target)

```bash
python3 onchain_scripts/auto_pipeline.py \
    --target 0xAlreadyDeployedContract \
    --key onchain_scripts/key.txt \
    --recovery-wallet 0xYourRecoveryWallet \
    --chain sepolia \
    --confirm-mainnet \
    --fuzz-seconds 300
```

or with a local `.sol`/`.bin` (fresh deploy):

```bash
python3 onchain_scripts/auto_pipeline.py \
    --target /path/to/MyContract.bin \
    --key onchain_scripts/key.txt \
    --recovery-wallet 0xYourRecoveryWallet \
    --chain sepolia \
    --confirm-mainnet \
    --fund-eth 0.01 \
    --fuzz-seconds 300
```

### Batch: `batch_pipeline.py` (many targets)

One funding and one recovery wallet for a **whole** series (never a different wallet between targets):

```bash
python3 onchain_scripts/batch_pipeline.py \
    --targets targets.txt \
    --key onchain_scripts/key.txt \
    --recovery-wallet 0xYourRecoveryWallet \
    --chain sepolia \
    --confirm-mainnet \
    --fuzz-seconds 300
```

`targets.txt`: one target per line (a path to `.sol`/`.bin` or a `0x` address).

### Direct: Rust binary

```bash
# Local contract from bytecode (no chain)
./target/release/forksploit evm -t 'tests/evm/erc4626/*' -f -d all

# Live deployed contract (black-box, no source code)
./target/release/forksploit evm -t 0xContractAddress -c etc \
    -f -d all --run-forever -w work_dir

# Declarative invariants (your own economic rules)
./target/release/forksploit evm -t 'tests/evm/two_step/*' -f \
    -d invariant --invariants tests/evm/two_step/invariants.json

# Automatic precondition derivation + flashloan + concolic
./target/release/forksploit evm -t 'tests/evm/erc4626/*' -f \
    --auto-setup --concolic --concolic-caller --jobs 3
```

---

## Configuration

### Private-key file (`--key`)

One line — the private key of the funding wallet (hex). This wallet pays **all** gas. **Never commit this file** (`.gitignore` already excludes `onchain_scripts/*.key`, `key.txt`, `keys/`).

```bash
printf '%s\n' '0xYOUR_PRIVATE_KEY' > onchain_scripts/key.txt
chmod 600 onchain_scripts/key.txt
```

### Wallet policy (`onchain_scripts/wallets.json`)

Lock the funding and recovery roles for a chain **once**, before you sign anything:

```bash
python3 onchain_scripts/wallet_policy.py register \
    --chain sepolia \
    --confirm-chain sepolia \
    --funding-wallet 0xWalletThatPaysGas \
    --recovery-wallet 0xWalletWhereFundsGo \
    --confirm

python3 onchain_scripts/wallet_policy.py show
python3 onchain_scripts/wallet_policy.py contracts
```

### RPC override (`onchain_scripts/rpc_overrides.json`)

Every chain has a default public RPC (`chains.DEFAULT_RPC`). For your own endpoint (paid, local anvil fork) set an override — via `forksploit.sh` (menu *Settings*) or programmatically (`chains.set_rpc_override`). Gitignored.

### Invariants (`--invariants file.json`)

Your own economic rules, evaluated after every non-reverted transaction. Operands: `native_balance`, `literal`, `call`, `sum_over_callers`; operators `le/lt/ge/gt/eq/ne`:

```json
{ "invariants": [
  { "name": "balances never exceed supply",
    "op": "le",
    "lhs": { "sum_over_callers": { "sig": "balanceOf(address)" } },
    "rhs": { "call": { "sig": "totalSupply()" } } },
  { "name": "vault solvent",
    "op": "le",
    "lhs": { "sum_over_callers": { "sig": "balances(address)" } },
    "rhs": { "native_balance": true } }
] }
```

- `{"native_balance": true}` — the target's real native balance.
- `{"literal": "1000"}` — a decimal or `0x` constant.
- `{"call": {"sig": "...", "args": ["$caller", "0x…", "123"]}}` — a single static call; `$caller` is the transaction caller.
- `{"sum_over_callers": {"sig": "balanceOf(address)"}}` — a call evaluated once per observed caller and summed (the call must take exactly one `address`).

### Setup / seed transactions (`setup.json`)

Some bug classes are only reachable once contracts are wired together (an ERC4626 vault with `asset`, an initialized pair). `setup.json` declares these preconditions alongside the fixture; they are executed **once, before fuzzing**:

```json
{ "calls": [
  { "to": "Vault", "sig": "setAsset(address)",        "args": ["Asset"] },
  { "to": "Asset", "sig": "mint(address,uint256)",    "args": ["$caller", "1000000000000000000000"] },
  { "to": "Vault", "sig": "deposit(uint256,address)", "args": ["100000000000000000000", "$caller"] }
] }
```

With `--auto-setup` the wiring calls (`setX(address)`) are derived automatically, with no manual `setup.json` (value-moving seeds `mint`/`deposit` are deliberately **not** guessed by ForkSploit).

### Environment variables

| Variable | Effect |
|---|---|
| `ETH_RPC_URL` | The RPC used by the **Rust** binary (unconditionally, for every chain) — `auto_pipeline.py` sets it itself from `chains.get_rpc_url(chain)` |
| `SOLC` / `CAST` | Path to `solc` / `cast` (default from `PATH`) |
| `OFFCHAIN_POOL_SIZE` | Parallelism of `integration_test.py offchain` |

### Chains

The Rust binary supports **25 chains** (`Chain::from_str`): `eth`, `goerli`, `sepolia`, `bsc`, `chapel`, `polygon`, `mumbai`, `fantom`, `avalanche`, `optimism`, `arbitrum`, `gnosis`, `base`, `celo`, `zkevm`, `zkevm_testnet`, `blast`, `linea`, `local`, `iotex`, `scroll`, `vana`, `story`, `etc`, `mordor`.

Python orchestration (`chains.known_chains()`, also used by the `forksploit.sh` wizard) offers **21 chains** — all of the above except `goerli`, `mumbai`, `zkevm_testnet` and `local`, for which there is no default RPC in `chains.DEFAULT_RPC`. **First-class** are two networks, each in both variants: **Ethereum (ETH)** mainnet (id 1) / **Sepolia** (11155111) and **Ethereum Classic (ETC)** mainnet (id 61) / **Mordor** (63). Against them both plan generation and execution have been live-verified.

Test networks (safe to sign on without real value): `sepolia`, `chapel`, `mordor`. Everything else requires `--confirm-mainnet`.

---

## CLI reference

### `forksploit evm` (Rust core)

| Flag | Description |
|---|---|
| `-t, --target <GLOB\|ADDR>` | Glob pattern or `0x` target address (default `none`) |
| `--target-type <TYPE>` | `glob`, `address`, `anvil_fork`, `config`, `setup` (default derived) |
| `-c, --chain-type <CHAIN>` | Chain (see [Chains](#chains)) |
| `-u, --onchain-url <URL>` | RPC endpoint (default derived from `--chain-type`) |
| `-b, --onchain-block-number <N>` | Block (default `0` = latest) |
| `-k, --onchain-etherscan-api-key <K>` | Etherscan API key (for ABI/source) |
| `-d, --detectors <LIST>` | `all` (default), `high_confidence`, or a list of oracles |
| `-f, --flashloan` | Enable the simulated flashloan |
| `--concolic` | Enable concolic/Z3 solving |
| `--concolic-caller` | Symbolic caller (experimental) |
| `--concolic-timeout <MS>` | Solve time limit (default 1000) |
| `--concolic-memory-mb <MB>` | Z3 memory limit (default 2048; 0 = unlimited) |
| `--concolic-num-threads <N>` | Number of Z3 solvers (default 0 = cap `min(2, cores)`) |
| `--invariants <FILE>` | JSON with user invariants |
| `--auto-setup` | Automatic derivation of wiring preconditions |
| `-r, --replay-file <FILE>` | Replay a stored trace |
| `-w, --work-dir <DIR>` | Working directory (default `work_dir`) |
| `--run-forever` | Do not stop at the first finding |
| `--jobs <N>` | Parallel fuzzing processes (process isolation) |
| `--fuzz-seconds <N>` | Campaign time budget (0 = unlimited) |
| `--seed <N>` | Random seed |
| `--max-call-depth <N>` | Taint/concolic analysis depth (default 32) |
| `--spec-id <SPEC>` | EVM spec (e.g. `Shanghai` for ETC/Mordor) |
| `--state-comp-file <FILE>` | Reference state for the `state_comparison` oracle |
| `--panic-on-bug` | Panic on `typed_bug()` |

Full list: `./target/release/forksploit evm --help`.

### `auto_pipeline.py`

| Flag | Description |
|---|---|
| `--target <PATH\|ADDR>` | **Required.** Path to `.sol`/`.bin` (fresh deploy) or a `0x` address |
| `--key <FILE>` | **Required.** Private-key file of the funding wallet |
| `--recovery-wallet <ADDR>` | **Required.** Where all funds are extracted |
| `--chain <CHAIN>` | Chain (default `sepolia`) |
| `--confirm-mainnet` | Required for every chain that is not a testnet |
| `--fund-eth <ETH>` | Fund the target if it has zero balance |
| `--fuzz-seconds <N>` | Fuzzing time (default 300) |
| `--detectors <LIST>` | Oracles (default `all`) |
| `--no-preflight` | Disable the pre-flight profitability gate (both layers) |
| `--no-gas-oracle` | Disable the gas-price oracle (prices from the node instead of the explorer) |

### `batch_pipeline.py`

Same as `auto_pipeline.py`, except it takes `--targets <FILE>` instead of `--target` (one target per line), with **one** `--key` and **one** `--recovery-wallet` for the whole series.

---

## Helper tools

All in `onchain_scripts/`:

| Tool | Purpose |
|---|---|
| `monitor.py` | Continuous post-deploy monitoring: detects a balance outflow, a newly seen selector, a large transaction; optionally re-fuzzes periodically and, on alarm, attempts to rescue the remaining funds |
| `strategy_layer.py` | Merges plans into a coherent multi-step plan (`unlock → neutral → objective → reentrancy last`); argument-level threading, topological ordering of dependencies |
| `triage_findings.py` | Shrinks thousands of plans to a handful of real surfaces and says what separates each from an executable exploit |
| `materialize_plan.py` | For surfaces blocked by control leak, says which real state change would replace the faked call |
| `proxy_resolver.py` | Unwraps the proxy stack (EIP-1967/UUPS/beacon/EIP-1167/EIP-7702) |
| `gas_utils.py` | Gas measurement (`eth_estimateGas`) + `block.gasLimit`, GasBudget, clamp to `MAX_GAS_LIMIT` |
| `gas_oracle.py` | Gas **price** from an official explorer (Etherscan v2 for ETH, Blockscout v2 for ETC) |
| `flashbots_bundle.py` | A real Flashbots bundle (`eth_sendBundle`/`eth_callBundle`) for atomic inclusion |
| `chains.py` | The single source of truth for chains/RPC; `verify_rpc_identity`, `require_mainnet_confirmation` |
| `wallet_policy.py` | Locks the funding/recovery roles per chain; register/show/contracts |
| `aave_flashloan_runner.py` | Validates a flashloan-fundable bug against a real Aave V3 deployment |
| `dex_arbitrage_scanner.py` | Cross-DEX arbitrage scanner with the same security logic (locked profit, gas budget) |
| `dashboard_server.py` | A local web dashboard that projects real state and runs scripts as subprocesses |
| `deploy_sepolia_demo.py` | Deploys deliberately vulnerable demo contracts on Sepolia (E2E validation) |
| `gen_chain_fixture.py` | Deterministically generates an N-step "chain" fixture (depth measurement) |

---

## Development, tests and build

### Tests

```bash
# Rust unit tests
cargo test --release

# Python unit tests (no network)
cd onchain_scripts && python -m pytest -q

# W1–W3 proof (requires anvil + cast + solc)
bash onchain_scripts/contracts/proof_w1_w2_w3.sh

# Integration tests
python3 integration_test.py offchain     # no RPC
python3 integration_test.py onchain      # requires RPC + Etherscan key
```

**Expected state:** `cargo test --release` has a few tests that depend on a **live network** (RPC to a real chain) or on **pinned live state** (`test_get_balance` compares an exact address balance that has since changed). Measured: these tests fail **even with network access** — so they are not usable as CI gates. There are 10 such tests: `onchain_pair_discovery::*`, `uniswap::tests::test_get_pair`, `uniswap::tests::test_fetch_uniswap_path`, `endpoints::tests::test_get_balance`. Any *other* failure is a regression.

### CI (GitHub Actions, 100% free)

`.github/workflows/ci.yml` runs on GitHub-hosted `ubuntu-22.04` (no macOS/Windows and no self-hosted/EC2 runners) and checks **only the green, deterministic** things — no live network and no `anvil`/`solc`/`forge`:

```bash
# 1) Rust: build + tests (network/state-dependent tests skipped)
cargo build --release --features "cmp dataflow evm print_txn_corpus full_trace force_cache real_balance" --no-default-features --locked
cargo test --release -- \
  --skip onchain_pair_discovery \
  --skip uniswap::tests::test_get_pair \
  --skip uniswap::tests::test_fetch_uniswap_path \
  --skip endpoints::tests::test_get_balance
# -> 139 passed, 0 failed

# 2) Python: doctor + pytest (232 passed without anvil/solc)
./forksploit.sh --doctor --no-install
python -m pytest onchain_scripts -q -p no:cacheprovider
```

**Deliberately NOT gates** (they would be red on the current tree, and that is not this workflow's job): `cargo fmt --check` (the tree is not rustfmt-clean) and `cargo clippy` (existing warnings).

### Quality

```bash
cargo fmt --check
cargo clippy
```

### Feature flags

Defaults: `cmp`, `dataflow`, `evm`, `print_txn_corpus`, `full_trace`, `force_cache`, `real_balance`. Notable non-default: `evaluation`, `ondisk_corpus`, `deployer_is_attacker`, `fuzz_static`, `print_logs`, `z3_debug`, `flashloan_debug`, `no_etherscan`.

```bash
# Production build
cargo build --release --features "cmp dataflow evm print_txn_corpus full_trace force_cache real_balance" --no-default-features
```

---

## Limitations (honest)

ForkSploit is a powerful tool, but it is not magic. What it **cannot** do:

- **It is not a fully symbolic planner.** W5 covers common dependency families (approve→transferFrom, deposit→withdraw); general sequence synthesis with data-flow analysis between arbitrary arguments remains open.
- **The simulation model has no gas metering.** So the authoritative gas number is the node's `eth_estimateGas` against the real `block.gasLimit`, not the model.
- **No mempool/front-running model** (sandwich/backrun/JIT are outside the model).
- **Concolic is only partly storage-aware.** Symbolic SLOAD/SSTORE and symbolic call return values exist, but `keccak256` is not inverted, so a mapping entry from imported state is unreachable.
- **Controlled control leak.** For non-concolic search the control leak remains on by design; the label + downgrade (PHASE 2.3) ensure such a trace is **never** presented as `sim-confirmed`.
- **A negative result is bounded.** "Nothing found" means "nothing found in this budget with these oracles", not "the contract is free of vulnerabilities". ForkSploit prints this explicitly.
- **Aave flashloan is tied to chains with a live Aave V3** (`eth`, `sepolia`, and others from `AAVE_V3_POOLS`); ETC/Mordor have no Aave (verified — it does not exist).

A more detailed, continuously maintained record of limitations and blockers is in `LIMITATIONS.md` and `BLOCKERS.md`.

---

## Legal and ethical use

ForkSploit signs and sends **real transactions** that can move real value. Use it exclusively:

- on contracts **you own** or for which you have the owner's **written permission** (e.g. within a security review or a bug-bounty program), or
- on **test networks** (Sepolia, Mordor, Chapel).

Under this project's working model the recovery wallet is always the owner's wallet — ForkSploit is built for **defensive** validation and proving vulnerabilities before funds are loaded, not for attacking third-party contracts. Unauthorized use is illegal.

---

## License

**Proprietary license — all rights reserved.** ForkSploit, including the source
code, architecture, algorithms, heuristics, discovery and exploit-generation
logic, the name "ForkSploit", the documentation and all associated intellectual
property, is the exclusive property of the author. **No use, copying,
modification, distribution or dissemination is permitted, in whole or in part,
without the author's prior written permission.** Details in [`LICENSE`](LICENSE).

## Changelog

The full version history (what was added, changed, fixed) is in
[`CHANGELOG.md`](CHANGELOG.md). Current version: **v1.0.0**.
