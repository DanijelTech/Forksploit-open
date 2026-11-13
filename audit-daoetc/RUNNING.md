# How to run ForkSploit on your own machine

All verified 2026-11-07. Repo: `github.com/DanijelTech/ForkSploit` (branch `main`).

---

## 0. Prerequisites (install once)

| Tool | Why | Command (Debian/Ubuntu) |
|--------|-------|----------------------|
| **z3 + z3.h** | Rust `z3-sys` links the system Z3. **Without this the build fails or builds Z3 from source (hours).** | `sudo apt-get update && sudo apt-get install -y libz3-dev z3 pkg-config` |
| **build tools** | compilation | `sudo apt-get install -y build-essential clang cmake` |
| **Rust nightly** | the repo requires `nightly-2026-10-15` (see `rust-toolchain`) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh -s -- -y` |
| **solc 0.8.24** | compiling `.sol` fixtures | see below (svm) |
| **Foundry (anvil)** | chain fork + pre-flight simulation | `curl -sL https://foundry.paradigm.xyz \| bash && foundryup` |
| **Python 3** | the `onchain_scripts/` pipeline | `pip install -r onchain_scripts/requirements.txt` |

Check:
```bash
pkg-config --modversion z3     # e.g. 4.13.3.0
cargo --version                # nightly
anvil --version                # e.g. 1.9.0
```

### solc 0.8.24 (pinned)
The project looks for exactly `~/.svm/0.8.24/solc-0.8.24`. Easiest:
```bash
pip install solc-select
solc-select install 0.8.24 && solc-select use 0.8.24
mkdir -p ~/.svm/0.8.24 && cp "$(which solc)" ~/.svm/0.8.24/solc-0.8.24
```
(or manually: download `solc-linux-amd64-v0.8.24+...` from binaries.soliditylang.org and save it to that path)

---

## 1. Clone and build

```bash
git clone https://github.com/DanijelTech/ForkSploit.git
cd ForkSploit
cargo build --release          # ~5-10 min the first time; at the end: target/release/forksploit
```
Check:
```bash
./target/release/forksploit --version
./target/release/forksploit evm --help
```

---

## 2. Run

### A) Interactive wizard (recommended)
```bash
./forksploit.sh
```
It asks you for 3 things: **who funds** (the path to `key.txt`), **what is being
reviewed** (a `0x...` address or a path to `.sol`/`.bin`), **where the extracted
funds go** (the recovery wallet). Then it runs `auto_pipeline.py`.

### B) Direct — fuzz a deployed contract on a live chain
```bash
./target/release/forksploit evm -t 0xTARGET_ADDRESS -c etc \
    --onchain-url https://etc.etcdesktop.com
```
`-c` is the chain (`eth`, `etc`, `sepolia`, `base`, `arbitrum`, …).

### C) Direct — fuzz a local contract
```bash
solc contracts/Target.sol -o out/ --bin --abi --overwrite
./target/release/forksploit evm -t 'out/*' -f
```

### D) With **concolic (Z3)** — deeper branch solving
```bash
./target/release/forksploit evm -t 'out/*' -f -d all \
    --concolic --concolic-caller --concolic-num-threads 4
```
Concolic **requires** a source map: compile with `--combined-json bin-runtime,srcmap-runtime`.

### E) Full pipeline (deploy → fund → fuzz → exploit → recover)
```bash
python3 onchain_scripts/auto_pipeline.py \
    --target /path/to/Contract.sol \
    --recovery-wallet 0xYourWallet \
    --key key.txt \
    --fund-eth 0.01
```

---

## 3. Our target (DAOETC, ETC mainnet)

```bash
# 1) a local ETC fork (ETC requires --hardfork shanghai!)
anvil --fork-url https://etc.etcdesktop.com --chain-id 61 \
      --gas-limit 8000000 --hardfork shanghai --port 8545

# 2) fuzz the target against the fork (in a second terminal)
cd ForkSploit
./target/release/forksploit evm \
    -t '0x9f5304DA62A5408416Ea58A17a92611019bD5ce3' \
    --target-type address -c etc -u http://localhost:8545 \
    --concolic --concolic-caller --concolic-num-threads 4
```

> **ETC + anvil:** ETC skipped the Merge EIPs, so `--hardfork latest` fails with
> `"Excess blob gas not set."`. Always use `--hardfork shanghai`.

---

## 4. Tests (check that everything works)

```bash
cargo test                                  # Rust unit tests
python3 integration_test.py offchain        # integration (no RPC)
python3 integration_test.py onchain         # requires RPC + Etherscan key
```

---

## 5. Common issues

| Symptom | Cause | Fix |
|---------|-------|---------|
| `cargo build` builds Z3 from source (hours) or fails | no `z3.h` | `sudo apt-get install libz3-dev z3 pkg-config` |
| `Nothing to fuzz` | the fixture is not compiled | `solc … --bin --abi` into the fixture directory |
| `Excess blob gas not set` | ETC + `--hardfork latest` | `--hardfork shanghai` |
| concolic solves nothing | no source map | solc `--combined-json bin-runtime,srcmap-runtime` |
| `unrecognised option '--base-path'` | an outdated system solc | use the pinned 0.8.24 (`~/.svm/0.8.24/`) |
| `Invalid option for --evm-version: cancun` (exit 64) | the file at `~/.svm/0.8.24/solc-0.8.24` is NOT really 0.8.24 | replace it with the real 0.8.24 (see §0); also fixed in the code (it detects this and falls back to `shanghai`/`london`) |
| the pre-flight does not run | no `anvil` on PATH | install Foundry |

---

## 6. Note on our fixes (commit `8e6a572`)

The concolic module **no longer crashes** on unsupported opcodes / unexpected
symbolic shapes — every `panic!` is replaced with graceful degradation. If you
want this fix, use our branch (already on `origin/main`). If you want clean
upstream only, clone without our commits — but then expect crashes on targets
with unsupported opcodes.


---

## 7. FIXED: `Invalid option for --evm-version: cancun` (exit 64)

**Symptom:** `./forksploit.sh` fails in `get_or_deploy_attack_wallet` →
`subprocess.CalledProcessError ... exit status 64`.

**Cause:** `onchain_scripts/auto_pipeline.py` hardcoded `--evm-version cancun`,
which only solc >= 0.8.24 accepts. If `~/.svm/0.8.24/solc-0.8.24` is not really
0.8.24 (e.g. an outdated/hand-copied binary), solc returns `Invalid option for
--evm-version: cancun` and exit 64 — before a single exploit step runs.

**Fix (in the code):**
- `_find_solc()` now **checks** the `--version` of the pin; if it is not 0.8.24,
  it rejects it and prints a clear warning.
- `_solc_extra_flags()` **probes** (`cancun → shanghai → paris → london`) and
  uses the newest supported one; if none, it omits `--evm-version`.

**Immediate fix on your machine (without waiting for the patch):**
```bash
# check what is really at that path:
~/.svm/0.8.24/solc-0.8.24 --version
# if it is NOT 0.8.24, replace it with the real one:
curl -sL -o /tmp/solc0824 \
  https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9
chmod +x /tmp/solc0824
cp /tmp/solc0824 ~/.svm/0.8.24/solc-0.8.24
~/.svm/0.8.24/solc-0.8.24 --version   # must say 0.8.24
```
