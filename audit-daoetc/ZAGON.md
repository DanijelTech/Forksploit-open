# Kako zagnati ForkSploit na svojem računalniku

Vse preverjeno 2026-11-07. Repo: `github.com/DanijelTech/ForkSploit` (branch `main`).

---

## 0. Predpogoji (namesti enkrat)

| Orodje | Zakaj | Ukaz (Debian/Ubuntu) |
|--------|-------|----------------------|
| **z3 + z3.h** | Rust `z3-sys` linka sistemski Z3. **Brez tega build pade ali gradi Z3 iz vira (ure).** | `sudo apt-get update && sudo apt-get install -y libz3-dev z3 pkg-config` |
| **build orodja** | prevajanje | `sudo apt-get install -y build-essential clang cmake` |
| **Rust nightly** | repo zahteva `nightly-2026-10-15` (glej `rust-toolchain`) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh -s -- -y` |
| **solc 0.8.24** | prevajanje .sol fixture-ov | glej spodaj (svm) |
| **Foundry (anvil)** | fork verige + pre-flight simulacija | `curl -sL https://foundry.paradigm.xyz \| bash && foundryup` |
| **Python 3** | `onchain_scripts/` pipeline | `pip install -r onchain_scripts/requirements.txt` |

Preveri:
```bash
pkg-config --modversion z3     # npr. 4.13.3.0
cargo --version                # nightly
anvil --version                # npr. 1.9.0
```

### solc 0.8.24 (pinned)
Projekt išče točno `~/.svm/0.8.24/solc-0.8.24`. Najlažje:
```bash
pip install solc-select
solc-select install 0.8.24 && solc-select use 0.8.24
mkdir -p ~/.svm/0.8.24 && cp "$(which solc)" ~/.svm/0.8.24/solc-0.8.24
```
(ali ročno: prenesi `solc-linux-amd64-v0.8.24+...` z binaries.soliditylang.org in shrani na to pot)

---

## 1. Kloniraj in zgradi

```bash
git clone https://github.com/DanijelTech/ForkSploit.git
cd ForkSploit
cargo build --release          # ~5-10 min prvič; na koncu: target/release/forksploit
```
Preveri:
```bash
./target/release/forksploit --version
./target/release/forksploit evm --help
```

---

## 2. Zaženi

### A) Interaktivni čarovnik (priporočeno)
```bash
./forksploit.sh
```
Vpraša te za 3 stvari: **kdo financira** (pot do `key.txt`), **kaj se pregleduje**
(naslov `0x...` ali pot do `.sol`/`.bin`), **kam gredo pobrana sredstva**
(recovery denarnica). Nato požene `auto_pipeline.py`.

### B) Neposredno — fuzzaj deployano pogodbo na živi verigi
```bash
./target/release/forksploit evm -t 0xTARGET_ADDRESS -c etc \
    --onchain-url https://etc.etcdesktop.com
```
`-c` je veriga (`eth`, `etc`, `sepolia`, `base`, `arbitrum`, …).

### C) Neposredno — fuzzaj lokalno pogodbo
```bash
solc contracts/Target.sol -o out/ --bin --abi --overwrite
./target/release/forksploit evm -t 'out/*' -f
```

### D) Z **concolic (Z3)** — globlje reševanje vej
```bash
./target/release/forksploit evm -t 'out/*' -f -d all \
    --concolic --concolic-caller --concolic-num-threads 4
```
Za concolic je **nujen source-map**: prevajaj s `--combined-json bin-runtime,srcmap-runtime`.

### E) Popoln pipeline (deploy → fund → fuzz → exploit → recover)
```bash
python3 onchain_scripts/auto_pipeline.py \
    --target /path/to/Contract.sol \
    --recovery-wallet 0xTvojaDenarnica \
    --key key.txt \
    --fund-eth 0.01
```

---

## 3. Naša tarča (DAOETC, ETC mainnet)

```bash
# 1) lokalni fork ETC (ETC zahteva --hardfork shanghai!)
anvil --fork-url https://etc.etcdesktop.com --chain-id 61 \
      --gas-limit 8000000 --hardfork shanghai --port 8545

# 2) fuzzaj tarčo proti forku (v drugem terminalu)
cd ForkSploit
./target/release/forksploit evm \
    -t '0x9f5304DA62A5408416Ea58A17a92611019bD5ce3' \
    --target-type address -c etc -u http://localhost:8545 \
    --concolic --concolic-caller --concolic-num-threads 4
```

> **ETC + anvil:** ETC je preskočil Merge EIP-je, zato `--hardfork latest`
> pade z `"Excess blob gas not set."`. Vedno uporabi `--hardfork shanghai`.

---

## 4. Testi (preveri, da vse dela)

```bash
cargo test                                  # Rust unit testi
python3 integration_test.py offchain        # integracijski (brez RPC)
python3 integration_test.py onchain         # zahteva RPC + Etherscan ključ
```

---

## 5. Pogoste težave

| Simptom | Vzrok | Rešitev |
|---------|-------|---------|
| `cargo build` gradi Z3 iz vira (ure) ali pade | ni `z3.h` | `sudo apt-get install libz3-dev z3 pkg-config` |
| `Nothing to fuzz` | fixture ni preveden | `solc … --bin --abi` v mapo fixture-a |
| `Excess blob gas not set` | ETC + `--hardfork latest` | `--hardfork shanghai` |
| concolic ne reši nič | ni source-map | solc `--combined-json bin-runtime,srcmap-runtime` |
| `unrecognised option '--base-path'` | prestar sistemski solc | uporabi pinned 0.8.24 (`~/.svm/0.8.24/`) |
| `Invalid option for --evm-version: cancun` (exit 64) | datoteka na `~/.svm/0.8.24/solc-0.8.24` NI res 0.8.24 | zamenjaj jo s pravim 0.8.24 (glej §0); popravljeno tudi v kodi (sam zazna in pade na `shanghai`/`london`) |
| pre-flight se ne izvede | ni `anvil` na PATH | namesti Foundry |

---

## 6. Opomba o naših popravkih (commit `8e6a572`)

Concolic modul **ne pada več** na nepodprtih opcodih / nepričakovanih simbolnih
oblikah — vsi `panic!` so zamenjani z graceful degradacijo. Če želiš ta popravek,
uporabi naš branch (že na `origin/main`). Če želiš le čist upstream, kloniraj
brez naših commitov — a potem pričakuj pade na tarčah z nepodprtimi opcodi.


---

## 7. POPRAVLJENO: `Invalid option for --evm-version: cancun` (exit 64)

**Simptom:** `./forksploit.sh` pade v `get_or_deploy_attack_wallet` →
`subprocess.CalledProcessError ... exit status 64`.

**Vzrok:** `onchain_scripts/auto_pipeline.py` je trdo podal `--evm-version cancun`,
kar sprejme **samo solc >= 0.8.24**. Če `~/.svm/0.8.24/solc-0.8.24` ni res 0.8.24
(npr. prestara/hand-copied binarka), solc vrne `Invalid option for --evm-version: cancun`
in exit 64 — še preden se izvede en sam exploit korak.

**Popravek (v kodi):**
- `_find_solc()` zdaj **preveri** `--version` pin-a; če ni 0.8.24, ga zavrne in
  izpiše jasno opozorilo.
- `_solc_extra_flags()` **sonda** (`cancun → shanghai → paris → london`) in uporabi
  najnovejšo podprto; če ni nobene, izpusti `--evm-version`.

**Takojšnja rešitev na tvojem računalniku (ne da bi čakal na popravek):**
```bash
# preveri, kaj je res na tisti poti:
~/.svm/0.8.24/solc-0.8.24 --version
# če NI 0.8.24, jo zamenjaj s pravo:
curl -sL -o /tmp/solc0824 \
  https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9
chmod +x /tmp/solc0824
cp /tmp/solc0824 ~/.svm/0.8.24/solc-0.8.24
~/.svm/0.8.24/solc-0.8.24 --version   # mora reči 0.8.24
```
