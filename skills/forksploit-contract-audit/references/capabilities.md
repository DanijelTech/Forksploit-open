# Complete reference manual: ForkSploit system capabilities

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it.**

This document is a **complete list of facts about the ForkSploit system**, verified
directly in the source code (not from memory), intended so that Hermes (or any other
agent operating this system) knows EVERY point — commands, capabilities, limitations —
without having to interpret or guess from the code itself. For the PROCEDURE (how to
safely carry out a review) see `../SKILL.md`. This document is a LEXICON, not a
procedure.

## 1. Two-layer architecture

1. **Rust fuzzer** (`./target/release/forksploit`, built from `src/`) — the core:
   coverage-guided fuzzing + concolic (Z3) solving over EVM bytecode (revm). It finds
   and PROVES bugs with an actually executable transaction trace.
2. **Python orchestration layer** (`onchain_scripts/*.py`) — calls the Rust binary,
   manages wallets, chains, exploit generation/execution on real networks.

ForkSploit is **not** formal verification and does **not** understand a contract's
business logic — it is a pattern detector + fuzzer. See section 9 (Known limitations)
below.

## 2. Complete CLI reference: `./target/release/forksploit evm`

The command is run from the repository root. The most important flags (all flags
verified from `evm --help` on the current version):

| Flag | Meaning |
|---|---|
| `-t, --target <TARGET>` | Glob pattern to a local `.bin`/`.abi` file, OR a `0x...` address of an already-deployed contract. |
| `-c, --chain-type <CHAIN>` | Chain for an onchain target: `eth,goerli,sepolia,bsc,chapel,polygon,mumbai,fantom,avalanche,optimism,arbitrum,gnosis,base,celo,zkevm,zkevm_testnet,blast,linea,iotex,scroll,vana,story,etc,mordor,local`. |
| `-u, --onchain-url <URL>` | RPC URL for the `-c` chain. Default derived from `-c`, but ALWAYS pass it explicitly for local/forked nodes — see PHASE 1 in `../SKILL.md`. |
| `-b, --onchain-block-number <N>` | The block at which the fork/state read happens. Default: latest. |
| `-k, --onchain-etherscan-api-key <KEY>` | API key to fetch the verified ABI. Without it the fuzzer falls back to EVMole decompilation (works, but less precise). |
| `-f, --flashloan` | Enables flashloan simulation (Aave V3/Balancer V2 on supported chains) — the fuzzer can "borrow" real tokens during exploration. |
| `--run-forever` | Does NOT stop after the first finding — keeps looking for other bugs until the `--fuzz-seconds`-equivalent elapses (a time limit via the `timeout` command). Without this flag it stops at the FIRST finding. |
| `-d, --detectors <LIST>` | Which oracles are active. `all` (default) = all 47. `high_confidence` = only the subset with a low false-positive rate (see section 3). It can also be a single oracle by name (e.g. `reentrancy`). |
| `--concolic` + `--concolic-caller` | Enables Z3-backed symbolic solving (slower, but deeper) + treats the caller as symbolic. |
| `--concolic-timeout <MS>` | Time limit for one Z3 solve (default 1000 ms). |
| `--max-call-depth <N>` | How deep into the call chain (nested proxies, reentrancy) the analysis goes (default 32). |
| `--sha3-bypass` | Treats SHA3/keccak comparisons symbolically — can UNDERMINE the contract's original logic (experimental); use only for taint analysis, never for final confirmation. |
| `-w, --work-dir <PATH>` | Where the corpus, logs and findings are written. Default `work_dir`. |
| `--constructor-args <STR>` | Constructor arguments for LOCAL deployment (`ContractName:arg1,arg2,...`, separated by `;` for multiple contracts). The last argument may end in `wei`/`gwei`/`ether` (WITH A SPACE before the unit, e.g. `"10 ether"`) to set the contract's initial ETH balance. |
| `--only-fuzz <ADDR,...>` | Restricts fuzzing ONLY to the listed addresses (useful in multi-contract setups). |
| `setup.json` (in a fixture) | Declarative initialization calls (`{"calls":[{"to","sig","args"}]}`) executed on the freshly-deployed state BEFORE fuzzing, so the campaign starts from already-wired contracts (e.g. `Vault.setAsset(token)`, `Token.mint`). `to`/address arguments accept a contract name or `$caller`/`$deployer`. Unblocks classes that need a precondition (ERC4626 donation, initialized pairs). |
| `--spec-id <ID>` | EVM hardfork rules (`Frontier`...`Cancun`,`Latest`). For ETC ALWAYS use `Shanghai` explicitly (see section 8, the ETC peculiarity). |
| `-m, --deployment-script <Path:Contract>` | Use a Foundry setup script for deployment instead of `.bin`/`.abi` (e.g. to replace invariant tests with `forge test --mc`). |
| `--force-abi <address:abi_path,...>` | Forces the use of a given ABI for an address (useful with complex proxies the decompiler misreads). |
| `--replay-file <PATH>` / `-r` | Replays an already recorded trace instead of a new fuzzing run. |

Output (in `<work-dir>/vulnerabilities/`):
- `<Name>.t.sol` — a Foundry TEST reproduction. Generated for EVERY finding, without exception.
- `<Name>.plan.json` — a structured list of exploit steps (used by `auto_pipeline.py`).
- `<Name>Exploit.s.sol` — the actual EXECUTABLE Foundry SCRIPT. Generated ONLY for
  `(sim-confirmed)` bug types (see the exact list in section 4) — except Reentrancy,
  which has its own separate generator (`<Name>Exploit.s.sol` with an `attack()`/`receive()` pattern).

## 3. All detectors ("oracles") — complete list

ForkSploit has **46 oracle types** (`OracleType` in `src/evm/mod.rs`). Each is a
BYTECODE-LEVEL pattern detector — it does not understand business logic, it only
recognizes a pre-coded pattern. The label in the output (`(sim-confirmed)` /
`(sim-review)`) says whether the finding is proven true WITHIN THE SIMULATION or is
only a suspicion that needs human judgement (see the exact logic in
`src/evm/oracle.rs`'s `classify_confidence`, verified 2026-11-02). **The `sim-` prefix
was added 2026-11-02** (previously a bare `confirmed`/`review`) — because on real ETC
mainnet (plan `C9f53_2`) it turned out that revm (without gas metering) marked
something as "Confirmed", while the real chain rejected it (exceeded
`block.gasLimit`). This label therefore NEVER means "money actually moved on the real
chain" — only `auto_pipeline.py`'s `PLAN_CONFIRMED` (PHASE 7/8, requires a real balance
change) means that.

### Confirmed-tier (31 bug_type patterns in `classify_confidence`, from 47 oracles + the generic "Bug" invariant)

| Oracle (file) | bug_type string | What it detects |
|---|---|---|
| `access_control.rs` | Unauthorized Owner Change / Pause Toggle / Proxy Upgrade | Unauthorized change of owner/pause/proxy upgrade. |
| `arb_call.rs` | Arbitrary Call | Arbitrary call to an attacker-controlled address. |
| `erc20.rs` | Fund Loss | Loss of ERC20 funds from the contract. |
| `delegatecall.rs` | Delegatecall Injection | Delegatecall to an address that grows through the campaign (unbounded). |
| `delegatecall_target.rs` | Delegatecall Target From Calldata | The delegatecall target originates from calldata OR the return data of a previous call (real taint tracking, not random byte coincidence — see section 6). **Fixed and live-confirmed 2026-11-03** for the case where RETURNDATACOPY decoding and the DELEGATECALL itself are split across a control-leak boundary: (1) `calldata_addresses`/`returndata_addresses`/`paid_calldata_addresses` now seed from this branch's `vm_state` when resuming after a leak, instead of resetting to empty (the same bug class as `view_call_baseline`, a safer fix — see SKILL.md); (2) the `calldata.len() < 20` check was a wrong blanket early-return for the WHOLE oracle (it also blocked Confirmed-tier signals that do not depend on `calldata`), now limited only to the weaker byte-coincidence fallback. |
| `ecrecover.rs` | Unchecked ecrecover(0) | `ecrecover` returns address 0 (invalid signature), but the code does not check this. |
| `erc4626.rs` | ERC4626 Share Inflation | Incorrect share calculation in a standard ERC4626 vault. |
| `eth_backing.rs` | Insolvent: Promised Native Value Exceeds Real Balance | Promised funds (internal accounting) exceed the real ETH balance. |
| `initializer_front_run.rs` | Initializer Front-Running | Anyone can call `initialize()` before the real owner. |
| `nft_transfer.rs` | Unauthorized ERC721/ERC1155 Transfer | Unauthorized NFT transfer. |
| `preview_rounding.rs` | ERC4626 Rounding Favors User | A rounding bug in standard ERC4626 preview functions. |
| `proxy_integrity.rs` | Proxy Reinitialization / Proxy Storage Collision | Proxy reinitialization; STATIC comparison of proxy/implementation storage layouts (see section 6). |
| `proxy_upgrade_hijack.rs` | Unprotected Proxy Upgrade (UUPS) | An upgrade selector (`upgradeTo`/`upgradeToAndCall`/`changeAdmin`/`diamondCut`) CHANGED the EIP-1967 implementation/admin slot, the caller is NOT `owner()`, AND the admin slot is zero (the UUPS case `access_control.rs` does not reach). The largest code-level USD class of 2025-2026 (~$366M: USPD, Rari Fuse, UPCX). |
| `forged_proof.rs` | Forged Proof (Caller-Supplied Root Accepted) | The tx itself computed a hash (SHA3) and compared it for equality against a caller calldata word, the JUMPI ACCEPTED the comparison, and that word was NEVER compared against the contract's own stored value (`root == trustedRoot`). Real dataflow (SHA3 -> EQ -> JUMPI), not a guess. Review-tier: a verifier that legitimately takes the root as a parameter (stateless, called only by a trusted relay) is well-designed. Nomad/KelpDAO $308M+$44M, BNB Bridge. |
| `transient_guard.rs` | Transient Guard Released Before External Call | An EIP-1153 reentrancy guard (TLOAD/TSTORE, 0x5c/0x5d) was RELEASED (TSTORE 0 to the TLOAD-ed slot) BEFORE an external CALL/STATICCALL -- the protection window closes too early. The only oracle that decodes TSTORE/TLOAD (the SSTORE oracles do not even see them). Review-tier: transient storage may be a non-guard use, but it flags the exact unlock-then-call location. Uniswap V4-era pattern. |
| `reentrancy.rs` | Reentrancy | Classic reentrancy (has its OWN exploit generator, see section 4). |
| `selfdestruct.rs` | Selfdestruct | Reachable selfdestruct. |
| `signature_malleability.rs` / `signature_replay.rs` | Signature Malleability / Replay | Reuse or a malleable ECDSA signature. |
| `storage_collision.rs` | Storage Collision | A dynamically detected storage slot written both "natively" and via delegatecall. |
| `tx_origin.rs` | Tx.Origin Phishing Bypass | A `tx.origin` check that a proxy can bypass. |
| `typed_bug.rs` | Bug | A generic, user-defined Foundry invariant (from a `-m` setup script). |
| `v2_pair.rs` | Imbalanced Uniswap Pair | An abnormal change of one reserve in a V2-style pair. |
| `arb_transfer.rs` | Unauthorized ERC20 Transfer | Unauthorized ERC20 transfer. |
| `self_referral.rs` | Validation-Independent Payment | A payment is made REGARDLESS of whether the argument passes the contract's own validation (requires observing BOTH validation outcomes — hence Confirmed, not Review). |
| `arbitrary_storage_write.rs` | Arbitrary Storage Write | SWC-124: `SSTORE` whose slot argument is a raw (unhashed) value from calldata — NOT the normal `mapping[key]=value` (that always goes through KECCAK256), but raw `assembly { sstore(slot, value) }` with an attacker-chosen slot (the 2017 Parity multisig library pattern). Added 2026-11-03, the first new oracle from the roadmap. |

Review-tier addition (2026-11-03): `forced_eth_accounting.rs` (SWC-132) -- an
EQ comparison that uses `SELFBALANCE`/`BALANCE(address(this))` as an operand (i.e.
EXACT equality against its own real ETH balance). This is the OPPOSITE direction from
`eth_backing.rs` (which checks `sum(balances) > real balance`, insolvency) -- here it
is a DoS: a `SELFDESTRUCT` with 1 wei can PERMANENTLY break such a check, because no
legitimate transaction can remove the unwanted ETH. **Important finding during
testing**: a test fixture with an outgoing `.transfer()` call after the EQ check NEVER
reported a finding -- not because of an oracle bug, but because the fuzzer's own
control-leak mechanism (`host.rs`'s `call_allow_control_leak`) almost always intercepts
value-transferring calls, which `feedback.rs`'s `has_post_exec` check excludes from
reporting entirely — REGARDLESS of the bug being detected EARLIER in the same
transaction. Fix: the test fixture must have no outgoing value-transferring call to
prove the pattern without that unrelated noise.

Review-tier addition (2026-11-03): `readonly_reentrancy.rs` — a `view` function
(e.g. a price getter) that returns an inconsistent intermediate state while a
reentrancy window is open (the SWC read-only reentrancy pattern). It requires a
persistent `view_call_baseline` host field (the same reason as `slot_write_contexts`:
the standard "clear on every call" pattern is also wiped on resumption of a
control-leak continuation, not only on a genuinely new top-level transaction).
**Important, broader finding**: even after this fix, in practice this finding is
ALMOST NEVER reported, although the host-level detection is proven correct (thousands
of confirmed hits in a debug run) — the cause is not `feedback.rs`'s `has_post_exec`
gate (verified as working correctly: classic `Reentrancy` regularly passes it), but
the fuzzer's mutation/continuation strategy (`mutator.rs`/`evm_fuzzer.rs`), which
during an open control-leak window almost never tries exactly "call back `getPrice()`
now". For EVERY control-leak-dependent oracle (this one and future ones, e.g. ERC721/
1155 hook reentrancy): a low reporting rate on real contracts is not necessarily a
sign of poor detection — see `SKILL.md`'s section on this (2026-11-03) for the full
analysis and data.

Review-tier addition (2026-11-03): `token_accounting_mismatch.rs` — a successful
`transferFrom(from, address(this), amount)`, immediately followed by an SSTORE that
adds the UNVERIFIED `amount` (not the actually observed balance change) to the
previously SLOAD-ed value at the same slot. A fee-on-transfer/rebasing token breaks
that assumption. The detection is in `host.rs`'s `call()`/`0x55` case (not a separate
middleware, because it needs a decoded `CallInputs`, which only `call()` itself
sees); it is a proximity heuristic (not full dataflow), hence Review not Confirmed —
many real tokens have no fee/rebase, where this pattern is entirely safe.
| `twap_manipulation.rs` | TWAP Manipulation (Profit Confirmed) | A price jump >2x WITHIN THE SAME transaction, AND the caller provably profited (ETH balance increased). |
| `curve_virtual_price.rs` | Curve Virtual Price Decrease (Profit Confirmed) | A drop in `get_virtual_price()`, AND the caller provably profited. |

### Review-tier (uncertain, needs human judgement — NEVER gets an exploit script)

| Oracle | bug_type string | Why it is uncertain |
|---|---|---|
| `centralization_risk.rs` | Centralization Risk: Owner-Only Function | This is NOT a bug — it is an inventory of what the owner can do BY DESIGN. |
| `curve_virtual_price.rs` | Curve Virtual Price Decrease (WITHOUT "Profit Confirmed") | A price drop detected, but it is NOT proven that THIS caller profited. |
| `price_feed_staleness.rs` | Price Feed Staleness | Only a PRECONDITION for an attack, not a proven exploit. |
| `twap_manipulation.rs` | TWAP Manipulation Precondition (WITHOUT "Profit Confirmed") | The same — only a precondition. |
| `unbounded_loop.rs` | Unbounded Loop | A DoS/gas-griefing signal, not theft — a growing loop with no bound. |
| `stale_guard.rs` | Stale Guard Counter | It may be a legitimate admin flag, not necessarily a bug. |
| `unbacked_mint.rs` | Unbacked Mint (Supply Growth Without Backing) | `totalSupply()` grows in a tx without payment AND without a native ETH inflow, on a contract that ALREADY holds native ETH and ALREADY has supply>0. A public `mint()` is sometimes intentional (faucet/rebase/inflationary token), hence Review — a human judges whether the token is even meant to be native-backed. |
| `unchecked_call.rs` | Unchecked Low-Level Call | It can also fire on code that intentionally checks the result and continues. |
| `uninitialized_memory.rs` | Uninitialized Memory Read | An EVM read of zero can be entirely normal. |
| `state_comp.rs` | state_comp | The semantics depend ENTIRELY on the user's definition of the "desired state". |
| `overflow.rs` | Integer Overflow | ALWAYS active (not tied to the `-d` choice) — a known high false-positive rate (it fires on compiler-generated selector arithmetic). |
| `delegatecall_target.rs` | Delegatecall Target From Calldata (Unconfirmed) | A weaker variant — the address only RANDOMLY appears in the calldata bytes, not real taint tracking. |

**A rule without exceptions**: a `(sim-review)` finding NEVER means "proven attack".
Every `(sim-review)` finding IS provably reproduced IN SIMULATION (`.t.sol` exists),
but is NOT proven EXPLOITABLE in the sense of real profit on the real chain.

## 4. Which findings get an actual exploit script

Only `(sim-confirmed)` findings (section 3, the table above) get `*Exploit.s.sol` —
with THREE exceptions/peculiarities:

1. **Reentrancy** has its OWN separate generator (`generate_reentrancy_script`),
   because the attack shape (`attack()` fires once, `receive()` repeats) differs from
   the others (which simply replay the call sequence).
2. **Multi-caller traces are NEVER turned into an exploit script**, even if the
   bug_type is Confirmed — the `has_multiple_distinct_callers()` check in
   `src/evm/solution/mod.rs` prevents this, because it was PROVEN, confirmed in that
   session, that an attempt to "align" multiple identities into one produces a SCRIPT
   THAT ACTUALLY CRASHES on launch (verified on a real ERC4626 contract). In that case
   ONLY `.t.sol` (a test) is generated, not `.s.sol` (a script).
3. **Review-tier NEVER gets a script**, no matter how convincing the finding looks —
   this is a deliberate, non-negotiable safeguard, not a missing feature.

## 5. All `onchain_scripts/*.py` tools

| File | Purpose |
|---|---|
| `auto_pipeline.py` | The MAIN cycle: register→fund→fuzz→detect→exploit (through a reused `AttackWallet.sol`)→sweep to the recovery wallet. One command, one run. `execute_plan()` captures the real ETH AND ERC20 balance of the recovery wallet just before/after EVERY plan — `CONFIRMED` is returned only if the balance ACTUALLY increased (ETH via `recovery_delta_wei`, ERC20 via `stolen_asset` in `plan.json` + `sweepToken()`), otherwise the new status `EXECUTED_NO_PROFIT`. For `kind=="flat"` plans on `eth`/`sepolia`, when the signer lacks enough ETH, it tries a real Aave V3 WETH flashloan instead of `INCONCLUSIVE` (`execute_flat_plan_via_flashloan`) — live-verified on an Anvil fork of ETH mainnet 2026-11-02 (see Bugs below for the `SlotWarmed` fix that was needed to make this work). After an independent run it now also calls `strategy_layer.run_chain_attempts()` (see its own row below and `../SKILL.md` 2026-11-03). See `../SKILL.md` for safe use. |
| `strategy_layer.py` | **New 2026-11-03.** It smartly orders findings (UNLOCK before OBJECTIVE, numerically not lexicographically) instead of a bare `sorted(plan_files)`, and after an independent run tries chaining (an UNLOCK finding + an OBJECTIVE finding on the same target → one composed plan through the EXISTING `execute_plan()`) for cases like "forge a signature → call withdraw()" that no single oracle links by itself. Live-confirmed on an Anvil fork. Only `kind=="flat"`, only pairs, no funded plans — see `../SKILL.md` for the full scope/limitations. Imported from `auto_pipeline.py` AND `batch_pipeline.py`, never the reverse (no circular import). |
| `batch_pipeline.py` | The same as above, but for MULTIPLE targets at once (not yet reviewed in detail this session — check `--help` before use). |
| `chains.py` | The single source of truth for RPC addresses/overrides of all chains. `require_mainnet_confirmation()` lives here — see section 8. |
| `monitor.py` | CONTINUOUS monitoring of an already-deployed contract (not a one-off review) — it warns about unusual selectors/balance drops, and can AUTOMATICALLY trigger a fund rescue on a detected crisis (`--key`+`--safe-wallet`). |
| `wallet_policy.py` | Validation/registration of wallets per chain (prevents a typo between addresses). |
| `aave_flashloan_runner.py` | Real (not simulated) execution of a flashloan attack via Aave V3 — to REPRODUCE an already-found bug with real capital-free capital, not to DISCOVER. |
| `gas_utils.py` | Precise computation of the gas price/limit for transactions (never a flat guess). |
| `dex_arbitrage_scanner.py` | A cross-DEX arbitrage scanner over a **list** of pre-defined pairs (not a general "find any pair" scanner): on `eth` there are now 5 live-verified WETH pairs (USDC/USDT/DAI/WBTC, each with real non-zero reserves on BOTH DEXes, verified 2026-11-02) on exactly TWO hard-coded DEXes (Uniswap V2, SushiSwap V2). `--token-a`/`--token-b` restricts to one manual pair instead of the whole list. Profitability: ternary search, self-tested against brute force (`--self-test`). `--execute` on `eth` now ALWAYS submits `armFlashloanActions`+`startFlashLoan` as one atomic Flashbots bundle (not above a threshold — arbitrage competes with bots regardless of size), live-verified against the real `relay.flashbots.net` 2026-11-02. **Other chains from `KNOWN_V2_FACTORIES`** (ETC, BSC, Polygon, Arbitrum, Celo) **have only ONE live-verified V2 factory each** — cross-DEX arbitrage needs TWO; the second DEX was not found/verified (an attempt for BSC Biswap failed — no reliable address source, so it was not guessed in). General discovery of COMPLETELY new pairs (`allPairsLength`/`allPairs(i)` across factories) remains a separate, larger project. |
| `dashboard_server.py` | A lightweight local FastAPI web dashboard; run from the `forksploit/` root with `python3 onchain_scripts/dashboard_server.py` (OR from `onchain_scripts/` with `python3 dashboard_server.py` — never both at once, `onchain_scripts/onchain_scripts/...` does not exist), `http://127.0.0.1:8765` only — it projects wallet policy/RPC overrides/AttackWallet balances/run history, and launches `auto_pipeline.py`/`dex_arbitrage_scanner.py` with an argument parser built from `build_parser()` (not hand-duplicated). The confirmation prompt in the GUI is a plain text field (not a button) — the same "YES" requirement as the CLI. No security logic is duplicated — every run is the same CLI script as a subprocess. **Live-verified network identity**: `GET /api/verify-chain` calls the real `eth_chainId` (honouring an active RPC override) and compares it against `chains.CHAIN_IDS` — a dark graphite theme with an ETH (purple)/ETC (green) watermark logo and a colour badge that switches EXCLUSIVELY based on that live result, never on the text in the `--chain` dropdown; a mismatch or an unreachable RPC triggers a loud red warning bar. **Phase 2 DONE (2026-11-02)**: all 5 Python scripts launchable (added `monitor.py`/`batch_pipeline.py`/`aave_flashloan_runner.py`), `POST/DELETE /api/rpc-override` and `POST /api/wallet-policy` (the same `--confirm-chain` double confirmation), a direct Rust fuzzer launch (`forksploit evm`, a MANUALLY maintained `RUST_FUZZER_FIELDS` schema — the only place in the GUI without automatic synchronization with the CLI, because clap is not introspectable like argparse). **Python changes to `dashboard_server.py` require a process restart** (not just a browser refresh) — unlike `dashboard_static/*`, which are read fresh on every request. |
| `debug_file_generator.py`, `evaluate.py`, `immunefi.py`, `deploy_sepolia_demo.py` | NOT reviewed/documented in detail in previous sessions of this session — CHECK each one's `--help` before use, do not assume the purpose from the name. |

## 6. External source of truth for a REAL, already-deployed target: Blockscout verified code

For ANY real, already-deployed mainnet contract (not a local `.sol`/`.bin`), FIRST
check whether verified source code exists — free, without an API key:

```
curl -s "https://<chain>.blockscout.com/api/v2/smart-contracts/<0xADDRESS>"
```

(for ETC: `etc.blockscout.com`; other supported Blockscout instances exist for several
chains — check whether one exists for this specific chain before assuming it does not).
The response contains `is_verified` (bool), `source_code` (the full Solidity source,
if verified), `abi`, `compiler_version`, `constructor_args` (ABI-encoded — it may
contain readable strings, e.g. a description of the contract's purpose, as was
discovered 2026-11-02 on a real ETC oracle contract).

**Why this matters, not just "nice to have"**: ForkSploit's oracles work at the RAW
BYTECODE level and do NOT understand business logic (section 9). The real source code
distinguishes:
- Which function is ACTUALLY vulnerable (e.g. `claim()` vs. a similar-looking but
  correctly written `withdraw()` in the same contract — both can trigger the same
  generic "Reentrancy" oracle, but only one is actually profitable).
- False-positive review-tier findings in LIBRARIES (e.g. gas-optimized assembly-based
  math libraries, like Solmate/Solady `FixedPointMathLib`, use the raw `SUB` opcode
  without Solidity's overflow check BY DESIGN — this will trigger "Integer Overflow
  (sim-review)" on every such call, which IS correct bytecode-level detection, but is
  NOT an actual bug in the library itself).
- A precise, code-backed answer to PHASE 4a (whose funds they are, how access to them
  is gated — `msg.sender`-only? is there an admin override?).

## 7. What ForkSploit ACTUALLY fixed this session (concrete evidence, not promises)

- Real (not random byte coincidence) tracking of the delegatecall target's origin
  (CALLDATALOAD + RETURNDATACOPY observation in `host.rs`).
- Static comparison of proxy/implementation storage layouts WITHOUT the fuzzer needing
  to actually trigger a collision (`bytecode_analyzer::find_literal_sstore_slots`).
- Secondary profit confirmation for TWAP/Curve (not just "the price moved", but "the
  caller ACTUALLY profited in the same transaction").
- Extended exploit generation from 6 to 25+ confirmed bug types.
- SEVERAL real fixed bugs during verification (a missing `msg.value`, a one-time
  detection that blocked later findings, "control leak" rejections, a panic on
  malformed `--constructor-args`).

## 8. Security mechanisms (verified in the current code, NOT from memory)

- `onchain_scripts/chains.py`'s `require_mainnet_confirmation(chain, confirmed)` —
  called IMMEDIATELY after parsing `--chain`, BEFORE any signing. It rejects
  (`SystemExit`) EVERY chain not in `TESTNET_CHAINS = {"sepolia", "chapel",
  "mordor"}`, UNLESS `--confirm-mainnet` is given. ETH and ETC are BOTH "mainnet" by
  this logic (one character apart in the name — the most common mistake).
- **Old, stale information (DO NOT USE)**: `tui.py` and the interactive "I CONFIRM"
  prompt were REMOVED from the project — if you see a reference to them anywhere, it is
  stale. The only current mechanism is the `--confirm-mainnet` CLI flag.
- ETC peculiarity: `revm`'s `SpecId` has no true ETC variant. `Shanghai` is the closest
  correct one, but ETC deliberately did NOT adopt the Merge-related EIPs — the
  `DIFFICULTY` opcode (0x44) on ETC returns the real PoW difficulty, not `Shanghai`'s
  PREVRANDAO-style value. Always use `--spec-id Shanghai` explicitly when targeting
  ETC.
- Aave and Balancer do NOT EXIST on ETC — `-f` (flashloan) on ETC will have nothing to
  borrow from.
- **`anvil --fork-url` on ETC needs `--hardfork shanghai` explicitly.** The default
  `--hardfork latest` makes anvil expect post-Cancun (EIP-4844 blob gas) block headers,
  which a real pre-Cancun ETC node never returns — every `eth_call` on such a fork fails
  with `{"code":-32602,"message":"Excess blob gas not set."}`, while
  `eth_chainId`/`eth_blockNumber` keep working normally (so it can be misleading — the
  fork is "alive" but unusable). Verified and fixed 2026-11-02.
- **Local nodes often run in Docker** — the internal port inside the container (e.g.
  `8545/tcp`) is NOT necessarily reachable on the host; `docker ps` shows the actual
  mapped port (the `PORTS` column, in the form `0.0.0.0:XXXX->internal_port/tcp`).
  Always check this before assuming the "default" port for geth/core-geth/besu, etc.

## 9. Known, persistent limitations (do not try to "solve" them by guessing)

- ForkSploit does NOT understand business logic — it only recognizes pre-coded
  patterns (section 3). A new, context-specific attack that matches none of the 46
  patterns is INVISIBLE. This is exactly the motivation for the LLM-hypothesis layer,
  `onchain_scripts/llm_poc/` (BUILT and tested 2026-11-02, no longer "under
  construction"): `hypothesis_engine.py` asks a local Hermes (llama-server) to read the
  contract source and propose a concrete attack as strict JSON; `confirm_engine.py`
  (entirely the author's code, not the LLM's) ACTUALLY executes that proposal on a
  fresh Anvil fork and rules CONFIRMED/REFUTED exclusively from measured state changes
  — "the LLM proposes, the simulator rules"; the LLM never decides success on its own;
  `run_loop.py` links the two for up to N rounds of propose→confirm→(if REFUTED)
  refine. A real test (a local 35B model, 3 rounds): the model immediately guessed the
  SHAPE of the attack correctly (a donation via `transfer()` bypassing `deposit()` to
  inflate the share), but in no round did it discover the exact numeric trick (a
  minimal first self-deposit so that rounding down hurts the victim) — a real,
  documented capability limit of a small model, not an invented success. The
  confirmation engine was verified NOT to rubber-stamp: at the same time a correct
  hand-written hypothesis (CONFIRMED) and a deliberately wrong control hypothesis
  (REFUTED, profit=0).
- **Fixed 2026-11-02 (a previously valid trap)**: ERC20 token sweep is now wired into
  the automated pipeline. `plan.json` carries `stolen_asset` for raw ERC20 steps
  (`erc20_token_touched` in `src/evm/solution/mod.rs`, reusing `make_erc20_calls`
  selector logic), and `auto_pipeline.py`'s `execute_plan()` checks/sweeps each such
  token via `sweepToken()` after every plan. Live-verified on an Anvil fork:
  `AttackWallet.execute(WETH.deposit, 0.05 ETH)` → `sweepToken(WETH, 0.05 ETH)` →
  the recovery wallet received exactly 0.05 WETH. **A limitation that remains**: it
  captures only RAW ERC20 calls (transfer/transferFrom/mint/burn/skim/approve directly
  on the token contract) — "Fund Loss" findings that go through a buy/sell swap-router
  mechanism (`Tx.swap_data`) already convert the profit back to ETH as part of the
  trace itself (see `foundry_script.hbs`), so the ETH-based check already covers them;
  this field is for cases that NEVER go through a swap.
- **Flashloan "zero capital" is now wired in and live-verified** (a closed trap,
  2026-11-02): previously `auto_pipeline.py` always gave up (`INCONCLUSIVE`) when the
  signer lacked enough ETH to fund the plan. Now, for `kind=="flat"` plans on
  `eth`/`sepolia`, it tries a real Aave V3 WETH flashloan
  (`execute_flat_plan_via_flashloan`): borrow WETH, unwrap to raw ETH inside
  `executeOperation()`, run the exploit steps, wrap back for repayment — all atomic.
  **A bug actually caught during testing on an Anvil fork of ETH mainnet**: WETH9's
  `withdraw()` internally uses `msg.sender.transfer()` (a hard 2300 gas) for the send,
  which RELIABLY triggered `OutOfGas` in `AttackWallet.receive()` (a cold SLOAD of
  `pendingCallbackTarget` alone uses ~2100 gas). Fixed with `emit
  SlotWarmed(pendingCallbackTarget)` at the start of `executeOperation()`, which warms
  that storage slot BEFORE anything can trigger the callback. After the fix: the whole
  cycle confirmed successful on the fork, states matching to the last wei. **A
  limitation that remains**: only "flat" plans (not "reentrancy" — the combination with
  `armCallback` was not designed), only `eth`/`sepolia` (the only chains with a
  live-verified Aave pool AND WETH address — see `chains.py`; ETC has no Aave, a real
  network limitation).
- **MEV protection for the flashloan path added, + a real `sign_step()` bug fixed**
  (2026-11-02): `execute_flat_plan_via_flashloan` now takes `use_bundle`/`submit_w3`
  from `execute_plan` (the same decision, the same `FLASHBOTS_THRESHOLD_ETH`
  threshold) — on ETH mainnet above the threshold, `armFlashloanActions` and
  `startFlashLoan` are pre-signed and submitted TOGETHER as one atomic Flashbots
  bundle, instead of as two separate public transactions (which would expose the whole
  exploit to a mempool bot before `startFlashLoan`). On the first actual `sign_step()`
  call for this, a real, PRE-EXISTING bug was discovered (it would have affected every
  bundle, not just the flashloan): `**fee_fields` leaves an `is_legacy` key in the tx
  dictionary, which `eth_account` discards. Fixed with the same legacy/1559 dispatch as
  `gas_utils.build_precise_tx`. Live-verified on an Anvil fork: both transactions are
  now correctly pre-signed. **A second, more serious bug was discovered and FIXED the
  same day — the earlier assumption "403 = a datacenter-IP block of the relay" was
  WRONG**: the actual cause was `sign_request()` in `flashbots_bundle.py`, which was
  missing the `0x` prefix on the SIGNATURE itself (not on the hash) in the
  `X-Flashbots-Signature` header — the official Python example on docs.flashbots.net
  has the same bug (the Go example on the same page does not, because
  `hexutil.Encode` always adds `0x`). Systematically tested all 4 `0x` combinations
  directly against the REAL `relay.flashbots.net`: only (hash=0x+hex, signature=0x+hex)
  produced a clean shift from `-32025 "invalid flashbots signature"` to the normal
  `-32003 "insufficient funds"` — proof that the relay now accepts the signature.
  Fixed in `sign_request()`; the Flashbots bundle path is now actually verified against
  the production relay, not just against a fork.
- A `(sim-review)` finding without additional verification is NOT proof of
  exploitability. And `(sim-confirmed)` is NOT proof that anything is actually feasible
  on the real chain — only `PLAN_CONFIRMED` from `execute_plan()` (a real balance
  change) is that.
- No fuzzing approach can prove the ABSENCE of bugs — only their PRESENCE, if it finds
  them within the time it has available.
