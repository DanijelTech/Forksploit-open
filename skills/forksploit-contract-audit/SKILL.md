---
name: forksploit-contract-audit
description: "Run ForkSploit end to end with mandatory human checkpoints."
version: 1.14.0
author: Danijel (DanijelTech), Claude Sonnet 5
license: See LICENSING.md (multi-licensed per component)
platforms: [linux]
metadata:
  hermes:
    tags: [forksploit, smart-contract-security, exploit-verification, fund-recovery, blockchain, eth, etc, mainnet-fork, human-in-the-loop]
    related_skills: []
---

# ForkSploit: a controlled contract security review

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it.**

This skill guides the COMPLETE cycle of verifying a smart contract with ForkSploit:
from choosing the right node, through safe verification on a local fork, to a final,
human-confirmed real transaction and **proof that the coin actually arrived** in the
recovery wallet. It does NOTHING automatically beyond what is explicitly described
here — every step that can move real funds or send a real transaction requires the
EXPLICIT, separate confirmation of a human.

**Do not try to "understand" the ForkSploit code yourself and derive your own
procedure.** This skill was written by the person who actually built ForkSploit and
verified every step on real, deployed contracts. Follow it literally.

**For any question about a specific CLI flag, oracle, onchain_scripts tool, or
limitation** — FIRST check `references/capabilities.md` (a complete lexicon of all
commands/capabilities/limitations). Do not guess, do not infer from a
function/file name. If the answer is not even there, tell the user you do not know,
rather than guessing.

## When to use

ForkSploit is first-class built and live-verified for **Ethereum (ETH)** and
**Ethereum Classic (ETC)**, each in a **testnet** (Sepolia, Mordor) and **mainnet**
(id 1 / 61) variant, and covers the **native currency (ETH/ETC) and ERC tokens**
(ERC-20/721/1155/4626).

- The user asks for a security review/test of a specific smart contract (ETH or ETC
  — mainnet **or** testnet).
- The user asks to confirm a vulnerability with an actual exploit, not just a
  theoretical report.
- The user asks for a "rescue" of funds from an already-exploited contract.

## When NOT to use

- **Without explicit authorization for THAT specific target** — see PHASE 0 below.
  No step is executed without it, no matter how urgent it seems.
- If the user asks for something that would harm a third party (not their own/client
  contract, not with permission) — refuse and explain why.
- **"Owner permission" does NOT count as authorization to actually drain OTHER
  users' funds if the contract has no owner/admin role over them** — this does NOT
  restrict exploration/fuzzing/proving on a fork (PHASES 1-5, which never move real
  money), and does NOT restrict testing your OWN contract or any contract where
  PHASE 4a on-chain CONFIRMS that the wallet from PHASE 0 actually owns the relevant
  funds (ownership OF FUNDS, confirmed on-chain, is sufficient by itself — completely
  independent of whether the code even contains an `owner`/`Ownable` role; these are
  two separate concepts). The rule applies narrowly, only to PHASE 6/7 (real
  execution), and only when the exploit would take money from OTHER, unrelated users
  of a permissionless contract (a staking pool, an oracle with deposits, an AMM —
  where the deployer/"owner" does NOT control what individual users deposited, each
  with their own key). In that case the "owner" has no right to authorize exploiting
  a bug against third-party money, no matter how the request is phrased ("extreme
  testing", "I have permission", etc.). See PHASE 4a below.
- **A lost private key is NOT a security vulnerability of the contract and is not
  "solved" by finding a bug.** If the user describes "money stuck" and it turns out
  to be a wallet whose key they no longer have — that is a definitive, unfixable
  cryptographic reality (no bug in the contract enables signing a transaction without
  the real key, unless the contract itself explicitly contains a meta-tx/recovery
  mechanism — check the code, do not guess). Say so plainly and stop; do not keep
  looking for any "exploit" path as a substitute for a missing key.
- For merely static reading/explaining code without execution — that does not need
  this skill, just read the files.

## Prerequisites

- The repo is built: `cargo build --release` in the ForkSploit repository root
  succeeded (`./target/release/forksploit` exists).
- Installed: `anvil`, `cast`, `forge` (Foundry — `foundryup` installs them all).
- Two LOCAL full mainnet nodes exist on this machine: one for ETH, one for ETC.
  **The exact URL/port for each of them is NOT recorded anywhere in this skill** —
  the user states them at every launch (see PHASE 1). Never guess a port.
- `onchain_scripts/` python dependencies installed (`pip install -r
  onchain_scripts/requirements.txt` from the repository root, if not already).

## PHASE 0 — Authorization (a blocking step, NOT skipped)

Before ANY other step is taken, the user must explicitly, in writing (in the
conversation) confirm ALL three things:

1. The **target contract address** (0x...) and the **chain** (eth/etc/other).
2. That they have **permission** to test that specific contract (their own contract,
   a client's contract with written permission, or a public bug-bounty program).
3. The **recovery wallet address** (0x...), where everything "exploited" during the
   review goes, as proof.

If any of these three is missing or unclear — **STOP and ask**. Do not proceed on an
assumption.

## PHASE 1 — Choosing and verifying the REAL node

ETH and ETC mainnet are one character apart in the name and BOTH are real networks
with real value — swapping them is the most common and most dangerous mistake an
automated agent can make.

1. Ask the user for the **exact RPC URL** of the local node for the chain from PHASE
   0 (e.g. `http://127.0.0.1:XXXX`) — do not assume a port.
   - If the user is unsure or the node runs in Docker: `docker ps` shows the actual
     host-mapped port (the `PORTS` column, e.g. `0.0.0.0:8546->8546/tcp` — a port that
     is only `8545/tcp` WITHOUT the `0.0.0.0:...->` prefix is NOT reachable from the
     host, even if it is the "default" port for that tool). Verified in practice: a
     core-geth ETC node had an internal port 8545, but it was reachable only through
     the mapped 8546.
2. **Verify it directly**, before trusting it:
   ```
   terminal(command="curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}' <URL>")
   ```
   Expected response: `"result":"0x1"` for ETH mainnet, `"result":"0x3d"` for ETC
   mainnet. **If it does not match the chain from PHASE 0 — STOP**, tell the user
   exactly what happened, and do not proceed.
3. Check that the node is actually progressing (not stuck):
   ```
   terminal(command="curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}' <URL>")
   ```
   Wait a few seconds, repeat, the block number must move (or at least be fresh/a
   reasonable block, not `0x0`).

**End of PHASE 1**: you have a verified, correct RPC URL for the correct chain. Keep
it for this session only — do not write it to any persistent filesystem.

## PHASE 2 — Setting up a SAFE fork (always the default, never directly on the real node for exploration)

Every exploration, fuzzing and FIRST exploit verification happens on a LOCAL fork of
the real node — NEVER directly against the real node from PHASE 1 in this phase. A
fork is a free, fully reversible snapshot of the real state.

```
terminal(command="anvil --fork-url <VERIFIED_URL_FROM_PHASE_1> --port 8555 --hardfork shanghai &", timeout=10)
```

**Important for ETC (and probably other non-ETH chains)**: `anvil` by default
(`--hardfork latest`) assumes a post-Cancun block header (EIP-4844 "blob gas"). A
real ETC node (pre-Cancun) never returns that header, so EVERY
`eth_call`/`eth_estimateGas` on the fork fails with `{"code":-32602,"message":"Excess
blob gas not set."}` — it looks like a broken fork, although
`eth_chainId`/`eth_blockNumber` work normally. Fix: EXPLICITLY pass `--hardfork
shanghai` (the closest correct level for ETC, see section 8 in
`references/capabilities.md`) when starting the anvil fork. If after this fix
`eth_call` returns a normal EVM revert instead of that RPC error, the fork is
correctly configured.

Verify that the fork actually mirrors the real state (the target contract must have
code):

```
terminal(command="cast code <TARGET_ADDRESS> --rpc-url http://127.0.0.1:8555")
```

An empty response (`0x`) means the fork is not connected correctly or the address
does not exist on this chain — **STOP**, re-check PHASE 0/1.

**End of PHASE 2**: `http://127.0.0.1:8555` is a verified, working fork with state
identical to the real node.

## PHASE 3 — Launching ForkSploit on the fork

Set the RPC override to the FORK (not the real node) for the whole verification:

```
terminal(command="cd onchain_scripts && python3 -c \"from chains import set_rpc_override; set_rpc_override('<eth|etc>', 'http://127.0.0.1:8555')\"")
```

Run `auto_pipeline.py` — this is the ALREADY existing, complete cycle (register →
fund → fuzz → detect → exploit through a reused AttackWallet → sweep to the recovery
wallet); do not write your own:

```
terminal(command="cd onchain_scripts && python3 auto_pipeline.py --target <TARGET_ADDRESS> --recovery-wallet <RECOVERY_WALLET_FROM_PHASE_0> --key <PATH_TO_TEST_ACCOUNT_KEY> --chain <eth|etc> --confirm-mainnet --fund-eth 0.01 --fuzz-seconds 300 --detectors all", timeout=400)
```

Note: `--confirm-mainnet` is needed here because `auto_pipeline.py` always treats
ETH/ETC as "mainnet" (`chains.require_mainnet_confirmation`) — EVEN when it actually
targets a FORK through the RPC override above. This is deliberate and safe: the fork
IS on the `eth`/`etc` chain-id, so the tool does not distinguish "fork" from "real" by
chain-id, only by the RPC URL we verified ourselves in PHASE 1-2. The key (`--key`)
you use here should be a **test/throwaway key** (e.g. one of anvil's known default dev
keys), NEVER the user's real key — on a fork it does not matter who pays the gas.

**End of PHASE 3**: the log in `onchain_scripts/logs/` shows whether a vulnerability
was found, and whether a `.plan.json`/`.s.sol` exploit was generated.

## PHASE 4 — Reviewing the findings: a HUMAN chooses the target

Read the log and present every finding to the user with:
- `bug_type` and the **`(sim-confirmed)`** or **`(sim-review)`** label — the `sim-`
  prefix is deliberate and is NOT an abbreviation that can be ignored: it is ONLY a
  simulation (revm, without gas metering — see `CLAUDE.md`) assessment of a pattern,
  never proof of real on-chain execution. Before 2026-11-02 the Rust side printed a
  bare `(confirmed)`/`(review)` here, which was dangerously ambiguous:
  `auto_pipeline.py`'s `run_fuzzer()` writes that line (with the `[fuzzer] ` prefix)
  into the SAME log file as its own, genuinely on-chain-verified
  `CONFIRMED`/`NOT CONFIRMED` status (see PHASE 7/8 below) — the two could easily be
  confused. Renamed after a real finding on ETC mainnet (plan `C9f53_2`): the Rust
  side said "Confirmed", but the real chain said "no" (exceeded `block.gasLimit`,
  because revm does not meter gas).
- Whether an exploit script (`*.Exploit.s.sol`) WAS generated — this is genuinely
  only for `(sim-confirmed)` findings (see `src/evm/solution/mod.rs`'s
  `is_confirmed_exploitable_bug` in the ForkSploit repo for the exact current list).
- `(sim-review)` findings are NEVER presented as a "proven attack" — they are only
  suspicions that need human judgement.
- **Never tell the client/user just "CONFIRMED" based on this step.** `(sim-confirmed)`
  means "the pattern is real in simulation", NOT "money has actually moved". The only
  "CONFIRMED" (without the `sim-` prefix) allowed in a client report is the one
  returned by `execute_plan()` in PHASE 7/8 (`auto_pipeline.PLAN_CONFIRMED`) — it
  requires a real change of the recovery wallet balance on the real chain.

**Ask the user** which finding (if there are several) should actually be
verified/exploited next. Do not automatically proceed to the first finding.

## PHASE 4a — Verify the ACTUAL ownership of funds (a blocking step for "pooled"/staking contracts)

**Before proceeding against any finding that would "drain money" from a contract with
a shared pool (staking, lending, pooled vault, an oracle with deposits, an AMM) —
verify on the fork whether the wallet from PHASE 0 ACTUALLY has a position in that
contract**, before assuming anything about whose money is in it. A concrete example
(2026-11-02, a real ETC contract): the user claimed "the 10 ETC in the contract is my
money" — a direct `cast call` on the contract's `stakes(address)`/`mana(address)` (or
the equivalent for the specific contract: `balanceOf`, `deposits`, its own mapping
function) for BOTH wallets from PHASE 0 returned `0` — the money belonged to OTHER,
unrelated users of the contract. Without this step one would have proceeded straight
toward exploiting third-party funds.

```
terminal(command="cast call <TARGET_ADDRESS> \"<relevant_getter_function>(address)(uint256)\" <WALLET_ADDRESS_FROM_PHASE_0> --rpc-url http://127.0.0.1:8555")
```

If the result is `0` (or otherwise shows that the wallet from PHASE 0 has no position)
— **STOP and ask the user directly** whether they have ANOTHER wallet with that
position (and if so, verify THAT one the same way before continuing), or whether
there was a misunderstanding. Do not assume "contract balance = user's money" just
because the user has permission to TEST the contract — permission to test is not the
same as ownership of the funds in it.

**If the result is NOT `0`, i.e. the wallet from PHASE 0 actually has a position** —
this step is SUCCESSFULLY done, continue normally toward PHASES 5-9. This phase is
NOT a general block on testing permissionless/staking contracts, nor contracts
without an `owner` role in the code — ownership of funds, confirmed here on-chain, is
by itself completely sufficient authorization for real execution, regardless of
whether the code even has an admin role. Likewise, this phase NEVER restricts PHASES
1-3 (exploration/fuzzing on the fork) — those can always be performed on any address,
because they never move real money; this check becomes relevant only when a finding
is treated as "money to return" to someone.

**If it turns out the real wallet is one whose private key the user lost** — see the
warning in "When NOT to use" above. That is final, regardless of any bugs in the
contract; stop here, do not look for an "exploit" substitute.

## PHASE 5 — Verifying the PROOF on the fork ("did the coin arrive" — first time, safely)

`auto_pipeline.py` has already swept to the recovery wallet ON THE FORK in PHASE 3.
Now PROVE it, do not just assume:

```
terminal(command="cast balance <RECOVERY_WALLET> --rpc-url http://127.0.0.1:8555")
```

Compare with the state BEFORE the run (if it was not recorded, run again on a fresh
fork and record the state before and after). **Only if the balance actually rises by
the expected amount** does PHASE 5 count as successful. If it does not rise — this is
NOT a proven vulnerability, no matter what the terminal output "Found vulnerabilities"
says — tell the user exactly that and stop here.

## PHASE 6 — FINAL confirmation before REAL execution (a separate, explicit step)

This is the most important safeguard in the whole skill. Before anything from PHASE 7
is launched, clearly, explicitly tell the user ALL of the following and wait for
EXPLICIT assent (not a silent continuation):

1. "I am now going to execute a REAL transaction on [ETH/ETC] MAINNET, with real funds."
2. "Target: [address]. Recovery wallet: [address]. Expected amount: [amount]."
3. "This is IRREVERSIBLE. Do you explicitly confirm that I should proceed?"

If the user does not answer with an unambiguous YES — **STOP**. Never interpret
silence or a previous general permission (PHASE 0) as sufficient for THAT specific
real execution — PHASE 0 is authorization for TESTING, PHASE 6 is a separate
confirmation for a REAL TRANSACTION.

## PHASE 7 — Real execution (only after PHASE 6)

Switch the RPC override to the REAL node from PHASE 1 (not the fork):

```
terminal(command="cd onchain_scripts && python3 -c \"from chains import set_rpc_override; set_rpc_override('<eth|etc>', '<REAL_URL_FROM_PHASE_1>')\"")
```

Run the **identical** `auto_pipeline.py` command as in PHASE 3, only with the user's
**real** key (the user supplies it freshly, now — see "Key security" below), not the
test one:

```
terminal(command="cd onchain_scripts && python3 auto_pipeline.py --target <TARGET_ADDRESS> --recovery-wallet <RECOVERY_WALLET> --key <PATH_TO_REAL_KEY> --chain <eth|etc> --confirm-mainnet --fund-eth <AMOUNT> --fuzz-seconds 300 --detectors all", timeout=400)
```

## PHASE 8 — FINAL verification: did the coin ACTUALLY arrive (real node)

**This is proof, not "the script ran without error".**

```
terminal(command="cast balance <RECOVERY_WALLET> --rpc-url <REAL_URL_FROM_PHASE_1>")
```

Compare with the state BEFORE PHASE 7 (record it BEFORE launching PHASE 7, not only
now). Tell the user the exact difference in ETH/tokens. Only THAT comparison counts as
proof of success — not the "ONCHAIN EXECUTION COMPLETE & SUCCESSFUL" output from
`forge script`, which only means "the transaction did not revert", not "the money
arrived where it should".

## PHASE 8a — If NO vulnerability was found: a formal "negative" claim

**This is as important as PHASE 8 and must NEVER be omitted.** A single fuzzer run
that finds nothing is NOT by itself enough for the claim "the contract is safe" — not
for ForkSploit, not for any other fuzz/security tool in the world (absence of evidence
is not evidence of absence). That is why `auto_pipeline.py`/`batch_pipeline.py` now
automatically compute a formal **bounded** claim instead of a bare silence, every time
`work_dir/vulnerabilities/*.plan.json` stays empty AND `vuln_info.jsonl` has not even
one (not even `sim-review`) finding (`determine_negative_result_verdict()` in
`auto_pipeline.py`, added 2026-11-02 as a direct response to the demand for a
"provable tool with a guarantee", not demonstration code):

- **`VERDICT: NO VULNERABILITY FOUND (bounded)`** — issued ONLY if ALL three
  conditions are met: ≥80% instruction coverage (the minimum across ALL contracts in
  `coverage.txt`, not the average), ≥300s of actual fuzz time (really elapsed, not
  requested), and `--detectors all` (not a narrower set). The client report must
  always state the exact coverage %, time and chain — NEVER just "safe".
- **`VERDICT: INSUFFICIENT COVERAGE`** — issued if ANY of the three conditions is not
  met. This means "we do not know", NOT "safe". The client report must say this
  clearly and recommend a longer run/`--detectors all` before anything about the
  absence of vulnerabilities may be issued.
- If AT LEAST ONE `(sim-review)` finding was found (even without a `.plan.json`), this
  formal claim is NOT issued — `report_unexecuted_findings()` already covers that case
  ("found something real, but not automatically exploitable"), and issuing "NO
  VULNERABILITY FOUND" as well would directly contradict it.
- **Rule for reporting to the client**: "no vulnerability" may be said ONLY together
  with the exact scope (% coverage, time, detector version) — never as a bare,
  unqualified "safe". The same holds in the opposite direction as the `(sim-confirmed)`
  renaming (PHASE 4 above): the word "CONFIRMED"/"safe" without an exact scope is
  exactly what this company must never utter.

## PHASE 9 — Cleanup and writing to the growing library

1. **Always, regardless of success**: clear the RPC override, so the next session does
   not accidentally point at the real node by default:
   ```
   terminal(command="cd onchain_scripts && python3 -c \"from chains import clear_rpc_override; clear_rpc_override('<eth|etc>')\"")
   ```
   Stop the anvil fork (`kill %1` or by PID).
2. **Only if PHASE 8 confirmed success**: add an entry to
   `references/confirmed-techniques.md` (see this skill's `references/` directory) —
   date, chain, contract address, `bug_type`, a brief summary, what actually worked.
   This is a "growing library", NOT "the model learned" — it is a real, readable
   record that the next session can read as a reference, not a change to the model
   itself.

## Key security (an immutable rule)

- Private keys NEVER go into this skill, into code, into persistent storage, or into
  any record that outlives this session. The user supplies them freshly, at every
  actual needed step (PHASE 3: a test key, PHASE 7: the real key).
- The test key (PHASE 3, fork) and the real key (PHASE 7, real node) are ALWAYS
  different. Never use the real key on a fork "because it does not matter" — habit
  kills discipline.

## Pitfalls

- **ETH and ETC mainnet are one character apart.** `require_mainnet_confirmation` in
  `onchain_scripts/chains.py` treats both the same (both require `--confirm-mainnet`)
  — it does NOT distinguish a typo between them. The only protection is PHASE 1
  (check `eth_chainId` directly, do not trust the name alone).
- The `--confirm-mainnet` flag is used EVEN on a fork (see the note in PHASE 3) — this
  is not a bug, it is a consequence of `chains.py` not distinguishing a fork from a
  real chain by chain-id.
- If `auto_pipeline.py` reports "Found vulnerabilities" that does NOT automatically
  mean the money was actually transferred — always verify PHASE 5/8 directly.
- Review-tier findings (the `(sim-review)` label) have NO generated exploit script by
  design — this is not a ForkSploit bug, see `src/evm/oracle.rs`'s
  `classify_confidence` in the repo for the exact reason for each case.
- `anvil --fork-url` on ETC (or another pre-Cancun chain) WITHOUT `--hardfork
  shanghai` throws `"Excess blob gas not set."` on EVERY `eth_call` — see PHASE 2.
- **Fixed 2026-11-02** (a previously valid trap, now closed for ETH): `execute_plan()`
  in `auto_pipeline.py` used to return `CONFIRMED` if no step reverted, EVEN if
  `AttackWallet balance after plan: 0 ETH` — i.e. a bug that succeeds without
  reverting but extracts no money (the fuzzer found only the primitive, not the most
  profitable variant). Now `execute_plan()` captures the real ETH state of the
  recovery wallet just before and just after that specific plan, and returns
  `CONFIRMED` ONLY if the balance actually rose — otherwise the new status
  `EXECUTED_NO_PROFIT`, which is NEVER reported as a proven attack. This does not
  replace PHASE 5/8 (those two still verify the WHOLE run on the real node, not just
  one plan, and are the only independent, human-performed checks), but it now means
  that the string `CONFIRMED` in the pipeline's own output actually means "money
  landed in the recovery wallet for THIS plan", not just "the steps did not revert".
  **Updated 2026-11-02 (same day, second step): it now covers ERC20 as well** —
  `plan.json` carries `stolen_asset` for raw ERC20 steps (see `erc20_token_touched` in
  `src/evm/solution/mod.rs`), and `execute_plan()` checks/sweeps each such token via
  `sweepToken()` after the plan, with the same before/after check on the recovery
  wallet. The example that first exposed this trap (2026-11-02): ForkSploit confirmed
  reentrancy in a `withdraw()`-style call at 38% coverage in 300s, but the real
  profitable path (in `claim()`, another function with the same vulnerability)
  required MANUAL reading of the verified source (Blockscout), not just trusting the
  automated run.
- **Verified source code on Blockscout is free and without an API key**:
  `https://etc.blockscout.com/api/v2/smart-contracts/<address>` (ETC) or the
  appropriate `<chain>.blockscout.com` for other supported chains — it returns
  `is_verified`, `source_code`, `abi`, `constructor_args` in JSON, if the contract is
  verified. For a real, already-deployed mainnet target this is ALWAYS the first step
  before reading raw bytecode or relying exclusively on ForkSploit's heuristics — the
  real source distinguishes the actually vulnerable function from false-positive
  findings in libraries (e.g. gas-optimized assembly-based math libraries trigger
  "Integer Overflow (sim-review)" on raw SUB opcodes that are NOT real bugs).
- **WETH9's `withdraw()` has a hard-coded 2300 gas limit on the return send — caught
  only by a live test on an Anvil fork, not by static code reading** (2026-11-02):
  when `AttackWallet` inside `executeOperation()` called `WETH.withdraw(amount)` to
  unwrap borrowed WETH into raw ETH (the flashloan funding path), WETH9 internally
  used `msg.sender.transfer(wad)` — Solidity's classic pattern with a hard-coded 2300
  gas stipend for the call into `receive()`. `AttackWallet.receive()` reads
  `pendingCallbackTarget` (a cold SLOAD, ~2100 gas under EIP-2929) before deciding
  whether to do anything — that ALONE almost exhausts the entire 2300 gas budget, and
  the transaction reliably (not occasionally) failed with `OutOfGas` inside
  `receive()`. Verified with `cast run <tx_hash> -vvvv` on a real Anvil fork of ETH
  mainnet — without that tool the root cause would be almost impossible to find from
  the "AttackWallet: flashLoanSimple failed" message at the top of the trace, which
  masks the true cause. Fix: `executeOperation()` now warms that storage slot at its
  start via `emit SlotWarmed(pendingCallbackTarget)` (NOT a bare read — the `--via-ir`
  optimizer could remove that as "without effect"). Live re-verified after the fix:
  the whole cycle (borrow→unwrap→step→wrap→repay) succeeded, the states match to the
  last wei. Lesson: this trap is INVISIBLE to `cargo build`/`solc` (both succeed
  without a warning) and to static code review — only actual execution on a fork
  reveals it.
- **MEV protection for the flashloan path + a real bug in `sign_step()`, caught only
  by an actual call** (2026-11-02): `armFlashloanActions` by itself reveals the WHOLE
  list of steps (target, calldata, value) as a separate, publicly visible transaction
  BEFORE `startFlashLoan` — without protection that would give a mempool bot enough
  time to exploit the same bug first (worse than for other plan types, because arm and
  start are SEPARATE transactions, not one). Now both together, atomically, via a
  Flashbots bundle (the same `use_bundle` decision as for other plans). During the
  first actual `sign_step()` call for these two transactions, a bug appeared that had
  already existed for EVERY bundle (apparently no one had actually driven it yet):
  `tx = {..., **fee_fields}` leaves an `is_legacy` key in the dictionary, which
  `eth_account.sign_transaction` rejects (`"Transaction had invalid fields:
  {'is_legacy': False}"`). Fixed with the same dispatch as
  `gas_utils.build_precise_tx` (legacy → `gasPrice`, otherwise
  `maxFeePerGas`/`maxPriorityFeePerGas`/`type=2`, NEVER `is_legacy` itself). After the
  fix: both transactions are correctly pre-signed.
- **A SECOND, more serious bug, caught and FIXED the same day — the earlier assumption
  "datacenter-IP block" was WRONG**: the actual submission to `relay.flashbots.net`
  returned `403` + `{"code":-32025,"message":"invalid flashbots signature"}` — not a
  network block, the actual signature was INVALID. `sign_request()` in
  `flashbots_bundle.py` was missing the `0x` prefix on the SIGNATURE itself in the
  `X-Flashbots-Signature` header (the hash digest was correct). The official Python
  example on docs.flashbots.net has the SAME bug (`signature.hex()` without `0x`,
  because `hexbytes>=2` does not add the prefix automatically) — the Go example in the
  same documentation always adds it via `hexutil.Encode`. Systematically tested all 4
  `0x` combinations on (hash, signature) directly against the REAL production relay:
  only (hash=0x+hex, signature=0x+hex) produced a clean shift from "invalid flashbots
  signature" to the normal `{"code":-32003,"message":"insufficient funds..."}` — proof
  that the relay accepts the signature and actually simulates the transaction. Fixed in
  `sign_request()`. **Lesson**: do not trust official documentation literally in all
  languages at once — the Python and Go examples on the same page contradicted each
  other, and only a live test against the real relay (not just "matches the reference
  implementation") revealed which is actually correct.
- **Changing a shared function's signature broke ANOTHER, separate script — caught
  only when the user asked about `dex_arbitrage_scanner.py`** (2026-11-02): when
  `AttackWallet.sol`'s `armFlashloanActions` gained a third parameter (`values`) for
  the flashloan funding path in `auto_pipeline.py`, `dex_arbitrage_scanner.py` — which
  INDEPENDENTLY calls the same function for cross-DEX arbitrage, built BEFORE this
  fix — was left at the old 2-argument form
  (`selector("armFlashloanActions(address[],bytes[])")`). That selector no longer
  exists after the contract change, so every `--execute` run would reliably fail.
  **Lesson**: changing the signature of a shared/common function (`AttackWallet.sol`,
  called from SEVERAL independent `onchain_scripts/*.py` files) requires `grep -rn
  "<function_name>" onchain_scripts/` BEFORE, not after, the change — a simple
  `cargo build`/`solc` test does not cover Python callers at all. On this occasion
  `dex_arbitrage_scanner.py`'s `--execute` path also got Flashbots bundle MEV
  protection for the first time (previously it sent `armFlashloanActions`/
  `startFlashLoan` as two separate public transactions — a worse risk than for exploit
  plans, because arbitrage runs in a loop, ALWAYS competing with other bots, regardless
  of the value threshold). Live-verified: the profitability calculation against the
  real Uniswap V2/SushiSwap V2 WETH/USDC pools on a fork (it correctly reports "not
  profitable" — the real market is efficiently arbitraged), and
  `execute_arbitrage()`'s bundle path against the REAL `relay.flashbots.net` (it
  reaches the normal "insufficient funds", not a signature error).
- **The relationship between `dex_arbitrage_scanner.py` and the Rust TWAP/price
  oracles (`src/evm/oracles/twap_manipulation.rs`, `v2_pair.rs`) — important, but
  DELIBERATELY without a technical safeguard** (2026-11-02, at the user's explicit
  request): this Python script NEVER calls the Rust oracles — they are two entirely
  separate systems (the Rust oracles run only inside a `forksploit evm` fuzzing run,
  through `src/feedback.rs`'s `OracleFeedback`). But the PHYSICAL primitive is
  IDENTICAL: `TwapManipulationOracle` detects a reserve-ratio shift >2x within ONE
  transaction; `build_arbitrage_steps()`'s transfer+swap on the named pool, with an
  arbitrarily chosen `x`, atomically wrapped in a flashloan, is EXACTLY that
  primitive. The only difference between "legitimate arbitrage" and "an oracle attack"
  is the INTENT of choosing `x` — the optimizer chooses it to close a real gap
  (self-limiting, a small `x` on an efficient market), an attacker would choose it
  deliberately large. `max_x = min(ra_a, ra_b) // 2` is the only size constraint — it
  is NOT a "stay below X% price impact" safeguard. **The user explicitly requested that

  this remain purely a human judgement, WITHOUT an automatic technical block** — do
  not add one yourself in a future session, unless the user explicitly changes this.
- **Added the same day**: "human judgement" without actually showing the number is not
  judgement, only hope. Added: `price_impact_pct()` (the same metric as above) is now
  printed in the log on EVERY review (even a self-warning one) for BOTH pools, and
  `--execute` ALWAYS stops and asks the human for the exact word "YES" (see
  `ask_human_confirmation()` in `dex_arbitrage_scanner.py`) before sending anything —
  with no flag to disable it. Any other answer (an error, an empty input, EOF) is a
  refusal; there is no default-approve path anywhere. Verified with all 4 cases
  (YES/wrong/empty/EOF) and with the formula on a deliberately large (-75%) and small
  (-0.02%) case, so that the metric is actually meaningful, not just present.
- **Two real bugs in `onchain_scripts/dashboard_server.py` (new, local web
  dashboard), caught only by an actual e2e test** (2026-11-02): (1) Python's
  `input("prompt")` NEVER writes a trailing `\n` (it waits for a human on the same
  line) — a line-based read of subprocess stdout (`for line in stdout`) never sees
  that prompt as a line, until some OTHER `\n` appears later that joins both — fixed
  by reading character by character and releasing as soon as a known string appears in
  the buffer. (2) When the subprocess's `stdout` is a pipe (always, when Python runs it
  as a subprocess, never a terminal), Python by default switches `print()`/`tee.log()`
  to BLOCK (not line) buffering of the output — lines silently sit in an internal
  buffer for an arbitrary time. Fixed with the `-u` flag on `subprocess.Popen([sys.executable,
  "-u", ...])`. Both bugs would be INVISIBLE without actually driving the whole chain
  (subprocess → prompt detection → write to stdin → real answer) — static code reading
  or `py_compile` would not catch them.

## Verification checklist

- [ ] PHASE 0: address, authorization, recovery wallet all explicitly confirmed
- [ ] PHASE 1: `eth_chainId` matches the expected chain, the block is progressing
- [ ] PHASE 2: the fork returns the target's real code
- [ ] PHASE 3-5: finding + balance on the fork ACTUALLY verified, not just assumed
- [ ] PHASE 4a: for "pooled"/staking contracts, ownership of funds ACTUALLY verified
      on-chain (not assumed from the user's statement)
- [ ] PHASE 6: an explicit, unambiguous user confirmation for REAL execution exists
- [ ] PHASE 7-8: the recovery wallet balance on the REAL node compared before/after
- [ ] PHASE 9: RPC override cleared, anvil stopped, (if success) an entry written

## Reference files in this skill

- `references/capabilities.md` — a **COMPLETE lexicon** of all CLI flags, all ~37
  oracles (with confidence tier), all `onchain_scripts/` tools, security mechanisms
  and known limitations. Check HERE first for any factual question about the system.
- `references/commands.md` — a collection of exact commands for quick lookup during
  work.
- `references/confirmed-techniques.md` — a growing log of actually confirmed successes
  (see PHASE 9).
- `references/new-oracle-roadmap.md` — an **OPEN PLAN (2026-11-02), to continue next
  session**: ~15 concrete, well-founded candidates for new oracle types (read-only
  reentrancy, ERC721/1155 hook reentrancy, weak randomness, DoS via revert in a loop,
  arbitrary storage write, hardcoded gas stipend, and more), prioritised. The user
  said they would research the candidates further themselves — coordinate BEFORE
  coding, do not assume this list is final.

## Dashboard: live-verified network identity (2026-11-02)

`dashboard_server.py`'s `GET /api/verify-chain` NEVER trusts the name from the
`--chain` dropdown — it calls the real, currently configured RPC (`chains.make_w3`,
honouring an active `rpc_overrides.json`) and compares the actual `eth_chainId`
against `chains.CHAIN_IDS` (carried over from `src/evm/onchain/endpoints.rs`'s
authoritative table, not guessed). The watermark (a purple ETH diamond / green ETC
diamond) and the colour badge in the GUI switch exclusively based on THAT live result,
never on the text in the dropdown. Live-verified during the build against the user's
real local nodes: `rpc_overrides.json`'s `eth` pointed at a dead RPC (port 8545,
connection refused) — the dashboard correctly showed this as a red "RPC unreachable"
warning, NOT as a silent wrong ETH label. The `etc` override (port 8555, an Anvil fork
of the user's real local ETC mainnet node on port 8546 — confirmed by the user)
correctly returned chain ID 61 and a green ETC label. This is actual proof of the
concept "eth and etc are one character apart, never trust the name" — the same guiding
principle as `chain_banner()`/PHASE 1 above, now also in the GUI, not just the CLI.

## Dashboard Phase 2 done (2026-11-02)

All 5 Python `onchain_scripts/*.py` scripts with `build_parser()` (also added
`monitor.py`, `batch_pipeline.py`, `aave_flashloan_runner.py`, the same pattern as
`auto_pipeline.py`/`dex_arbitrage_scanner.py` earlier), PLUS a direct Rust fuzzer
launch (`RUST_FUZZER_FIELDS` — a MANUALLY maintained schema, because the Rust clap
parser is not introspectable from Python like `argparse`; this is the ONLY place in
the dashboard where the form is not automatically synchronized with the real CLI — if
the Rust `evm` flags change, this must be updated by hand), PLUS
`POST /api/rpc-override`/`DELETE /api/rpc-override/{chain}` (a thin wrapper around
`chains.set_rpc_override`/`clear_rpc_override`) and `POST /api/wallet-policy` (a thin
wrapper around `wallet_policy.register_policy`, the same anti-typo `--confirm-chain`
double confirmation — verified that a wrong confirmation writes NOTHING). Important
for the next session: **changes to `dashboard_server.py` (Python) require a process
restart**, not just a browser refresh — unlike `dashboard_static/*` (CSS/JS/HTML),
which are read fresh from disk on every request.

## Business model: recovery_wallet = the owner of the tested contract (2026-11-02)

An important clarification from the user: `recovery_wallet` is NOT a fixed ForkSploit
wallet — it is **always the wallet of the owner/client whose contract you are
currently testing**. A successfully exploited vulnerability drains funds DIRECTLY to
the client's address — that IS a deterministic proof of vulnerability (see the earlier
part of this session on "the only reliable path"). Because the recovery wallet changes
PER CLIENT/ENGAGEMENT, `wallet_policy.register_policy()` now accepts an optional
`client_note` (CLI: `--client-note`, dashboard: a "Client / note" field in the
wallet-policy panel) — purely informational, NEVER read by `enforce_wallet_policy()`
or any signing path, just so it is clear at a glance FOR WHOM the current recovery
wallet on a given chain is locked, not just a bare hex address. Existing entries
(e.g. `etc` in `wallets.json`) do not yet have a back-filled note — leave that to the
user, who knows the real context; do not guess it yourself.

**Separately, an important discovery the same day**: the AttackWallet address recorded
for `etc` in `attack_wallets.json` (`0x5FbDB2315678afecb367f032d93F642f64180aa3`) is a
**well-known Anvil/Hardhat default address** ("the first contract deployed from the
default dev account at nonce 0") — which means it is a leftover from LOCAL fork
testing, NOT a real contract on the real ETC mainnet. That is why it shows a balance of
0 and why the query earlier threw "missing trie node". Lesson for the next session:
`attack_wallets.json` entries are not automatically "real" just because they exist —
check the address pattern/origin before trusting it, the same discipline as for
everything else in this project.



## General finding: the control leak can exclude ALL findings in a transaction, wherever they occur (2026-11-03)

While testing `forced_eth_accounting.rs`, the finding was NEVER reported, even though
the detection logic in `host.rs` unambiguously worked correctly (verified with a
temporary debug print: thousands of correct hits). The cause was not in the oracle —
it is in `feedback.rs`'s `is_interesting()`:

```rust
if metadata.known_bugs.contains(&bug_idx) || has_post_exec {
    continue;
}
```

`has_post_exec` says whether this WHOLE transaction (as a whole, not just the part
where the bug was detected) ended with an UNRESOLVED "control leak" continuation (see
`host.rs`'s `call_allow_control_leak`/`CALL_UNTIL`). If yes, ALL bug_idxs from that
transaction are excluded from reporting — even if the bug was detected EARLIER,
completely independently of the call that caused the leak.

The test fixture had `require(EQ check); ... payable(x).transfer(amount);` — the EQ
(the bug) happens FIRST, the `.transfer()` (which causes the leak) comes LATER, but it
STILL excluded the report for the EQ. **Every outgoing value-transferring call is
exactly the shape that the fuzzer's own exploration mechanism tries most aggressively
to intercept** (to explore reentrancy scenarios) — so ANY oracle whose detection
happens in a FUNCTION that also sends ETH/value LATER in the same transaction rarely
or never reports, EVEN THOUGH the detection itself is correct.

**This is not a bug in an individual oracle — it is an architectural property worth
being aware of for EVERY new oracle and when interpreting "0 findings" on real
contracts that have functions with outgoing ETH transfers.** Test fixtures for such
patterns must be without an outgoing value-transferring call (see the test note in
`forced_eth_accounting.rs`) to prove the pattern without that unrelated noise.

## A serious Rust-side bug: 5 oracles misattributed bugs to unrelated calls (2026-11-02)

On a real ETC mainnet contract (`0x9f5304DA62A5408416Ea58A17a92611019bD5ce3`, plan
`C9f53_5`) an `[Unchecked ecrecover(0)] (sim-confirmed)` finding was attributed to the
call `0x64dab283()` — but independently verified with `cast disassemble` AND with
`debug_traceCall` on a local anvil fork: that call is a plain `address` getter (0
CALL-type opcodes, pc reaches at most 1314), which NEVER calls `ecrecover`. The
described `pc=1927` was in a WHOLE OTHER function (`0xe3ce9714`, the real
"claim with signature" call with 5 arguments) — verified with the same
`debug_traceCall`: that one DOES call the `ecrecover` precompile (a `CALL` to `0x1`)
at exactly pc=1927.

**Root cause** (verified in the Rust code, `src/evm/vm.rs`): detectors like
`ecrecover_zero`, `integer_overflow`, `delegatecall_injections`, `storage_collisions`,
`arbitrary_calls` are UNIONED (`old.chain(current)`) forward through the WHOLE corpus
genealogy, NEVER cleared. The oracle (`ctx.post_state.X.iter()`) iterated that WHOLE
accumulated set, not only the NEW entries from THAT transaction — so a bug once found
on one address/pc "stayed attached" to EVERY later, unrelated transaction built on the
same corpus branch, even if that transaction never reached that code. The minimizer
(`src/evm/minimizer.rs`) could therefore "minimize" the trace to a single, completely
unrelated transaction, and `objective.reproduces()` still returned `true`, because the
minimization's initial state already inherited the old flag.

**Affected oracles** (all have an IDENTICAL pattern, verified with a grep over the
whole `src/evm/oracles/`): `ecrecover.rs`, `overflow.rs`, `delegatecall.rs`,
`storage_collision.rs`, `arb_call.rs` — of these the Confirmed-tier ones (which
therefore automatically generate `*Exploit.s.sol`) are: Unchecked ecrecover(0),
Delegatecall Injection, Storage Collision, Arbitrary Call.

**Fix**: each of these five `oracle()`s now filters on
`ctx.post_state.X.difference(ctx.pre_state.X)` — `OracleCtx` already has a separate
`pre_state`/`post_state` (documented in `src/oracle.rs` as "state before/after the
execution of THIS transaction"), so this is exactly the right place for the fix,
without affecting real multi-tx logic (the step that ACTUALLY first triggers the bug is
still correctly caught at ITS OWN `oracle()` call, because then `pre_state` does not
yet contain it).

**Live-verified** (a local anvil fork, no risk, 2x `debug_traceCall` as independent
proof before and after the fix): before the fix the bug was misattributed to
`0x64dab283()`; after the fix (rebuild + a re-run on the same target) it was correctly
attributed to `0xe3ce9714(...)`, independently confirmed with `debug_traceCall` (a CALL
to the `0x1` precompile at exactly that pc).

**Why this matters for the business model**: this is not "found a primitive, no
profit" (as was thought for `C9f53_5` earlier) — this was a case where ForkSploit
CLAIMED that a certain call behaves in a certain way, which was NOT TRUE even in the
simulation. Without this fix, `auto_pipeline.py` could generate and (if gas/profit
conditions matched) even SIGN a transaction for an exploit that does not exist at the
described address/pc.

## Two further layers of the same problem, found the same day (2026-11-02)

After the fix above, a REAL mainnet run (same target, 7 plans, all 7 actually signed
and sent) showed that the fix above was NOT sufficient — `Unchecked ecrecover(0)` was
still attributed to unrelated selectors (`02ef6c86`, `f3fef3a3`), independently
refuted with `debug_traceCall` (max reached pc 2050, the claimed pc 2214 never
reached). Two separate, deeper layers:

**Layer 2 — `host.current_*` was never reset between transactions** (`src/evm/vm.rs`):
`current_arbitrary_calls` was correctly reset at three places before every transaction,
but `current_ecrecover_zero`/`current_integer_overflow`/`current_delegatecall_injections`/
`current_storage_collisions` NEVER were — they grew over the ENTIRE lifetime of the
fuzz process (not just within one transaction). So the layer-1 fix (comparing
`pre_state`/`post_state` in the oracle) only helped partially: `current_X` was already
"dirty" from an UNRELATED exploration branch, before `pre_state` for the NEW branch was
even built. Fixed: added a reset of all four missing `current_*` HashSets at all three
places (`init_host!` macro + 2 manual blocks) where `current_arbitrary_calls` is already
reset.

**Layer 3 — a "control leak" simulation without verification against the real chain**
(`src/evm/host.rs`'s `call_allow_control_leak`, `src/evm/solution/mod.rs`): during
exploration the fuzzer can INTERCEPT a call (after a `call_leak` call count) and,
instead of the real execution, INJECT its own, invented return value, then continue
with a separate continuation that is NOWHERE SERIALIZED. A trace found this way can
"prove" an oracle in simulation with a value the REAL chain will NEVER return.
AttackWallet has no way to replicate "falsely return X for this call" — only
Reentrancy's `armCallback` (a REAL repeated call, not a faked return value) is a
reliable atomic primitive. Fixed: `Tx` (and the `SolutionTx` trait, `ConciseEVMInput`)
now carries `call_leak: u32` through to the generator; `trace_depends_on_control_leak()`
in `solution/mod.rs` ABANDONS generation of an atomic `.plan.json`/`.s.sol` for such a
case (only `.t.sol` remains, with a clear debug message why) — the same pattern as the
existing `has_multiple_distinct_callers` skip. It does NOT apply to the Reentrancy path
(that remains reliable, because `armCallback` injects nothing false).

**An important, honest limitation found here**: ForkSploit's oracles recognize only
~37 pre-coded bytecode patterns. "0 Confirmed bugs" on a given contract does NOT mean
"the contract is safe" — it means only that none of THESE SPECIFIC patterns matched
within the given fuzz window/coverage. Business logic, economic/price exploits,
admin-key risks and systemic errors between multiple contracts are not and cannot be
covered by purely bytecode-level pattern recognition — that is the limit of this
category of tool, not a bug in ForkSploit. See PHASE 8a above for the formal "bounded"
claim that delimits this.

## Layer 4 — 4 more overlooked instances of the same bug, found systematically (2026-11-03)

Before starting work on new oracles, a systematic review was made of ALL
`.chain(self.host.current_X...)` calls in `src/evm/vm.rs` (11 in total), not only the
4-5 that the previous day's concrete finding on ETC mainnet had shown. Result: only 3
of 11 (`self_destructs`, `arbitrary_calls`, `typed_bug`) were correctly reset; 4 were
fixed the previous day (`integer_overflow`, `delegatecall_injections`, `ecrecover_zero`,
`storage_collisions`); **4 were overlooked, because the previous day's grep did not
catch those field names**: `current_uninitialized_memory_reads`, `current_unchecked_call`,
`current_tx_origin_checks`, `current_delegatecall_targets_seen`. Fixed the same way as
the previous day: a reset at all three places in `vm.rs` + a `pre_state`/`post_state`
comparison in `uninitialized_memory.rs`, `unchecked_call.rs`, `tx_origin.rs`,
`delegatecall_target.rs`. Note: `calldata_addresses`/`returndata_addresses`/
`paid_calldata_addresses` (which `delegatecall_target.rs` and `self_referral.rs` also
read) are NOT affected — those two are SET (`=`) every transaction, not UNIONED
(`.chain()`), so they were correct from the start.

**Lesson for the future**: before adding a NEW oracle with a "current_X" accumulated
field, ALWAYS check with `grep -n "\.chain(self\.host\.current_" src/evm/vm.rs` whether
the number of matches equals the number of reset fields at ALL three places (the
`init_host!` macro + 2 manual blocks) — do not rely on the previous fix having been
exhaustive.

## Finding on real ETC mainnet: a simulation without gas metering can confirm an infeasible trace (2026-11-02)

While executing a real, not-yet-tested plan `C9f53_2` against the real ETC mainnet
contract `0x9f5304DA62A5408416Ea58A17a92611019bD5ce3`, `execute_plan()` failed with
`Web3RPCError: {'code': -32000, 'message': 'exceeds block gas limit'}`. Directly
verified with `eth_estimateGas`/`eth_getBlock('latest')`: the estimated gas for that
call was ~50 million, while the real ETC `block.gasLimit` is exactly 8,000,000. Root
cause: the Rust fuzzer simulates on `revm`, which (see `CLAUDE.md`) **has no gas
metering** — so it can "confirm" a trace that is valid in the idealized unbounded
simulation, but on the real chain you can physically never submit it in one block. The
error had previously appeared only as a raw RPC rejection AFTER signing the transaction.

**Fix**: `gas_utils.estimate_gas_limit()` now, BEFORE returning, compares the estimate
against the real, freshly read `w3.eth.get_block('latest')['gasLimit']` and raises
`GasExceedsBlockLimitError` if the estimate exceeds the block limit — this is the only
place where this is checked, because ALL callers (`auto_pipeline.py`,
`aave_flashloan_runner.py`, `batch_pipeline.py`, `dex_arbitrage_scanner.py`) go through
`build_precise_tx`/`estimate_gas_limit`. `execute_plan()` in `auto_pipeline.py` now
catches this exception at the first gas estimate (previously outside any `try`/`except`
block — hence the uncaught exception) and returns a clean `PLAN_NOT_CONFIRMED` with a
readable message, likewise for the bundle path (`execute_flat_plan_via_flashloan`) and
the sequential path. **Live-verified on the real ETC mainnet chain after the fix and
merge into `main`** (re-running the same `C9f53_2` plan, same day): the gas estimate
49,610,942 against the real `block.gasLimit` 8,000,000 → a clean `NOT CONFIRMED: the
required gas exceeds the block limit`, `status=not_confirmed, recovery_delta_wei=0`,
WITHOUT any attempt to sign/send a transaction (the plan had `total_value=0`, so the
funding step was not reached before the gas check either). It confirms two things: (1)
the fix works exactly as intended, and (2) this specific fuzzer finding is NOT really
exploitable on the real chain despite the `CONFIRMED`-looking simulation — exactly the
blind-spot case this fix catches.

## Finding: logs hard-printed "ETH" even on ETC/BSC/Polygon/... (2026-11-02)

When reading a real ETC-mainnet output, the user asked "why does it mix ETH with ETC?"
— rightly so: `auto_pipeline.py`, `batch_pipeline.py`, `aave_flashloan_runner.py` and
`gas_utils.describe_actual_cost()` all had a hard-coded `" ETH"` suffix for every
`w3.from_wei(..., 'ether')`, REGARDLESS of which chain was actually running — so even
a real ETC-mainnet run printed amounts as "ETH", not "ETC" (the same would hold for
BSC → BNB, Polygon → POL, Avalanche → AVAX, Gnosis → xDAI on paths that actually
support these chains, e.g. `aave_flashloan_runner.py`).

**Fix**: `chains.py` gains `NATIVE_SYMBOL` (chain string → ticker) and
`native_symbol_for_w3(w3)`, which derives the symbol from the REAL, live-connected
`w3.eth.chain_id` (not from a possibly wrong `--chain` string — the same "never trust
the name alone" discipline as `chain_banner()`/`require_mainnet_confirmation()`, here
used for display instead of chain selection). All affected call sites now call
`native_symbol_for_w3(w3)` instead of a hard `"ETH"`. `dex_arbitrage_scanner.py` was
deliberately left out — it currently operates exclusively on `eth`
(`DEX_PAIRS_BY_CHAIN` has only the `"eth"` key), so `"ETH"` there is actually correct,
until the scanner is extended to other chains.

## `readonly_reentrancy.rs`: correct detection, but `has_post_exec` almost never lets it through — the root cause is NOT in `feedback.rs` (2026-11-03)

The new oracle `readonly_reentrancy.rs` (bug_idx 39, the SWC read-only reentrancy:
a `view` function returns an inconsistent intermediate state while a reentrancy window
is open) required an additional fix before it could even detect correctly:

**Fix 1 — `view_call_baseline` must be persistent.** The standard "`current_*`, clear
on every call" pattern (see Layers 2-4 above) turns out to be TOO aggressive for this
case too: the field was cleared also on the RESUMPTION of a control-leak continuation,
not only on a genuinely NEW top-level transaction. Consequence: `baseline_present=false`
exactly when the oracle needs it. Fix: `current_view_call_baseline` → renamed to the
persistent `view_call_baseline` (NEVER cleared at the 3 reset places), following the
same pattern as the existing `slot_write_contexts`. After the fix, debug
instrumentation confirmed `baseline_present=true` and correct `HIT INSERTED` events
(21562+ times in one run).

**Fix 2 was not possible — the second layer of the same `has_post_exec` problem, but
this time unsolvable by reshaping the test fixture.** In `forced_eth_accounting.rs`
(see the section above) it was possible to simply remove the unnecessary outgoing
`.transfer()` call from the test fixture, because the bug pattern did not need that
call at all. But in read-only reentrancy the control-leak call (the external call that
opens the reentrancy window) IS the bug's mechanism — it cannot be removed without
removing the very scenario the oracle checks.

At the user's explicit request ("Dig into `feedback.rs` and try to solve the
`has_post_exec` problem at a general level"), temporary debug instrumentation was added
to `feedback.rs`'s `is_interesting()` (removed before the commit), and a 20s run was
launched on `tests/evm/readonly_reentrancy/*`. Result:

```
120305 has_post_exec=false
 99444 has_post_exec=true
---per bug_idx, has_post_exec=false count---
2579933380265121289   <- only classic Reentrancy, NOTHING else
```

Of **120,305** fully resolved transactions in the whole run, only ONE bug_idx (classic
`Reentrancy`) ever reached `has_post_exec=false`. The two `readonly_reentrancy` bug_idxs
(`4330118404053422103`, `10675110855689788199`) did not appear even once among
~220,000 total checks — despite the host-level detection being proven correct and
firing thousands of times.

**Conclusion: `feedback.rs`'s `has_post_exec` gate is NOT a bug — it works exactly as
designed.** Classic reentrancy proves that the fuzzer OCCASIONALLY FINDS a fully
resolved path for a control-leak-dependent bug — so the mechanism itself works. The
real obstacle is in WHICH continuations the fuzzer's mutation/selection strategy
(`src/evm/mutator.rs`, `src/fuzzers/evm_fuzzer.rs`) even attempts during an open
control-leak window — "call back `getPrice()` DURING the window, then let the outer
sequence finish normally" is a much narrower, more specific goal than the classic
"transfer value back", so the current strategy rarely hits it.

**Consequence for ALL future control-leak-dependent oracles** (not just this one): a
low actual reporting rate on real contracts is not necessarily a sign of wrong
detection logic — it may be a sign that the fuzzer simply rarely attempts exactly the
right continuation. This is an architectural limitation of the mutation strategy, not
an oracle-specific bug, and a fix would have to target `mutator.rs`/`evm_fuzzer.rs`
(affecting ALL control-leak-dependent oracles at once, hence risky, a bigger job), not
`feedback.rs`. The user chose this deepening; it was not completed in this session due
to the session limit approaching — to be continued next session.

## `delegatecall_target.rs`: two real fixes, SUCCESSFULLY live-confirmed (2026-11-03)

At the user's request ("finish the fix above and this `delegatecall_target.rs` too"),
the hypothesis was first verified that
`current_calldata_addresses`/`current_returndata_addresses`/
`current_paid_calldata_addresses` suffer from the SAME cross-leak-resumption problem
as `view_call_baseline` (see the section above). Confirmed in the code:
`execute_abi`'s `is_step` loop (`vm.rs`) calls `execute_from_pc` with `cleanup=true`
already for the FIRST resuming segment, and the `post_exec` parameter is `Some(pe)`
exactly and ONLY for a resumption (never for a genuinely new transaction, which always
receives `None`) — this is an exact, reliable signal for distinguishing "a genuinely
new transaction" (needs a real reset, to prevent cross-transaction contamination, the
same reason as "Layers 1-4" above) from "a continuation of the same leak" (needs the
PRESERVED taint from before the leak).

**Fix (safer than "persistent forever")**: instead of NEVER resetting these three
fields (risk: address values coincide by chance much more often between unrelated
transactions than a narrowly-keyed `view_call_baseline`, which on a Confirmed-tier
oracle could trigger false positives), on `post_exec.is_some()` they are SEEDED from
the `vm_state` of the same lineage (which was correctly computed just before the leak
and is available as a parameter to `execute_from_pc`) instead of resetting to `empty`
— exact, without the risk of cross-lineage contamination, because it is the REAL,
already-correctly-computed state of this specific branch, not global persistent state
on the host object.

**A second, separate finding during live verification**: a purpose-built test fixture
was made (`tests/evm/delegatecall_target/main.sol`) that deliberately splits the
RETURNDATACOPY decoding of the target (a self-call to `getTarget()`, a derived value
from the stored `x`, to avoid any collision with the calldata/byte-coincidence signal)
and the vulnerable DELEGATECALL across a control-leak boundary (`Someone(x).something()`).
Debug instrumentation showed that `delegatecall_targets_seen`'s pre/post diff CORRECTLY
detects a new hit (tens of thousands of cases `pre=0 post=1 equal=false`), but the
`calldata.len() < 20` check ALWAYS returned `vec![]` too early for SUCH a segment —
root cause: `set_as_post_exec()` (`src/evm/input.rs`) on a "step" mutation OVERWRITES
`input.data` with a synthetic placeholder (representing the injected return value of
the leak callback), so `ctx.input.to_bytes()` for a resuming segment returns only 4
bytes (a bare selector), NEVER the real arguments of the original transaction —
verified live.

**This check was wrongly placed as a blanket early-return for the WHOLE function**,
although it is really relevant ONLY for the weaker "byte coincidence" fallback — the
Confirmed-tier `via_calldata_taint`/`via_returndata_taint` do not use `calldata` at all;
they rely exclusively on the (now correctly persistent)
`calldata_addresses`/`returndata_addresses`. Fix: the `calldata.len() < 20` check was
moved from the early `return` into the `via_byte_coincidence` computation inside the
loop — Confirmed-tier signals now run independently of the `calldata` length, and the
fallback simply does not apply when `calldata` is too short (the same practical
behaviour as before, but correctly limited to only the signal that actually depends on
it).

**Live-confirmed after both fixes**: on the new fixture the fuzzer, in 15s, reported
exactly ONE `[Delegatecall Target From Calldata] (sim-confirmed)` hit, correctly
described as "read back from a PRIOR call's return data within this same transaction"
— and generated `Delegatecall_target_0.t.sol` in `work_dir/vulnerabilities/`. **This is
the FIRST case in this session where a control-leak-dependent oracle was SUCCESSFULLY
fixed and live-confirmed to the end** (unlike `readonly_reentrancy.rs` above, where the
obstacle remains in the fuzzer's mutation strategy) — the difference: here the obstacle
was in TWO concrete, localized code errors (state persistence + a wrong scope of the
length check), not in WHICH continuations the fuzzer even attempts.

## Strategy Layer: two-step chaining of findings, live-confirmed (2026-11-03)

The user identified a real gap: `auto_pipeline.py`/`batch_pipeline.py` execute every
`.plan.json` finding on the same target COMPLETELY INDEPENDENTLY, in the lexicographic
order of file names (not even numeric). Nowhere in the code did the concept "this
finding enables another" exist — if oracle A (e.g. `ecrecover.rs`) discovers a forged
signature that unlocks `authorized[caller]`, and oracle B (e.g. `erc20.rs`) separately
discovers `withdraw()`, which requires that flag, but the real fuzz run did NOT happen
to continue from A into B within one lineage — then this compound attack was NEVER
attempted on the real chain, even though BOTH halves were already independently
discovered.

**New module**: `onchain_scripts/strategy_layer.py`. Two separate improvements:

1. **`ordering_key()`** — replaces a bare `sorted(plan_files)` (lexicographic name)
   with a meaningful order: UNLOCK-type findings (signature forgery, auth bypass,
   delegatecall/storage hijack, ...) before OBJECTIVE-type ones (Fund Loss,
   unauthorized transfers, insolvency, ...), with NUMERIC (not lexicographic) sorting
   within the same class. The classification relies EXCLUSIVELY on the already
   existing, already reviewed bug_type taxonomy (`src/evm/oracle.rs`'s
   `classify_confidence`) — without any new semantic understanding of the code, just
   another axis over the same table.
2. **`run_chain_attempts()`** — after the existing independent run (which is NOT
   changed, zero regression risk) it attempts pairs (an UNLOCK finding A, an OBJECTIVE
   finding B on the SAME target) where B has not yet confirmed on its own. It builds a
   synthetic plan (`merge_plans()`: `A.steps + B.steps`, `kind:"flat"`) and sends it
   through the COMPLETELY EXISTING `execute_plan()` — without duplicating the
   gas-limit/mainnet-confirmation security logic.

**Deliberately NARROW scope of the first version** (documented, not silently omitted):
only `kind=="flat"` plans (a reentrancy-type one has a single `repeat_step` slot that
does not cover two separate findings); only pairs, not 3+ chains; only the same target;
funded (`needs_funding`) plans excluded; no transfer of a real on-chain return value as
an argument (only REPLAYING the steps in order — it covers "A changes state/permission
that B needs", not "B needs A's exact output byte as an argument").

**A technical detail**: `plan.json` itself has no `bug_type`/`confidence` field
(verified in `src/evm/solution/script_generator.rs`'s `ExploitPlan` struct) —
`strategy_layer.py` obtains it from the Description block of the same-named `.t.sol`
(`[bug_type] (confirmed): ...` lines, a regex tolerant of the `sim-` prefix), because
`generate_test()`/`generate_exploit_plan()` write it from the SAME `TemplateArgs` with
the same `contract_name`.

**Live-confirmed** on a local anvil fork with a purpose-built two-contract fixture that
exactly illustrates the user's case: `Vault.claim(v,r,s)` has an unchecked
`ecrecover(bytes32(0),...)` that, on `signer==address(0)`, sets
`authorized[msg.sender]=true`; a SEPARATE `Vault.withdraw()` requires that flag and
transfers the whole balance. Result:
- `withdraw()` ALONE (without `claim()`): `EXECUTED_NO_PROFIT`, 0 ETH (not
  `NOT_CONFIRMED` — `AttackWallet.execute()` does not undo the outer transaction when
  the inner call reverts, so this correctly shows as "executed, no profit", not as a
  failure of the transaction itself).
- `strategy_layer.merge_plans(claim, withdraw)`, sent through `execute_plan()`:
  **`CONFIRMED`**, the recovery wallet gains ~1 ETH (the exact amount minus gas, because
  in this test the signer was the same address as the recovery wallet — in real use,
  where they are separate, the amount would be exactly 1 ETH).

This is the first direct proof that chaining TWO separately discovered findings into
ONE real, executed compound exploit works — not just theoretically planned.

## A serious trust-worthy fix: oracles hard-printed "ETH" even on ETC/BSC/... (2026-11-03)

The user reported **real business damage**: a client, on an ETC review, saw the word
"ETH" in the name/description of a bug and concluded that ForkSploit does not
distinguish ETH (the pricier coin) from ETC (~500x cheaper) — a loss of trust, a lost
deal. This WAS real, but SEPARATE from the already-fixed Python-side
`native_symbol_for_w3()` fix (2026-11-02, see below) — THAT fix covered only
`onchain_scripts/*.py`, NOT the Rust fuzzer binary itself.

**Found** (verified with a grep over `src/evm/oracles/*.rs`): `eth_backing.rs`,
`forced_eth_accounting.rs`, `curve_virtual_price.rs`, `twap_manipulation.rs`,
`erc20.rs`, `unchecked_call.rs` had the word "ETH" hard-written in the `bug_type` name
and/or the `bug_info` description, REGARDLESS of the real chain. These strings go
directly into `.t.sol`, `vuln_info.jsonl` and the dashboard — so the client actually
sees them.

**Why it was not possible to dynamically insert the CORRECT ticker** (e.g. "ETC"
instead of a generic one): verified in the code (`src/evm/oracle.rs`'s `EVMOracleCtx`)
that the active chain is NOT reliably reachable inside an `oracle()` call — the only
path is `chain_id` as a SIDE EFFECT of the `CHAINID` opcode (`onchain/mod.rs`'s
`OnChain::step`), which is `None` until the contract actually calls `CHAINID`. During
OFFCHAIN fuzzing (without `--onchain-*` flags) there is no real chain context at all.
The correct, only universally correct solution: **genericization** — "native value"/
"native-token balance" instead of any concrete ticker, which is correct for BOTH
onchain AND offchain fuzzing.

**Fix** (the bug_type STRINGS, which are a matching key, updated IN LOCKSTEP at all
places): `"Insolvent: Promised ETH Exceeds Real Balance"` → `"Insolvent: Promised
Native Value Exceeds Real Balance"` (3 places: `eth_backing.rs`, `oracle.rs`'s
`classify_confidence`, `solution/mod.rs`'s `CONFIRMED_EXPLOITABLE_BUG_TYPES`, PLUS
`onchain_scripts/strategy_layer.py`'s classification tables, because this same string
is used as the UNLOCK/OBJECTIVE classification key); `"Forced ETH Accounting"` →
`"Forced Native Value Accounting"` (no lockstep risk in Rust, but likewise updated in
`strategy_layer.py`). Free text (not a matching key) in the remaining 4 files was simply
renamed ("net ETH balance increase" → "net native-token balance increase", etc.).

**Live-confirmed** on the existing test fixtures (`tests/evm/eth_backing/*`,
`tests/evm/forced_eth_accounting/*`): the new strings are printed correctly
(`[Insolvent: Promised Native Value Exceeds Real Balance] (sim-confirmed)`,
`[Forced Native Value Accounting] (sim-review)`), and the confidence tier did NOT
change (the lockstep fix worked correctly).

## A serious gap found on a real client contract: a serious Confirmed finding, 0 plans generated — partly fixed, NOT final (2026-11-03)

The user reported serious business damage: on a client contract known as "90%
vulnerable", ForkSploit found serious bugs, but `AttackWallet` executed NOTHING — not
wrongly, but because **no plan was generated at all**. Live-verified on the user's real
ETC contract (`0x9f5304DA62A5408416Ea58A17a92611019bD5ce3`, the same as in earlier
findings this session): a 300s run, 90.90% instruction coverage, **4037 separate
findings, 0 `.plan.json` files**.

Among them: `[Fund Loss] (sim-confirmed)` — "Anyone can earn 1,277,262 native tokens"
(nearly the WHOLE contract balance), repeated 4x with a realistic (not
fuzzer-inflated) value. Trace: `Sender → target.call(0x1554611f) → Sender.fallback()
→ target.call(0x00000000)` — a classic control-leak/callback pattern.
`trace_depends_on_control_leak()` correctly rejected it (the security safeguard works),
BUT `solution/mod.rs` had previously used the callback-capable generator
(`armCallback`/`repeat_step`) ONLY if `bug_type` was literally "Reentrancy" — an
oracle-naming accident, not a real difference in what AttackWallet needs to do.

**Fix 1 (done, safe, committed)**: the `trace_depends_on_control_leak` branch now
attempts `split_reentrant_trace` for EVERY Confirmed finding, not only for
"Reentrancy" — the same mechanism, a wider trigger condition, without duplicating cases
the "Reentrancy" branch already handled.

**But this specific case is STILL not solved with THAT fix** — live re-verified on the
same contract after the fix: **still 0 plans**. The root cause, precisely:
`split_reentrant_trace()` requires the attacker to call the same (contract, selector)
pair TWICE (the classic "call the same function again" reentrancy pattern). This trace
has a DIFFERENT selector in the callback window (`0x00000000`) than the outer call
(`0x1554611f`) — it is not a repeat, it is a DIFFERENT call during the window.
`split_reentrant_trace` therefore correctly returns `None`, and the fix does not trigger.

**The real solution, deferred to the next session due to time pressure**: extend the
`armCallback`/`repeat_step` mechanism (or build a parallel one) so that AttackWallet can
replay a DIFFERENT, fuzzer-discovered call during the callback window (not just the same
call again) — this is a bigger, riskier job (it affects plan generation for ALL
control-leak-dependent Confirmed findings), which needs its own careful planning and
live verification before it is considered solved.

**An important guideline for the future** (the user's explicit request, see
[[feedback_literal_execution]] in memory): until this specific case on this specific
contract actually reaches a real movement of funds, it must NOT be counted or reported
as "solved". This section remains open until that is proven.

## A serious bug in the gas-limit check: "exceeds block limit" was FALSE (2026-11-03)

After the previous fix (control-leak routing) the user re-ran on the SAME real ETC
contract — this time 2 plans WERE generated (progress!), but BOTH failed with `NOT
CONFIRMED: the required gas (49610942) exceeds the real block gas limit (8000000)`.
The exact same number for TWO completely different, unrelated calls (`3e2640d6...` and
`c01c1ca3`) was suspicious.

**Verified directly against the real local ETC node** (`eth_call`, not just trusting
`eth_estimateGas`): with the EXACT real block limit (8,000,000 gas) BOTH calls
**succeed without reverting** — even a completely trivial call (empty calldata) through
AttackWallet returns the IDENTICAL "required" estimate 49,610,942. This definitively
proves: **the gas estimate was wrong, not the truth about infeasibility**. A known
EVM/geth phenomenon: `eth_estimateGas`'s binary search can return a completely wrong,
inflated number if the real gas usage is NON-MONOTONIC with respect to the available
gas (e.g. a `gasleft()`-dependent branch somewhere in the call chain) — binary search
then does not converge correctly.

**This was the SAME contract and the SAME kind of error as in the original fix of this
check (2026-11-02, plan C9f53_2)** — which means that EVEN that original "exceeds block
gas limit" case was possibly also a false negative, never verified with a real
`eth_call`.

**Fix** (`gas_utils.py`'s `estimate_gas_limit()`): before giving up, it now performs a
REAL check — an `eth_call` with exactly the real block limit as gas. If THAT does not
revert, the estimate is simply wrong, and the real `block_gas_limit` value is used
directly (without a margin, because that would exceed the cap again).
`GasExceedsBlockLimitError` now fires ONLY if even this direct probe reverts — i.e.
only when the trace is REALLY infeasible, not just "estimateGas returned a large number".

**Live-confirmed** (a direct Python call to `estimate_gas_limit()` against the real
local ETC node, with the EXACT calldata of both failed plans): both now return
`8000000` instead of raising an error. **The user will now re-run `auto_pipeline.py` on
the same contract** — only THAT run tells whether these two plans, after this fix,
actually move real funds. Until that is confirmed, this REMAINS open, the same as the
section above.

## Triage + materialization: 4664 plans -> 241 surfaces -> 21 real (2026-11-07)

The user ran the triage layer (`triage_findings.py`) on their real data: **4664 plans
collapsed to 241 surfaces**, of which 2 RUNNABLE, 19 NEEDS_MATERIALIZATION and 220
HEURISTIC_ONLY. From the aggregate of faked calls two things are immediately clear: (a)
all 19 materialization surfaces are on the SAME target
`0x9f5304DA62A5408416Ea58A17a92611019bD5ce3`, (b) the selectors `escapeHatch`,
`proxyWithdraw`, `withdraw`, `claimRemaining` and `extendClosingTime` dominate — so it
is ONE contract, not 19 bugs.

`materialize_plan.py` was added as the next step: it classifies each repeated call into
a class (`AUTH_GUARD`, `SIGNATURE`, `TOKEN_BALANCE`, `PRICE_ORACLE`,
`REENTRANCY_CALLBACK`, ...) and assigns it a recipe. A repeated call into ANOTHER
contract (not the target) is classified as `REENTRANCY_CALLBACK`, because that is a
callback shape, not a state read.

### Live-verified on a local anvil fork of ETC (NEVER on mainnet)

The target `0x9f53...5ce3` holds **1,277,262 ETC** (`getTotalFunds` 8.44M ETC). All 14
selectors from the dispatcher were resolved via 4byte: `escapeHatch()`,
`proxyWithdraw(address,uint256,uint8,bytes32,bytes32)`, `withdraw(address,uint256)`,
`claimRemaining()`, `extendClosingTime(uint256)`, `changeOwner`,
`addOwner/removeOwner/changeRequirement`, `setDailyLimit`, `resetSpentToday`, `seal`,
`fill`, `deposit`.

**Every function reverts for a non-owner (`InvalidJump` = solc 0.4.x `require`),
EXCEPT `deposit()` and `proxyWithdraw` with a small amount.**

`escapeHatch()` is `require(msg.sender == slot0)` (the owner `0xe79aca...`); on the
owner path it transfers `slot8` (a fixed 100 wei), NOT the whole balance. The fuzzer's
"Fund Loss" on `escapeHatch` is therefore a control-leak artifact: no non-owner path
moves value.

**A real finding -- `proxyWithdraw` (Unchecked ecrecover(0)):** the function builds the
message `"Withdraw DAOETC to " + <20-byte address> + <32-byte amount>` (verified by
reconstructing the keccak prefix), CALLS the ecrecover precompile (a CALL to `0x1`,
pc=1927), but **does not check that the result is non-zero**. With `v=27, r=0x1111...,
s=0x2222...` (a forged signature) the function **SUCCEEDS (status 1, 64122 gas)**. With
`v=0, r=0, s=0` ecrecover returns `0x0`, but the function stops AT the check `amount >
100` (a second check); with an amount `<= 100` it goes through.

**But a real movement of funds is NOT proven:** on a successful
`proxyWithdraw(ME,1)` and `proxyWithdraw(ME,100)` the balance of the target, the
attacker AND the owner **does not change** (all deltas 0). The payout goes through
`slot7` (the owner `0xe79aca...`) with an amount determined by something that is 0 in
this state — so "Fund Loss" here is UNCONFIRMED. What IS confirmed is the vulnerability
itself: the signature is not verified correctly (ecrecover(0) is not rejected) — which
is the classic `Unchecked ecrecover` class, but by itself in this state it does not
drain the contract.

**The second RUNNABLE target `0xD096...9ff7` is standard WETH9** ("Wrapped Ether"): it
has no call to the ecrecover precompile, so "Unchecked ecrecover(0)" there is a FALSE
POSITIVE. `deposit()/withdraw()` behave exactly as in WETH (withdraw of an unheld
balance reverts).

### Conclusion

The triage was correct: 220 of 241 surfaces are noise, 21 are real, but **none of the
21 (in this state) moves funds** — RUNNABLE is a necessary, not a sufficient condition.
This is exactly the "prove, do not claim" rule: only a real tx on the fork that moves
value counts. The materialization recipe for `proxyWithdraw` (SIGNATURE) is correct, but
materialization ITSELF does not create value that is not available in the contract
through that path.

## Following the money on 0x9f53...5ce3: no non-owner path pays out (2026-11-07)

A continuation of the previous section. After deeper tracing (an anvil fork of ETC,
never mainnet) the picture is complete and NEGATIVE regarding draining the contract:

**An important correction of the previous measurement:** `withdraw(address,uint256)` is
NOT non-replayable. At 3M gas it is OOG, but at 8M (the REAL ETC block limit, confirmed
on mainnet: gasLimit=8,000,000) it **SUCCEEDS** (status 1, 37064 gas) with `amount=1`.
The earlier OOG was due to too little gas, not the contract's logic — this is exactly
the "simulation without gas metering" trap.

**But the payout is 0, because `balanceOf(user)` is 0.** The `withdraw` trace:
1. SLOAD slot1 -> the ledger address `0x180826b05452ce96e157f0708c43381fee64a6b8`
2. CALL ledger.`balanceOf(msg.sender)` (0x70a08231)
3. SLOAD `keccak(user, slot0)` -> the internal balance (0)
4. CALL ledger.`totalSupply()` (0x18160ddd) -> 1.15e25
5. SLOAD slot2, slot4, slot `keccak(adr, ...)` -> all 0
The contract therefore checks `balanceOf` + the stored balance; since both are 0, it
transfers 0. The `RETURN` of the intermediate steps is `0x00...00`.

**The ledger `0x180826...` has `totalSupply` 11538165987024671407837618, but
`balanceOf` is 0 for EVERY checked address** (owner, WHG donation, slot8, the target,
the zero address) — even directly via `cast index` on the mapping at slot0. The
distribution of balances was therefore never performed (or the balances are elsewhere
and the path to them is not through these selectors).

**`deposit()` accepts ETH but does NOT credit a per-user balance:** after a deposit of
1 ETC the target's balance increases (+1 ETC), but `getMyBalance(ME)` stays **0**; the
deposit only adds to slot4 (the total pool) and emits LOG1. So `deposit -> withdraw`
returns nothing to the depositor. `withdraw` with `amount=1e18` after a deposit even
OOGs (the loop depends on the amount), while with `amount=1` it succeeds with a 0
payout.

**In the successful paths there is NO value transfer:** the opcode histogram of
`withdraw`/`proxyWithdraw` contains only 3 CALLs with `value=0` (ecrecover, balanceOf,
totalSupply), `SELFDESTRUCT: 0`, `CREATE: 0`, the last opcode STOP. `sealed() == true`,
`totalAccounts == 22092`.

**Conclusion:** all 21 real surfaces are structurally UNEXPLOITABLE in the contract's
current state — either they are `AUTH_GUARD` (owner-only), or they pay out 0 because the
ledger has no balances. The only confirmed bug remains `proxyWithdraw` `Unchecked
ecrecover(0)` (a forged signature SUCCEEDS), but it alone does not move funds. The
contract is probably a "DAOETC"-style refund/claim system, where the balances are set
in another (managed) step that a non-owner does not reach.

## Final proof: the ledger has totalSupply, but NO balances (2026-11-07)

The last stone is uncovered and closes the whole investigation of 0x9f53...5ce3.

The ledger `0x180826b05452ce96e157f0708c43381fee64a6b8` has exactly 7 functions:
`totalSupply()`, `seal()`, `totalAccounts()`, `balanceOf(address)`, `fill(uint256[])`,
`owner()`, `sealed()`. There is **NO `mint` or `setBalance`** — the balances are fixed
in storage and cannot be increased through any selector.

`balanceOf(a)` reads `storage[keccak(a, slot0)]` (confirmed with a trace: KECCAK inputs
[0x40, 0x0] -> SLOAD key 0x88d0184361... = `cast index address 0x941D... 0`). It is
**0 for every checked address**. The ledger's structure: slot0=0 (mapping), slot1=owner
0x941D..., slot2=totalSupply 1.153e25, slot3=22092 (totalAccounts), slot4=1 (sealed),
owner()=0x941D..., sealed=true.

**Consequence:** the fuzzer's "Fund Loss" on `withdraw`/`proxyWithdraw` relies
EXCLUSIVELY on a faked `balanceOf` (a leak of `0x70a08231`/`0x7e3ef7cd`), not on a real
movement. The `TOKEN_BALANCE` recipe in the materialization list is theoretically
correct, but **physically infeasible for this contract**: loading a non-zero balance for
the attacker in the ledger is impossible, because the ledger has no path to write
balances and its `fill`/`seal` is owner-locked.

Therefore the final answer to "does any of the 21 real surfaces drain the contract?" is
**NO**, and that with proof, not with a guess. The only confirmed bug remains
`proxyWithdraw` Unchecked ecrecover(0) (a forged signature SUCCEEDS, status 1), but it
alone does not move value.

This is also the limit of the fuzzer itself: the control leak (a faked `balanceOf`)
CREATED a passage through a `require` that does not exist on the real chain. The triage
+ materialization layer correctly flags this as NEEDS_MATERIALIZATION; only a real tx on
the fork (which moves 0) shows that materialization is not possible.

## Layer 5 — `owner_impersonation`: separating the owner from the attacker (2026-11-07)

**A problem found live** (the ETC target `0x9f5304DA62...5ce3`): a run returned 1201–2072
plans, **all 2072 `SKIPPED, NOT EXTRACTABLE`, 0 confirmed**. This was not a pipeline bug
— the fuzzer worked exactly as designed, but it created most findings by **becoming the
owner of the target**.

`src/evm/host.rs` on `SLOAD` deliberately collects concrete addresses from storage into
the caller pool (without it, owner-gated code is unreachable). But when it reads the
`owner` from slot 0, it can call `escapeHatch()` (`require(msg.sender==owner)`) **as the
owner** — and report it as "Fund Loss". Verified on a fork: `escapeHatch` as OWNER → OK;
as RANDOM → REVERT (InvalidJump). There is no intrusion, only a privileged party
exercising its right.

**Fix (an honest tag, not a cover-up):**
- `host.rs`: a new `HARVESTED_STORAGE_ADDRESSES` (`lazy_static RwLock<HashSet<String>>`,
  checksummed addresses) + `record_harvested_storage_address()` at the harvest site +
  `is_harvested_storage_address()`.
- `solution/script_generator.rs`: `PlanMeta.owner_impersonation` =
  `callers.iter().any(...)`. Deliberately `any`, not `all`: the live false positive had
  TWO callers (a generic fuzzer address + the owner's multisig), and the owner was the
  one that satisfied the `require`. `all` would miss exactly this case.
- `auto_pipeline.py` / `batch_pipeline.py`: `metadata_skip_reason` now skips such plans
  with a clear reason ("owner/admin/multisig impersonation"), and the summary prints how
  many. Verified order: the review-tier reason takes precedence over owner-impersonation
  (a heuristic finding with a harvested address stays "heuristic", not "impersonation").

**Why a tag, not a removal:** using harvested addresses is useful and deliberate for the
fuzzer. Removing it would reduce coverage of owner-gated code. The tag preserves
coverage but prevents the pipeline from presenting 2000+ infeasible plans as attacks.

**Tests:** `test_preflight_gate.py` +3 (`test_owner_impersonation_is_skipped`,
`test_missing_owner_impersonation_defaults_to_not_flagged`,
`test_review_tier_wins_over_owner_impersonation`). Total 31/31 PASS.
