# Expansion plan: new oracle types (2026-11-02, to continue "tomorrow")

## Scope -- clarified 2026-11-02 (important, do not miss)

After reviewing an external (ChatGPT) proposal for "70 oracles", the user explicitly
clarified the goal: **lending/liquidation/governance/bridge/staking-specific oracles
(the proposed group #48-70 in that external document) are NOT the goal** -- that would
require a semantic understanding of a SPECIFIC protocol (what "collateral factor" IS
in Aave vs Compound vs Euler), which contradicts ForkSploit's own, deliberate identity:
"EVM-only, bytecode-only, no need for source" (see `CLAUDE.md`). That would be a
different category of tool (a manual audit checklist for a known protocol), not an
extension of the same bytecode fuzzer.

**The real, clarified task**: achieve **full, thorough, reliable coverage within the
existing scope** -- i.e. (a) implement PHASES A/B/C below (13 candidates, all
protocol-agnostic, purely EVM-level patterns, the same as the existing oracles), AND
(b) systematically find gaps WITHIN and BETWEEN the existing oracles -- i.e. places
where one oracle partly covers something it should cover completely, or where two
oracles overlap / have an unclearly divided responsibility (example A2 below: "does
`reentrancy.rs` already cover ERC721/1155 hook reentrancy before we write a new
middleware" is EXACTLY this type of task). The goal is not a larger number of oracles
for its own sake -- the goal is that no bytecode-level, protocol-agnostic pattern from
well-established taxonomies (the SWC Registry, known DeFi hacks) is left uncovered or
half-covered.

> **Update 2026-11-07**: this document was written 2026-11-02, when there were 31
> oracles. Since then several have been added (today there are **46**; count the
> `OracleType` variants in `src/evm/mod.rs`), and the empty stub
> `src/evm/oracles/function.rs` has been **deleted** (along with the dead constant
> `FUNCTION_BUG_IDX`) -- see the "Context" paragraph below.

## Context

ForkSploit currently covers **46 actual oracles** (`src/evm/oracles/*.rs`; count the
`OracleType` variants in `src/evm/mod.rs`). The empty stub `function.rs` (1 byte, no
content) was **deleted 2026-11-07** along with the dead constant `FUNCTION_BUG_IDX` --
it was never wired into `OracleType` and no other module referenced it, so it was dead
technical debt, not a candidate for completion. This document is the result of a
systematic review of the SWC Registry (Smart Contract Weakness Classification) and
known, real DeFi hacks, compared against the existing list, to find CONCRETE, real
gaps -- not a generic "add a few more" list.

**Deliberately excluded**: everything that is purely static/source-code analysis
(floating pragma, variable naming, default function visibility, inheritance order) --
ForkSploit works at the BYTECODE level; Slither already covers that in
`onchain_scripts/auto_pipeline.py`'s `run_static_analysis()`. Below are ONLY patterns
worth detecting dynamically, during fuzzing execution (opcode-level tracing, taint
tracking, pre/post state comparison).

**Each candidate below needs**: a new middleware (opcode tracing) + a new oracle
(interpretation + a `bug_type` string + a confidence tier) + wiring into
`src/evm/mod.rs`'s `OracleType` enum + `src/evm/evm_fuzzer.rs`'s oracle registration +
a test fixture in `tests/evm/<name>/` + live verification (a local fuzz run, verify it
fires on the fixture and NOT on a control case without the bug) + documentation in
`capabilities.md`. The same discipline as for all existing oracles -- no shortcuts.

## PHASE A — Already confirmed by the user (2026-11-02), first in line

These four were explicitly chosen the previous evening, before the session expanded to
"all the missing ones". Start HERE, in order:

### A1. Read-only reentrancy (highest priority)
- **What**: a `view`/`pure` function returns a manipulated/inconsistent state DURING a
  reentrant callback (before the state is "fixed" after the outer call ends), and an
  EXTERNAL integrator (another contract) reads it and trusts it as the real state. The
  cause of real hacks: Curve (January 2023, ~$70M of funds at risk for integrators),
  Sturdy Finance (2023).
- **Why it is not covered**: the existing `reentrancy.rs`/`ReentrancyTracer` (a
  middleware, a SLOAD/SSTORE read-before-write pattern on the SAME contract) catches
  ONLY a change of STATE (SSTORE) during the leak -- it does not catch the case where
  the only "damage" is that a VIEW function returned a wrong result during the leak,
  which NOBODY within that transaction writes back, but which an EXTERNAL contract
  reads (i.e. cross-contract, not cross-function within one).
- **Detection mechanism (sketch)**: a new middleware tracks when contract A is in the
  middle of a "control leak" state (see `host.rs`'s `leak_ctx`/`ControlLeak`) AND in
  that window ANOTHER contract B called STATICCALL/CALL on contract A on a view-style
  function (a selector without a state change), which returns a value that DIFFERS
  from the value the same function would return BEFORE/AFTER the whole transaction.
  This is an `arb_call.rs`-style "who called during the leak" + a before/after result
  comparison.
- **Confidence tier**: Review first (a heuristic; legitimate patterns may exist) --
  Confirmed only if profit is proven on B's side.
- **Test fixture**: a minimal ERC4626-style vault with a `pricePerShare()` view
  function that returns an inflated price during `withdraw()`'s ETH-send reentrancy
  window, + a separate "integrator" contract that reads it.

### A2. ERC721/1155 safe-transfer hook reentrancy
- **What**: the `onERC721Received`/`onERC1155Received`/`onERC1155BatchReceived`
  callback during `safeTransferFrom()` is a reentrancy vector separate from an ordinary
  ETH-send reentrancy (the NFT standard EXPLICITLY requires this callback, so the
  standard's "safety" benefit is at the same time an attack vector).
- **Check first**: whether `reentrancy.rs`'s existing mechanism (depth-based
  SLOAD/SSTORE tracking) already detects this indirectly, because the callback mechanism
  at the EVM level is the same as an ordinary CALL (only a different caller/trigger). If
  YES, no new oracle is needed -- only a new TEST FIXTURE, to prove coverage and add a
  regression test. If NO (perhaps because ReentrancyTracer filters in some way on it
  being an ETH transfer specifically), a separate mechanism is needed.
- **This is therefore first a RESEARCH task** ("is this already covered"), and only
  then a possible implementation.

### A3. Weak randomness (blockhash/timestamp as entropy)
- **What** (SWC-120): reading `block.timestamp`/`blockhash(...)`/`block.number`/
  `block.difficulty`/`block.basefee` and using the RESULT in a comparison/modulo
  operation that determines a payout/winner/allocation (e.g. a lootbox, a lottery, a
  "random" NFT mint).
- **Detection mechanism**: trace the opcodes `0x42` (TIMESTAMP), `0x40` (BLOCKHASH),
  `0x43` (NUMBER), `0x44` (DIFFICULTY/PREVRANDAO), `0x48` (BASEFEE) -- remember (addr,
  pc, the value on the stack), then check whether that value (or its MOD/AND result) is
  later used as an operand of EQ/LT/GT/MOD just before a branch that affects an SSTORE
  connected to a payout/balance. A fairly similar pattern to `tx_origin.rs` (trace the
  origin -> check its use in a condition).
- **Confidence tier**: Review (legitimate use for NON-critical logic is possible, e.g.
  caching a timestamp with no security significance).
- **Test fixture**: a simple "lottery" contract, `winner = blockhash(block.number-1) %
  participants.length`.

### A4. DoS via revert in a loop (the push-payment pattern, SWC-113)
- **What**: a loop that within each iteration performs a CALL (often sending ETH to
  several recipients), and is NEITHER wrapped in try/catch NOR checks the result with
  `continue` on failure -- so ONE rejected/broken recipient (e.g. a contract without
  `receive()`, or one that deliberately reverts) blocks the WHOLE function for ALL the
  other recipients forever.
- **Difference from `unchecked_call.rs`**: that existing oracle catches the OPPOSITE
  thing -- a call that SILENTLY fails and continues (the result is ignored). The new
  oracle catches a call in a loop whose failure LEADS TO A REVERT of the whole
  transaction (a `JUMPI` on the revert path, conditioned on the CALL's success bit,
  inside a detected loop -- `unbounded_loop.rs` already has loop detection, so this
  oracle can share the same JUMPDEST-loop-detection infrastructure).
- **Confidence tier**: Review (a legitimate design is possible, if few recipients are
  known).
- **Test fixture**: `distributeDividends(address[] recipients)`, which inside a `for`
  loop does `recipients[i].transfer(amount)` without try/catch.

## PHASE B — Additional candidates from the SWC Registry (a systematic review)

Counted against ALL SWC-100 to SWC-136 -- below are ONLY those that (a) are not already
covered and (b) make sense for bytecode-level dynamic detection:

### B1. Write to Arbitrary Storage Location (SWC-124)
- An `SSTORE` whose SLOT argument is (partly) derived from CALLDATA (taint tracking, a
  pattern similar to `delegatecall_target.rs`'s real taint tracking) -- NOT just a
  static layout comparison like `storage_collision.rs`. A real, separate, high-risk
  issue: an attacker can OVERWRITE an arbitrary slot (owner, implementation address, a
  balance mapping) through an uncontrolled index in a `mapping`/`array` access.
- A Confirmed-tier candidate (a very low false-positive rate, if the taint is really
  proven, the same as delegatecall_target.rs).

### B2. Hardcoded Gas Stipend Reliance (SWC-134)
- **We ALREADY FOUND THIS IN THIS SESSION as a real contract-specific bug** (WETH9's
  `transfer()` 2300-gas stipend, which broke `AttackWallet`'s `receive()`). This proves
  the pattern is real and important. Detection: a `CALL`/`STATICCALL`/`SEND` with an
  explicit gas value on the stack == exactly 2300 (or another low hardcoded constant
  amount), combined with a `.transfer()`/`.send()`-style bytecode shape.
- Confirmed-tier (deterministic, easy to verify).

### B3. Unexpected Ether Balance / Force-Fed ETH Assumption (SWC-132)
- The contract compares `address(this).balance` with internal accounting
  (`totalDeposits`/the sum of a mapping) and EXPECTS equality -- a `selfdestruct` from
  any contract to THAT address, or a `block.coinbase` reward, can force ETH past every
  `receive()`/`payable` check, breaking that assumption. Partly related to
  `eth_backing.rs` (which already catches "promised > real"), but this is narrower:
  ONLY the case where the cause is UNEXPECTEDLY forced ETH (not just general
  insolvency).
- Review-tier (eth_backing.rs may already suffice -- check the overlap BEFORE a new
  implementation, similar to A2 above).

### B4. Assert Violation / Reachable INVALID with attacker input (SWC-110)
- An `assert()` (the INVALID opcode `0xfe`, not an ordinary REVERT) reached with
  attacker-controlled input instead of an internal invariant -- it means the developer
  used `assert` for INPUT VALIDATION instead of an internal check, which consumes ALL
  the gas instead of refunding the remainder (and is a signal of bad practice/ a
  possible logic bug where `require` should have been used).
- Low priority, review-tier, easy detection (just `0xfe` reached without a revert
  earlier, with taint on the input).

## PHASE C — DeFi-specific candidates (from real hacks, not the SWC)

### C1. Flashloan-enabled price/governance manipulation in ONE transaction
- A generalization of the existing `twap_manipulation.rs`/`v2_pair.rs`: detect a LARGE
  flashloan-financed swap/deposit + a VOTE or a PRICE-DEPENDENT decision + a repay, ALL
  in ONE transaction. The pattern for Beanstalk ($182M, April 2022), bZx (2020). Partly
  covered indirectly through `erc20.rs`'s Fund Loss + `v2_pair.rs`, but NONE of the
  existing ones EXPLICITLY links "a flashloan in this transaction" + "a vote/governance
  call" as its own bug_type.
- High value, but a more complex implementation (it needs tracking of "was this call
  financed with a flashloan", which `auto_pipeline.py` partly knows from
  `execute_flat_plan_via_flashloan`, but that is the Python side, not a Rust oracle).

### C2. Missing slippage/deadline check on swap functions
- A function that performs a swap/trade WITHOUT checking the `minAmountOut`/`deadline`
  parameter (or accepts it but NEVER uses it in a comparison/`require`) -- a classic
  "sandwich attack" enabler. Taint tracking: is a `minOut`-style parameter present in
  the calldata, but never reaches any `LT`/`GT`/`require` comparison before the swap is
  performed.
- Review-tier (may be legitimate if the deadline/slippage is checked HIGHER in the call
  chain, e.g. at the router level).

### C3. Fee-on-transfer / rebasing token mismatch
- The contract assumes `amountReceived == amountSent` on an ERC20 transfer (it stores
  the `amount` argument directly into the accounting, instead of checking the ACTUAL
  change of its own balance before/after the transfer) -- fee-on-transfer and rebasing
  tokens (real, common in production) break that assumption, which leads to accounting
  drift/a drain.
- Detection: a `TRANSFERFROM`/`TRANSFER` call whose return value (or the `amount`
  argument) is SSTORE-d directly into an accounting mapping, WITHOUT an intervening read
  of `balanceOf(address(this))` before/after.

### C4. Missing zero-address check on critical setter functions
- `setOwner(address)`/`setAdmin(address)`/`upgradeTo(address)` without
  `require(newAddr != address(0))` -- a simple, but genuinely common mistake that can
  irreversibly "cement" a contract (owner = address(0), no one can manage it anymore).
  Easy, deterministic detection: an SSTORE into a slot `access_control.rs` already
  recognizes as an owner/admin slot, with the value `0x0`, without a preceding
  `ISZERO`+`REVERT`-JUMPI check on the argument.
- A Confirmed-tier candidate (a low false-positive rate).

### C5. Precision loss: division before multiplication
- The bytecode pattern `DIV` immediately follows `MUL` on the SAME value without an
  intervening SSTORE/use (i.e. `(a / b) * c` instead of `(a * c) / b`) -- a classic,
  well-documented bug in interest/share calculations, which leads to rounding against
  the user or the protocol. Purely bytecode-pattern-detectable (an opcode sequence),
  without needing taint tracking.
- Review-tier (may be deliberate, e.g. for gas optimization where the loss is not
  significant).

## Status: B1 (Arbitrary Storage Write) done (2026-11-03)

Implemented and live-verified -- a new middleware
(`middlewares/arbitrary_storage_write.rs`, extending the existing `0x35` CALLDATALOAD
case in `host.rs` with a generic, not only address-filtered, `current_calldata_words`)
+ a new oracle (`oracles/arbitrary_storage_write.rs`, built with a
`pre_state`/`post_state` diff FROM THE START, not as a later fix). Wired into the
`OracleType` enum, the `all`/`high_confidence` lists, `CONFIRMED_EXPLOITABLE_BUG_TYPES`,
`classify_confidence`. Test: a positive fixture
(`tests/evm/arbitrary_storage_write/main.sol`, a raw `assembly { sstore(slot, value) }`)
fires correctly; a control fixture (an ordinary `mapping[key]=value`, which always goes
through KECCAK256) correctly does NOT fire -- verified, not just claimed.

Found and fixed in passing BEFORE this work: a systematic review of all 11
`.chain(self.host.current_X...)` places in `vm.rs` revealed 4 ADDITIONAL, previous-day
overlooked instances of the same "never reset" bug (`uninitialized_memory_reads`,
`unchecked_call`, `tx_origin_checks`, `delegatecall_targets_seen`) -- see SKILL.md
"Layer 4".

## Status: C3 (Token Accounting Mismatch) done (2026-11-03)

Implemented and live-verified -- `transferFrom(from, address(this), amount)` +
an immediate SSTORE that adds the UNVERIFIED `amount` to the SLOAD-ed old value, is
detected directly in `host.rs`'s `call()`/`0x55` code (not a separate middleware --
it needs a decoded `CallInputs.input`, which only `call()` itself sees). Review-tier.
The test fixture (`tests/evm/token_accounting_mismatch/Vault.sol`) deliberately calls
ONLY ITSELF with transferFrom-shaped calldata (an empty `fallback()`), to avoid the
unrealistic "the fuzzer must guess the address of another randomly-deployed contract"
problem -- the detection itself does not depend on which address is actually called,
only on the shape of the outgoing call and the SSTORE that follows it. The positive
fixture fires immediately; the control case (an ordinary ETH `deposit()` without an
external call) correctly does NOT fire.

## Status: B3 (Forced Native Value Accounting) done (2026-11-03)

Implemented and live-verified -- an EQ comparison against
SELFBALANCE/BALANCE(address(this)) (SWC-132, the DoS direction, opposite to
`eth_backing.rs`'s insolvency direction). Here an IMPORTANT, GENERAL architectural
property was found (see SKILL.md): an outgoing value-transferring call LATER in the
same transaction can exclude the reporting of ALL bugs in that transaction through
`feedback.rs`'s `has_post_exec` check (control leak), REGARDLESS of where in the
transaction the bug is detected. The test fixture must be without such a call, to
avoid this.

## Status: C1 (Flashloan Manipulation) CANCELLED (2026-11-03)

After research, cancelled as infeasible/redundant within the existing EVM-generic,
bytecode-only scope -- distinguishing "legitimate arbitrage" from "manipulation"
within one flashloan-wrapped block of transactions requires protocol-specific semantic
understanding (which contract is the real oracle/pool, what a "fair" price is), which
is in direct contradiction with ForkSploit's own, deliberate restriction to
EVM-only/bytecode-only detection without business logic. The existing
`twap_manipulation.rs`/`curve_virtual_price.rs` (both with a "Profit Confirmed"
variant) already cover the actually provable part of this pattern (a price jump +
proven caller profit within one transaction), regardless of whether the capital for
the attack came from a flashloan or its own funds -- a flashloan is only a funding
mechanism, not a new detection signal.

## Status: A1 (Read-Only Reentrancy) implemented, but rarely reports -- an architectural limitation, not a bug (2026-11-03)

The oracle (`readonly_reentrancy.rs`, bug_idx 39) is implemented; it required a
persistent `view_call_baseline` host field (the same pattern as `slot_write_contexts`),
and the host-level detection is proven correct (debug runs confirm thousands of correct
hits). Nevertheless, in practice the finding is almost never reported -- the root cause
is NOT in the oracle nor in `feedback.rs` (verified as working correctly: classic
`Reentrancy` regularly passes it), but in the fuzzer's mutation/continuation strategy
(`mutator.rs`/`evm_fuzzer.rs`), which during an open control-leak window almost never
tries exactly "call back `getPrice()` now, then finish normally". The full analysis and
data: `SKILL.md` (the 2026-11-03 section), `capabilities.md` (the Review-tier
addition). The user chose to dig into `mutator.rs`/`evm_fuzzer.rs` directly -- NOT
completed in this session (the session limit approaching), to continue next session.
This holds as a warning for ALL future control-leak-dependent oracles (e.g. A2 below).

## Status: the existing delegatecall_target.rs fixed and live-confirmed (2026-11-03)

Separate from the new oracles above: at the user's request the already-existing
`delegatecall_target.rs` (added 2026-11-02) was reviewed for the same class of
cross-leak-resumption bug as `readonly_reentrancy.rs`. TWO real bugs were found and
fixed (see SKILL.md for the full analysis): (1)
`calldata_addresses`/`returndata_addresses`/`paid_calldata_addresses` did not survive a
continuation of a control-leak continuation -- fixed more safely than
`view_call_baseline` (seeded from `vm_state`, not persistent forever, to avoid false
positives on a Confirmed-tier oracle); (2) the `calldata.len() < 20` check wrongly
blocked even Confirmed-tier signals that do not depend on `calldata` -- limited only to
the weaker fallback. **Unlike A1 above, this fix WAS successfully live-confirmed** (a
new purpose-built fixture, `tests/evm/delegatecall_target/`) -- the oracle now reports
correctly when the RETURNDATACOPY decoding of the target and the DELEGATECALL are split
across a leak boundary. Proof that A1's obstacle really is specific to the fuzzer's
mutation strategy (which continuations it even attempts), not a general architectural
inability to report across a leak boundary in general -- here the obstacle was in two
localized code errors that could be directly fixed.

## Priority summary for tomorrow

1. **PHASE A (4 already confirmed)** — start here, in order A1→A4. A2 is partly a
   RESEARCH task (check coverage, then code).
2. **B1 (Arbitrary Storage Write) and B2 (Hardcoded Gas Stipend)** — the next highest
   value: both Confirmed-tier, both with a low false-positive rate, B2 is literally a
   proven real bug in this session (WETH9), B1 is the same taint-tracking pattern as the
   existing `delegatecall_target.rs` (hence less implementation risk).
3. **C4 (zero address on setters)** — very easy, a quick win.
4. The remainder (A3, A4, B3, B4, C1, C2, C3, C5) by agreement, depending on the time
   available — each requires the same discipline (middleware + oracle + fixture + live
   verification), no shortcuts.

**Not in this list** (deliberately omitted, because it is purely static/source-code,
not bytecode-dynamic): SWC-100, 102, 103, 108, 111, 118, 119, 125, 129, 130, 131, 135,
136 -- those already are (or should be) covered by Slither/static analysis in the
Python layer, not by ForkSploit's bytecode fuzzer.

---

## PHASE D — Data-driven gaps from 2025-2026 incidents (2026-11-05)

Source: DefiLlama `api.llama.fi/hacks` (1339 records, 696 from 2024+) + the rekt.news
leaderboard, processed by technique and USD. Below are ONLY those that (a) actually
caused losses in 2025-2026, (b) are bytecode-level, protocol-agnostic detectable, and
(c) are NOT already covered by the existing 43 bug_types.

### Key context: where the money actually disappeared (2025+)
- **Off-chain (keys/phishing/supply-chain): ~$7.4 bn** — ForkSploit deliberately does
  NOT cover this (it is not code; `capabilities.md` §9 already says this is out of
  scope). Do not add oracles for it.
- **Code-level: ~$4.1 bn**, of which the three largest classes:
  **Proxy Upgrade Hijack $366M**, **Unbacked Cross-Chain Mint $334M**,
  **Cross-Chain Message Spoofing $308M**.

### D1. Proxy Upgrade Hijack (the highest USD in code-level, $366M)
- Existence: `proxy_integrity.rs` catches REINITIALIZATION and STORAGE COLLISION, but
  does NOT catch the **upgrade hijack** pattern itself: `upgradeTo`/`_authorizeUpgrade`
  /UUPS `upgradeToAndCall` reached by a caller that was NOT authorized at the time of
  the call (e.g. an `onlyOwner` bypassed through an `initialize()` front-run or a
  `delegatecall` in `receive()`). This is the same class as Gala ($216M, 2024) and
  Balancer-forks (2025).
- Mechanism: `access_control.rs` already recognizes the owner/proxy slot; here add the
  link "a slot written by an `upgradeTo`-style selector" → "was that selector ever
  reached without a prior successful `onlyOwner` check in the same transaction".
  A Confirmed-tier candidate.
- Priority: **highest** (the most USD, closest to the existing infrastructure).

### D2. Unbacked Mint / Missing Supply Accounting ($334M + $21M Infinite Mint)
- Existence: `erc20.rs` covers "Fund Loss" (an outflow from the contract), but does NOT
  cover **a mint that is not backed by a counterpart** — e.g. `mint()`/`_mint()` raises
  `totalSupply`, but the corresponding deposit/collateral mapping is NOT increased. The
  pattern: Liquid Network (2026, ~$320M, "unbacked L-BTC"), Cashio ($48M), many 2025
  infinite-mint hacks.
- Mechanism: trace `totalSupply`-slot writes (an SSTORE into the slot read by the
  `totalSupply()` selector) → compare with writes into the "backing" mapping/slot in the
  same transaction. If the supply grows without a proportional backing write → a bug.
  Partly related to `eth_backing.rs`, but that is narrower (native ETH only) and
  reversed (insolvency, not a mint).
- A Confirmed-tier candidate.

### D3. Cross-Chain Message Spoofing / Forged Proof ($308M + $44M Forged Proof)
- Existence: `signature_replay.rs` covers signature replay, but does NOT cover
  **forged cross-chain message proofs** (Merkle proof / message hash verification, where
  an attacker plants `(root, proof)` or bypasses `verifyMessage`). The pattern:
  KelpDAO/LayerZero (2026, $290M), Nomad ($190M, "trusted root = 0x0"), BNB Bridge
  ($586M).
- Mechanism: a `verify`-style external call whose return value decides whether to
  continue (mint/release), where the `root`/`message` argument comes from calldata and
  was NEVER compared against authoritative state. Very close to the existing
  `unchecked_call.rs` + `signature_replay.rs` — perhaps an extension suffices, not a new
  oracle (the same "check the overlap BEFORE implementing" discipline as A2).
- Review→Confirmed (depending on whether the forged proof is provable).

### D4. Donation Attack / Balance-vs-Accounting Drift ($145M + $137M Rounding)
- Existence: `erc4626.rs` covers share inflation, `forced_eth_accounting.rs` covers
  forced-ETH. Missing: a **general "donation" pattern on NON-ERC4626 contracts**:
  `token.balanceOf(address(this))` as the source of truth, where a direct `transfer()`
  into the contract (bypassing `deposit()`) changes the price/share. The pattern:
  Balancer II (2025, $128M, "rounding down"), 2025 donation hacks.
- This is EXACTLY what the LLM layer (`llm_poc/`) already hit in a test by SHAPE (a
  donation via `transfer()`), but not by the exact numeric trick — hence a real,
  confirmed gap in the bytecode oracles.

### D5. EIP-1153 transient-storage reentrancy guard (Uniswap V4 era)
- Existence: `host.rs` has `transient_storage`, but **no oracle checks the guard in the
  TSTORE/TLOAD space** — `reentrancy.rs`/`stale_guard.rs` look at SSTORE/JUMPI. Modern
  contracts (V4 hooks, newer reentrancy guards) use transient storage; a guard that
  resets at the end of a transaction can be vulnerable if the `TSTORE` is in the wrong
  context.
- Mechanism: extend `stale_guard.rs` to TSTORE/TLOAD (the same JUMPI-fed-by-slot
  pattern, a different space). A smaller, targeted extension.

### D6. EIP-7702 delegation / ERC-4337 account-abstraction (completely empty)
- Existence: **NOTHING** (`grep 7702|4337|userop|paymaster` = 0 hits).
- This is the only completely uncovered NEW attack surface from 2025-2026 (7702 went to
  mainnet in Pectra, May 2025). Bytecode-level detectable: the
  `EXTCODECOPY`/delegation-designator pattern, a `validateUserOp`-style selector, the
  paymaster `validatePaymasterUserOp` flow.
- A higher effort (a new subsystem), but the only one covering a category that is 0%
  covered today.
- **Partly covered (2026-11-07):** the delegation designator `0xef0100 || delegate` is
  now recognized in BOTH layers (`src/evm/contract_utils.rs`'s `eip7702_delegate` +
  `onchain_scripts/proxy_resolver.py`'s `eip7702_delegate`) and placed into the existing
  proxy-resolution path, so the delegated contract is fuzzed (not just the designator).
  **Still missing:** the ERC-4337 `validateUserOp`/paymaster flow and an oracle for
  7702-specific abuses (e.g. delegation to a malicious contract) — that is still a
  separate project.

### Do not add (deliberately omitted from this phase)
- Off-chain classes (Private Key Compromised, Phishing, Supply Chain, DNS Hijack) —
  outside ForkSploit's identity.
- Protocol-specific lending/liquidation/governance oracles — already excluded in this
  same file above (they would require business logic).
- `Oracle Misconfiguration` ($11M) and `Aave liquidation` (2026) — these are
  config/ops errors, not bytecode patterns; not for a fuzzer.

### Proposed order
1. **D1 (proxy upgrade hijack)** — the most USD, closest to the existing code.
2. **D2 (unbacked mint)** — the most USD among the "clean" mint patterns.
3. **D5 (transient-storage guard)** — a small, targeted extension.
4. **D4 (donation, non-ERC4626)** — a confirmed gap from the LLM-layer test.
5. **D3 (cross-chain proof)** — first CHECK the overlap with
   `signature_replay.rs`/`unchecked_call.rs`.
6. **D6 (7702/4337)** — the largest new scope; a separate project.

## Status: D1 (Proxy Upgrade Hijack) DONE (2026-11-05)

Implemented and live-verified -- a new oracle (`oracles/proxy_upgrade_hijack.rs`,
bug_idx 46), without a new middleware (the detection is entirely in the oracle: it reads
the EIP-1967 slots from `pre_state`/`post_state` + `fast_static_call(owner())` on
`pre_state`).

**The gap, proven EMPIRICALLY BEFORE implementation** (not a guess): the existing
binary on the new fixture `tests/evm/proxy_upgrade_hijack/` (UUPS `upgradeTo` without a
guard, the admin slot never set) reported ONLY `Zero Address Setter` (sim-review) --
and that only because the fuzzer happened to call `upgradeTo(address(0))`. The real
vulnerability (a missing access control) was NEVER reported; a realistic malicious
NON-ZERO implementation address triggered NOTHING, `confirmed_exploitable: false`. The
code explains it: `access_control.rs` requires a NON-ZERO EIP-1967 admin slot (so it
has something to compare the caller against), while `proxy_integrity.rs` deliberately
skips the upgrade selectors. UUPS falls into both gaps.

**After implementation**: the same fixture now reports
`[Unprotected Proxy Upgrade (UUPS)] (sim-confirmed)`, `confirmed_exploitable: true`, and
generates a `*Exploit.s.sol` (confirmed: the file exists, because the finding is
single-identity/atomic).

**A negative fixture** (`tests/evm/proxy_upgrade_hijack_guard/`, an `onlyOwner` guard):
the oracle is SILENT -- and it is proven not silent because the fuzzer would not call
`upgradeTo`: the traces (`traces/1.json`, `traces/2.json` from a non-owner,
`traces/3.json` from the owner) confirm that the fuzzer really did execute the selector
`3659cfe6`; the guard reverted it, so there was no slot change.

**Regression**: the existing `proxy_reinit`/`proxy_collision`/`access_control` fixtures
still report exactly their existing bug_types, none reports the new one (no false
positives). Rust test suite: 67 passed / 11 failed -- IDENTICAL to the baseline before
the change (all 11 are network-dependent, they need Anvil on `localhost:8545`).

**A limitation that remains**: the detection requires a readable `owner()` through the
proxy (non-zero, != caller). A role-based guard (`hasRole`) without `owner()` looks
identical to a missing guard from the outside, so the oracle stays silent there rather
than guessing -- this is a deliberate choice (Confirmed-tier requires proof, not
suspicion).

## Status: D2 (Unbacked Mint / Missing Supply Accounting) DONE (2026-11-05)

Implemented (`oracles/unbacked_mint.rs`, bug_idx 47, Review-tier) -- deliberately
Review, not Confirmed: a public `mint()` is sometimes legitimate (a
faucet/rebase/inflationary token, or a token that is not meant to be native-backed at
all), so the final judgement needs a human. The detection itself is deterministic
(without heuristics), all 6 gates:

1. `totalSupply()` answers in the pre- AND post-state (ERC20-shaped).
2. post supply > pre supply (a mint happened in this tx).
3. the caller paid nothing (`txn_value == 0`).
4. the contract's native balance did NOT increase (there is no inflow to back the new
   supply -- e.g. a normal `deposit()`).
5. the contract ALREADY held native ETH and ALREADY had supply>0 (there is an existing
   backed pool being diluted; it excludes the first mint and pure ERC20/LP tokens).
6. the caller is not `owner()` (an admin mint is usually legitimate).

**Why this is not a duplicate**:
- `erc20.rs` reports "Fund Loss" (an outflow) -- a mint is the opposite direction.
- `eth_backing.rs` reports INSOLVENCY of the form `balances(address)` and deliberately
  excludes the ERC20 shape (as soon as `totalSupply()` answers, it goes to
  `not_applicable`). A token with `totalSupply()` is EXACTLY what it skips.

**Verified live**:
- `tests/evm/unbacked_mint/` (an honest `deposit()` + a free `mint()`): reports
  `[Unbacked Mint (Supply Growth Without Backing)] (sim-review)`. The trace confirms
  `deposit{value} -> deposit{value} -> mint(big)` -- the real pattern.
- `tests/evm/unbacked_mint_guard/` (supply grows ONLY through a paid `deposit()`): the
  oracle is SILENT, and the traces (`d0e30db0`) prove the fuzzer really did call
  `deposit` -- the silence is meaningful, not empty.
- `-d high_confidence` does NOT include this oracle (Review-tier stays outside the
  high-confidence set; verified that on the positive fixture `high_confidence` does not
  report unbacked mint).
- Regression: `eth_backing`/`erc4626`/`token_accounting_mismatch` still report exactly
  their existing bug_types, none reports "Unbacked Mint".
- `cargo test`: 67 passed / 11 failed == baseline (all 11 network).

## Status: D3 (Cross-Chain Message Spoofing / Forged Proof) DONE (2026-11-05)

Implemented (`oracles/forged_proof.rs`, bug_idx 48, Review-tier). The roadmap proposed
"check the overlap BEFORE implementing" -- verified EMPIRICALLY on the new fixture
`tests/evm/forged_proof/` with the EXISTING binary: the existing oracles report only
unrelated `Centralization Risk`/`Zero Address Setter`/`Arbitrary Storage Write`, NOT ONE
reports a forged proof. The gap is confirmed.

**Why a NEW oracle, not an extension** (the answer to the roadmap's doubt):
- `signature_replay.rs` covers REPLAY of the same signature bytes; here there is no
  signature and no replay (each `(root, proof)` is unique).
- `unchecked_call.rs` covers a FAILED external call whose result is ignored; here the
  call/verification SUCCEEDS and is accepted.
- No existing oracle traces "a locally computed hash == a caller calldata word,
  accepted, without a comparison against stored state".

**Mechanism (real dataflow, not proximity)**:
1. `host.rs` 0x20 (SHA3): computes EXACTLY the hash revm is about to compute, and
   records it (`current_last_sha3`).
2. 0x14 (EQ): if one operand is that hash and the other is a raw calldata word
   (`current_calldata_words`), remember the pair. It separately records every calldata
   word ever compared with an SLOAD-ed value (`current_calldata_sload_compared`) -- the
   SAFE `root == trustedRoot` shape.
3. 0x57 (JUMPI): record the pair only if the branch was ACCEPTED
   (`current_proof_accepted`).
4. The oracle excludes every pair whose root was also SLOAD-compared (the contract DID
   bind it to state).

An additional safeguard against false positives (found during regression): the
comparison must have TWO DIFFERENT operands and the computed hash must not be just one
of the caller's words -- without this, solc's mapping-slot arithmetic (comparing the
calldata key with itself) triggers a false positive (confirmed on `eth_backing`).

**Verified live**:
- `tests/evm/forged_proof/` (the root from calldata, never compared with `trustedRoot`):
  reports `[Forged Proof (Caller-Supplied Root Accepted)] (sim-review)`, pc 2858, with
  the caller's word.
- `tests/evm/forged_proof_guard/` (the same pattern, but `require(root == trustedRoot)`
  before the credit): the oracle is SILENT.
- Regression (false positives): `eth_backing`, `token_accounting_mismatch` are CLEAN
  after the additional filters; `signature_replay`, `ecrecover`, `storage_collision`,
  `arbitrary_storage_write`, `erc4626`, `erc1155_batch`, `nft_transfer`,
  `twap_manipulation`, `curve_virtual_price`, `olympus-simple`, `proxy_collision`,
  `proxy_reinit`, `readonly_reentrancy`, `delegatecall_target` -- all without a Forged
  Proof false positive.
- `-d high_confidence` does NOT include this oracle (Review-tier).

## Status: D5 (EIP-1153 transient-storage reentrancy guard) DONE (2026-11-05)

Implemented (`oracles/transient_guard.rs`, bug_idx 49, Review-tier).

**The gap, proven EMPIRICALLY BEFORE implementation** (not a guess): `host.rs` `step()`
in the existing binary did NOT decode `0x5c` (TLOAD) / `0x5d` (TSTORE) AT ALL --
verified with `grep -c "0x5c =>\|0x5d =>"` = **0**. The only existing reentrancy/stale
guard oracles look at `0x54/0x55` (SSTORE/SLOAD), so the EIP-1153 guard is completely
invisible. On the new fixture `tests/evm/transient_guard/` (the guard released BEFORE
the call) the existing binary reports only the SSTORE-tracking `Reentrancy` through
`balances` -- NOT ONE oracle shows that it is precisely the TRANSIENT guard released too
early.

**Why the signal deviates from the roadmap's proposal**: the roadmap proposed "the same
JUMPI-fed-by-slot pattern as stale_guard". That would be WRONG -- transient storage
resets at the end of every transaction, so "the slot never changes" would fire on EVERY
correct guard (every `tload(0)` reads 0 at the start of every tx). The real,
deterministic signal is instead: **the guard was unlocked (a TSTORE of 0 to a slot that
was TLOAD-ed and previously locked in this transaction) BEFORE an external CALL** -- a
checks-effects-interactions violation in the transient space.

**Mechanism (real dataflow)**:
1. `host.rs` 0x5c (TLOAD): records the slot as a guard candidate
   (`current_transient_loaded`).
2. 0x5d (TSTORE): a non-zero write = a lock; a zero to a previously locked slot =
   "pending unlock" (`current_transient_unlock`); a re-lock cancels it.
3. The CALL/STATICCALL arm (0xf1/0xf2): if it executes while a TLOAD-ed slot is in the
   unlocked state, record a hit (`current_transient_unlock_calls`).
4. The oracle (Review-tier) reports each such pair (addr, tstore pc, slot).

**Verified live**:
- `tests/evm/transient_guard/` (the guard released BEFORE the call): reports
  `[Transient Guard Released Before External Call]`.
- `tests/evm/transient_guard_safe/` (the same guard, released AFTER the call -- a correct
  checks-effects-interactions): the oracle is SILENT.
- `-d high_confidence` does NOT include this oracle (Review-tier); verified that on the
  positive fixture `high_confidence` does not report Transient Guard.
- Regression (false positives): `reentrancy`, `stale_guard`, `eth_backing`, `erc4626`,
  `proxy_upgrade_hijack`, `unbacked_mint`, `forged_proof` -- all without a Transient
  false positive. Only the new fixtures use TSTORE/TLOAD (`grep -rl tstore tests/evm`).
- `cargo test`: 67 passed / 11 failed == baseline (all 11 network).

## Status: D4 (Donation / balance-vs-accounting drift, non-ERC4626) DEFERRED (2026-11-05)

An attempt to implement it (a new oracle `oracles/donation.rs`, bug_idx 50) was REMOVED
before the commit, because the positive fixture could NOT be reached with the existing
fuzzer -- in accordance with the project rule "(a sim-review finding must be provably
reproduced in simulation)", we do not commit an oracle without a live positive proof.

**What was done and what is proven**:
- The gap in the CODE is real: the existing binary on the new fixture
  `tests/evm/donation_non4626/` (a Vault without `totalAssets()`/`totalSupply()`, which
  prices through `asset.balanceOf(address(this))`) does NOT report a donation attack --
  only `Stale Guard Counter` / `Reentrancy` / `Zero Address Setter`. So `erc4626.rs`
  (which requires `totalAssets()`) really does not cover this.
- A deterministic two-part latch was implemented in `host.rs`: `T.balanceOf(C)` where C
  is the contract itself (`current_self_token_reads`) AND `T.transfer(X,...)` where the
  caller is not X (`current_token_donations`); the oracle fires when the same `(C, T)`
  pair is in both.
- **Why it could not be proven live**: both latches fill (confirmed with
  instrumentation: `self_read` 144x, `donation` 3x), but the fuzzer directs the donation
  to RANDOM addresses, not to the vault; `Vault.setAsset()` + `deposit()` + a foreign
  `Token.transfer(vault,...)` in the right sequence is not reached in reasonable time.
  The existing `erc4626` oracle has the same limitation -- on ITS OWN fixture
  `tests/evm/erc4626/` it likewise does NOT fire (only Stale Guard, etc.), which confirms
  that this is a harness limitation (multi-step cross-contract wiring), not specific to
  D4.

**Conclusion**: D4 remains a gap, but it first requires a harness improvement (a directed
call sequence / a seed corpus with `setAsset` set), and only then an oracle. The proposed
order: D6 (7702/4337) or harness work, not D4.

---

## Harness improvement #2 (2026-11-05): biasing the address pool -- DONE

Implemented and committed (530c1f4): `state.rs` gains `contract_addresses_pool` (filled
ONLY from `add_contract_address`, which `corpus_initializer.rs` and `onchain/mod.rs`
call), and `get_rand_address` prefers these addresses 75% of the time (mirroring the
existing `get_rand_caller_excluding`). The remaining 25% + the "no contract yet" case
stays uniform, so a fresh EOA/`0x0`/third parties are not starved.

**Measured live** (instrumentation, `tests/evm/erc4626/` and `donation_non4626/`):
- Before: `addresses_pool` = 34 addresses, of which only 2 were contracts -> arguments
  rarely pointed at contracts.
- After: `contract_addresses_pool = [Token, Vault]`; the Vault actually executes
  `asset.balanceOf(self)`.
- All positive oracles (D1 proxy_upgrade_hijack, D2 unbacked_mint, D3 forged_proof, D5
  transient_guard, reentrancy, eth_backing) still fire; `cargo test` 67/11 == baseline.

**A limitation**: #2 is necessary, but NOT sufficient for D4/erc4626 -- the fuzzer still
does not hit `setAsset(realToken)` + `Token.transfer(vault,...)` in the right sequence.
The next step for D4 is #1 (setup/seed transactions, see above).

The remaining proposed harness improvements (by ROI):
1. **#1 setup.json** (LOW-MEDIUM, the highest ROI): execute declarative initialization
   calls in `initial_state` before fuzzing -- unblocks D4 + erc4626.
3. **#3 correlated cross-contract seeding** (MEDIUM): for each pair (A,B) add
   `A.transfer(B,x)`/`A.approve(B,max)` to the corpus.
4. **#4 a real multi-tx sequence in the input** (HIGH): `EVMInput` -> `Vec<Tx>`;
   invasive (mutator, scheduler, minimizer, executor, serialization).
5. **#5 a semantic donation mutator** (MEDIUM, narrow): when the oracle sees
   `balanceOf(self)`, the mutator injects `transfer(vault, amount)`.

---

## Harness improvement #1 (2026-11-05): `setup.json` seed transactions -- DONE

Implemented and committed: a new module `src/evm/setup.rs` (+ a `setup_spec` field on
`ContractLoader`, a call in `EVMCorpusInitializer::initialize` between
`initialize_contract` and `initialize_corpus`).

**Format** (`tests/evm/<fixture>/setup.json`):
```json
{ "calls": [
  { "to": "Vault", "sig": "setAsset(address)",        "args": ["Asset"] },
  { "to": "Asset", "sig": "mint(address,uint256)",    "args": ["$caller", "1000000000000000000000"] },
  { "to": "Vault", "sig": "deposit(uint256,address)", "args": ["100000000000000000000", "$caller"] }
] }
```

- `to` is the name of a deployed contract (the file stem from the fixture) or
  `$deployer`.
- Arguments of type `address` accept a contract name or `$caller`/`$deployer`; the rest
  are passed to the ABI encoder as literals.
- The signatures are parsed with `alloy_json_abi::Function::parse`, and the arguments
  with `coerce_str` + `abi_encode_input` (existing dependencies, nothing new).
- The calls are executed with `EVMExecutor::fast_call_` on the freshly deployed state;
  each call is best-effort (a revert is logged, never fatal).

**Measured live** (`tests/evm/erc4626/`): without `setup.json` 986k executions -> 0
ERC4626 hits; with `setup.json` a hit in ~1.5M executions (the Vault price-per-share 1e9
-> 1.2e47). This closes the gap that blocked D4 (see above): the harness can now
establish the precondition `setAsset` + `deposit` before fuzzing.

**A limitation**: #1 solves the precondition (wiring), not yet the attack sequence
itself; for full D4 coverage (non-ERC4626 "balance-vs-accounting drift") #5 (a semantic
mutator) or #4 (a real multi-tx sequence) is still needed.
