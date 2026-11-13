# ForkSploit + DAOETC — full status, findings and plan

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it.**

Date: 2026-11-07 · Target: `0x9f5304DA62A5408416Ea58A17a92611019bD5ce3` (Ethereum Classic, chainId 61)

---

## 1. WHAT WE ARE ACTUALLY DOING (purpose)

**Project goal:** verify whether ForkSploit (an EVM fuzzer/exploit-synthesis tool)
produces **REAL exploit paths**, and not just "evidence" that does not hold up on
the real chain. The goal is to determine which of the found "surfaces" (leak
surfaces) can be **materialized** — i.e. replace a faked (leak/control-leak) call
with real on-chain state, so that the transaction actually moves funds.

**The concrete target:** the "DAOETC" contract on ETC mainnet, which ForkSploit
flagged as the most promising (all 19–23 materialization surfaces are on it).

**The question we answer:** Does any of the found exploits actually drain the
contract? (Yes/No — with proof, not with a guess.)

---

## 2. WHAT FORKSPLOIT IS (the tool)

Rust (LibAFL + a fork of revm) + a Python pipeline in `onchain_scripts/`.

Key components:
- **Fuzzer** (Rust): generates "plans" (sequences of calls) and finds passages
  through `require` via a **control leak** (faking a value, e.g. `balanceOf`).
- **`triage_findings.py`** — sorts findings into three tiers:
  `RUNNABLE`, `NEEDS_MATERIALIZATION`, `HEURISTIC_ONLY`.
- **`materialize_plan.py`** — turns `NEEDS_MATERIALIZATION` findings into a
  working list of recipes (which class: `TOKEN_BALANCE`, `AUTH_GUARD`,
  `SIGNATURE`, `STORAGE_READ`, `NATIVE_UNWRAP` …) and says what would need to be
  done.
- **`auto_pipeline.py` / `batch_pipeline.py`** — tie it all together.

**Key concept:** the fuzzer finds a passage through `require` by **faking** (a
leak of) the value that `require` checks. Such a finding is NOT an exploit — it is
a **hypothesis** that with the right state the passage would exist. The
materialization layer says how to reach that state.

---

## 3. WHAT THE TARGET IS (DAOETC) — reconstructed from bytecode

The runtime bytecode (2319 B) was disassembled with `pyevmasm`; the whole logic
was read. The reconstructed Solidity is in `/workspace/audit/DAOETC_reconstructed.sol`.

**State (slots):**
| slot | content | on-chain value |
|------|---------|--------------------|
| 0 | `owner` | `0xe79aca5C8cDa44d834efa969906A377Cb987E02E` |
| 1 | `ledger` (ILedger) | `0x180826b05452ce96e157f0708c43381fee64a6b8` |
| 2 | `balances` (mapping) | all 0 for the checked addresses |
| 3 | `used` (signature replay) | — |
| 4 | `totalDeposits` | — |
| 5 | `closingTime` | (= the timestamp at deploy) |
| 6 | `extension` | `0xdd7c00` = 14,515,200 s (168 days) |
| 7 | `whgDonationAddress` | `0xe79aca…` (owner) |
| 8 | `escapeAddress` | `0x87af33960b633469d2524883027b777a433bc11b` |
| 9 | `claimAddress` (+ bit 0xa0 = `sealed`) | `0xe79aca…`, **sealed = TRUE** |

**Functions (selector → name):**
| selector | name | access |
|----------|-----|--------|
| 0x02ef6c86 | `calculateWithdraw(address)` | view |
| 0x1554611f | `escapeHatch()` | **owner** |
| 0x3e2640d6 | `extendClosingTime(uint256)` | **owner** |
| 0x3fb27b85 | `seal()` | **owner** |
| 0x57211ac0 | `getPaidOut(address)` | view |
| 0x64dab283 | `getWHGDonationAddress()` | view |
| 0x7e3ef7cd | `getMyBalance(address)` | view |
| 0x884b5dc2 | `fill(uint256[])` | **owner && !sealed** (see §5) |
| 0x893d20e8 | `getOwner()` | view |
| 0xa6f9dae1 | `transferOwnership(address)` | **owner** |
| 0xc01c1ca3 | `claimRemaining()` | timelock |
| 0xd0e30db0 | `deposit()` | public (payable) |
| 0xe3ce9714 | `proxyWithdraw(address,uint256,uint8,bytes32,bytes32)` | public |
| 0xeb8bbd28 | `getTotalFunds()` | view |
| 0xf3fef3a3 | `withdraw(address,uint256)` | public |

**CORRECTION (important):** all "payable" functions have `require(msg.value ==
0)`, NOT `> 0`. Empirically: `escapeHatch` with `value=0` → OK, with `value=1` →
REVERT. (My earlier notes had this backwards.)

**The final payout formula** (`calculateWithdraw`):
```
B = ledger.balanceOf(a)
T = ledger.totalSupply()          // 1.153e25
S = balances[a]
amount = S * T / totalDeposits    // a share of the supply
if (B < amount) amount = 0        // THE CAP
return amount
```
and `_withdraw`:
```
amt = calculateWithdraw(user)
if (amt > address(this).balance) amt = address(this).balance
balances[user] += amt
fee = amt * 100 / FEE_DENOM       // fee
whgDonationAddress.call.value(fee)("")
to.call.value(amt - fee)("")
```

**The `proxyWithdraw` bug (the only confirmed bug):**
```solidity
address signer = ecrecover(h, v, r, s);   // NO check that signer != 0
```
→ a forged signature SUCCEEDS (status 1), but `_withdraw(signer=0, …)` pays out 0.

---

## 4. WHAT IS PROVEN (with evidence, not guesses)

All verified on an **anvil fork of ETC** and/or with `eth_call` on a public RPC
(never a mainnet tx).

1. **`withdraw(address,uint256)` SUCCEEDS** at 8M gas (status 1, 37064 gas) —
   the earlier "OOG" was due to too little gas (3M). ETC block limit = 8M.
2. **But it pays out 0**, because `balanceOf(user)` = 0 and `balances[user]` = 0.
3. **`deposit()` takes ETH but does NOT credit `balances[msg.sender]`** — only
   `totalDeposits += msg.value`. So deposit → withdraw returns 0.
4. **The ledger `0x180826…` has `totalSupply` = 1.153e25 and `totalAccounts` =
   22092, but `balanceOf` = 0 for EVERY checked address** (owner, WHG, slot8, the
   target, 0x0). Its `balanceOf(a)` reads `storage[keccak(a, slot0)]` (confirmed
   by a trace).
5. **`sealed` = TRUE** on both contracts.
6. **`fill()` is NOT callable**: it reverts for a random caller AND for the owner,
   with `value=0` and `value=1`. The lock: `fill` is allowed only for the owner
   **before** `seal()`. Since `sealed=true`, `fill` is permanently dead → balances
   cannot be loaded.
7. **In the successful paths there is NO value transfer:** only 3 CALLs with
   `value=0` (ecrecover, balanceOf, totalSupply), `SELFDESTRUCT=0`, `CREATE=0`,
   `STOP`.
8. **Access control test:** the RPC **honours `from`** (`transferOwnership` and
   `escapeHatch`: owner → OK, random → REVERT). So the access tests are valid.

**Conclusion:** all 19–23 real surfaces are, in the contract's current state,
**structurally unexploitable**. The only confirmed bug (`Unchecked ecrecover(0)`)
does not by itself move funds. This is also a **limitation of the fuzzer**: the
control leak faked a `require` that the real chain does not satisfy.

---

## 5. WHAT STILL NEEDS TO BE DONE / VERIFIED

### A) On ForkSploit (the tool)
- [ ] **Confirm the tier-filter fix** (already committed: `df12879`) — the
      worklist must count ONLY `NEEDS_MATERIALIZATION`. User output: 23 surfaces
      / 5870 plans ✓.
- [ ] **`--lookup`** (already committed: `1bfd775`) — works (4byte + User-Agent).
- [ ] **Materialization of the `TOKEN_BALANCE` recipe** — currently the recipe
      says "supply the tokens"; we must **verify that for this target it is
      physically infeasible** and build that in as a warning (because `fill` is
      not callable and `balanceOf` is 0). → Add "dead-end" detection.
- [ ] **Extend `AUTH_GUARD` detection** — 9/19 surfaces are `AUTH_GUARD`
      (owner-only); the tool should tag them `NEEDS_PRIVILEGE` and **not suggest**
      materialization.
- [ ] **Optional: Rust `armCallback`** — allow replaying an arbitrary call in a
      reentrancy window. **It does not solve this target** (the payout is 0), but
      it is a real improvement for other targets. Low priority for DAOETC.

### B) On the bytecode / target
- [ ] **Find whether the ledger's `balanceOf` is non-zero for any of the 22092
      accounts.** If an address with `balanceOf > 0` exists, the `TOKEN_BALANCE`
      recipe might materialize. Candidates: addresses from `fill` transactions
      (on-chain logs).
- [ ] **Check the ledger's `fill()` access** — if it is callable under some
      condition (e.g. `owner || sealed` with different logic), that would open a
      path. (So far: it reverts for everyone.)
- [ ] **Check `claimRemaining()`** — timelock `closingTime + extension`. If `now
      >= closingTime + 0xdd7c00`, **anyone** can trigger a transfer of the whole
      balance to `claimAddress` (= the owner!). This is not an exploit (it goes
      to the owner), but it must be recorded.

### C) Where we stopped
- Target bytecode analysis: **DONE** (all functions and the formula are known).
- Empirical verification on a fork: **DONE** (payout 0, fill dead).
- Documentation: **THIS DOCUMENT** + `DAOETC_reconstructed.sol` in `/workspace/audit/`.
- Sandbox: `/tmp` is reset → work saved in the **persistent `/workspace`**.

### D) How to continue (concrete steps)
1. `cd /workspace/audit && cat AUDIT_STATUS.md` (this document).
2. To continue the bytecode analysis: `python3 probe*.py` (read-only, public RPC).
3. For fork tests: `foundryup` → `anvil --fork-url https://etc.etcdesktop.com
   --chain-id 61 --gas-limit 8000000 --hardfork shanghai`.
4. **The next concrete step:** find whether an address with `ledger.balanceOf > 0`
   exists (via the `fill` logs on-chain). If NO → the target is definitively
   closed. If YES → materialize the `TOKEN_BALANCE` recipe.
5. An alternative with more potential: **point ForkSploit at ANOTHER target** from
   the `HEURISTIC_ONLY` surfaces, where materialization may be feasible.

---

## 6. NOTE ON THE SANDBOX

`/tmp` is on a **non-persistent** overlay — it is wiped on restart (which is why
`/tmp/ForkSploit` and Foundry disappeared several times). **`/workspace` is
persistent** (`/dev/nvme0n2`, 25 GB). All work must be saved in `/workspace`. The
disk is not full (61 GB free, 2% inodes) — the issue was purely the
non-persistence of `/tmp`.

---

## 7. FIXED: panics in the concolic module (2026-11-07)

Commit `8e6a572`. Every reachable `panic!`/`expect`/`unwrap` in the concolic path
is replaced with **graceful degradation** — an unsupported opcode or an
unexpected symbolic shape can no longer crash the whole fuzz run.

| Place | Before | Now |
|-------|------|-----|
| `expect_bv`/`expect_bool` | `panic!` | concrete 0 / false |
| `push_ctx` unsupported opcode | `panic!` | empty input slice |
| `pop_ctx` empty ctx | `panic!` | reset the symbolic frame |
| `get_input_slice_from_ctx` | `expect("no ctx")` | a zero slice |
| `on_step` opcode match | `panic!("Unsupported opcode")` | log + skip (0x0c-0x0f, 0x1e-0x1f, 0x21-0x2f, 0x49-0x4f, 0x5c-0x5d, 0xf6-0xf9, 0xfb-0xfc) |
| `ALREADY_SOLVED` RwLock | `expect("concolic crashed")` | `into_inner()` (poison resistance) |
| `ALL_WORKER_THREADS`/`ALL_SOLUTIONS`/`SOURCE_MAP_PROVIDER` | `.unwrap()` | `into_inner()` |
| `ConcolicHost::new` without an ABI | `expect` | empty input |
| `concolic_stage` metadata/corpus | `.unwrap()`/`.expect` | skip |

**Evidence (all with `cargo build --release` EXIT 0):**
- `concolic-1`: solves the constraint, finds the vulnerability, **0 panics**.
- `concolic-2`, `concolic-origin`: **0 panics**.
- `concolic-for`: **0 panics**, 4.1M executions @ 14.7k exec/s.
- **DAOETC target** (anvil fork of ETC, chainId 61): **0 panics**, corpus 23–25
  (= your 23 surfaces). Finding: `Integer Overflow: Unchecked MUL at :1029` →
  exactly `S * T / totalDeposits` in `calculateWithdraw`.

**Remaining (not a crash, but depth):** `concolic-for` did not find the bug in
4.5 min — that is a question of solving power (Z3 timeout 1000 ms), not a panic.
