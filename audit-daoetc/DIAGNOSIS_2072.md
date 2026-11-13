# Diagnosis: "2072 plans, 0 confirmed" is not a pipeline bug — it is correct behaviour

Date: 2026-11-07. Source: a live `./forksploit.sh` run on the ETC mainnet target
`0x9f5304DA62A5408416Ea58A17a92611019bD5ce3` + local reproduction.

## Short answer

The pipeline is **not broken**. ForkSploit **behaved exactly as designed**: it
found 1201–2072 "findings", but **none is an executable exploit**, so it
correctly labelled all 2072 as `SKIPPED, NOT EXTRACTABLE`. That is an **absence of
a result, not an error**.

## What is actually in those 2072 plans (reproduction)

I reproduced the exact command from the pipeline (`-d all --concolic
--run-forever`) and got **1201 plan.json** files. Breakdown:

| Category | Count | Meaning |
|---|---|---|
| `confirmed_exploitable = false` (Review-tier) | **1191 / 1201** | "Stale Guard Counter", "Unchecked Call" ... heuristics; no oracle saw a movement of funds |
| `sim-confirmed`, but `atomic_replayable = false` | **10 / 1201** | the finding relied on a **control leak** (the fuzzer invented a call return value) |
| plans with `confirmed_exploitable=true` AND `atomic_replayable=true` AND only on the target | **0** | nothing executable |

In addition: of the 1201 plans, **1190 involve THIRD-PARTY contracts** (not the
target):
- `0xe79aca5C...` (755×) = a **Gnosis-style multisig** = the **OWNER of the target** (slot 0)
- `0x87af33960b...` (633×) = the target's **escapeAddress** (slot 8)
- `0x180826b054...` (18×) = the target's **ledger** (slot 1)

## Root cause (two, both "by design")

### 1. The fuzzer deliberately "borrows" the owner's address as the attacker
`src/evm/host.rs` on `SLOAD` **collects concrete addresses from storage** into the
caller pool (including the `owner` from slot 0). The rationale in the code is
legitimate: without it the fuzzer would never reach `owner`-gated code. **But**
that means the fuzzer calls `escapeHatch()` (`0x1554611f`,
`require(msg.sender==owner)`) **as the owner** — and reports it as "Fund Loss".

**That is a false positive.** Verified on a fork:
```
escapeHatch  as OWNER   -> OK      (fires, because it really is the owner)
escapeHatch  as RANDOM  -> REVERT  (InvalidJump)
```
The fuzzer did not "break in" — it simply was the owner. `escapeHatch` is an
**intentional** function, not a vulnerability.

### 2. The control leak disables every atomic replay
The 10 "sim-confirmed" findings (`Fund Loss`, `Unchecked ecrecover(0)`) have
`call_leak != u32::MAX` → `atomic_replayable=false` + `requires_control_leak=true`.
The fuzzer reached a deeper path by **inventing the return value** of an inner
call; `AttackWallet` **cannot replay that** on the real chain. Hence
`distinct_callers > 1` (2–18 distinct `msg.sender`).

## Why "0 confirmed" is the correct outcome

`calculateWithdraw` requires `ledger.balanceOf(a) >= S*T/totalDeposits`. The
ledger (slot 1) has **totalSupply but zero balances** (confirmed in a previous
session: `5db8ca1`). So **no profit can be extracted** until the ledger state
changes. The pipeline correctly works this out and **sends no real transaction** —
which is exactly a security property, not a bug.

## What this means for the target (the actual audit conclusion)

- `escapeHatch`, `claimRemaining`, `transferOwnership` — owner-only, **not**
  vulnerabilities.
- The only real weakness: **`proxyWithdraw` does not check `signer != 0`** (in the
  reconstruction). But even that leads to `_withdraw(0x0, ...)`, where
  `calculateWithdraw(0x0)` = 0 (because `ledger.balanceOf(0x0)` = 0) → **no
  profit**.
- **Conclusion: the target is currently not exploitable**, because the ledger is
  empty. That is an economic property, not a fuzzer limitation.

## What (if anything) to fix

1. **Do not** "fix" the fuzzer using the owner's address — it is deliberate and
   useful. Instead, it would be worth **tagging** findings where the only
   "attacker" is the target's `owner`: add `owner_impersonation: true` to
   `plan.json`, so the Python layer separates such findings from the real ones.
2. **Do not** lower the `MIN_STREAK_OF_INTEREST` threshold — the 1191 Stale Guard
   findings are noise, but the threshold is already conservative (6 consecutive
   calls).
3. If you want **real** findings on this target, you must first **fill the
   ledger** (an economic precondition), not change the fuzzer.

## Reproduction

```bash
anvil --fork-url https://etc.etcdesktop.com --chain-id 61 \
      --gas-limit 8000000 --hardfork shanghai --port 8545
./target/release/forksploit evm \
  -t '0x9f5304DA62A5408416Ea58A17a92611019bD5ce3' --target-type address \
  -c etc -u http://localhost:8545 -f -d all -w /tmp/wd --run-forever \
  --concolic --concolic-caller --spec-id Shanghai
# -> /tmp/wd/vulnerabilities/*.plan.json : 1201 plans, 0 executable
```
