# ForkSploit — a full run directly against live Mordor (no anvil fork)

Goal: the **full** ForkSploit (all capabilities) on **exactly this contract** and
**exactly this network**, as required — no anvil fork, directly against the public
Mordor RPC.

- Contract: `CyberScratchLottery`
  `0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee`
- Network: ETC Mordor, `https://rpc.mordor.etccooperative.org` (chainId 63)
- Block: `17353046` (`0x108c9dd`)
- Target bytecode: 4427 B (`eth_getCode`)

## Command (the full run)

```bash
./target/release/forksploit evm \
  -t 0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee \
  -c mordor -u https://rpc.mordor.etccooperative.org \
  --spec-id Shanghai \
  --concolic --concolic-caller --concolic-num-threads 3 \
  -f \
  --jobs 3 --fuzz-seconds 300 \
  --invariants benchmarks/forksploit_full_live_mordor/invariants.json \
  --auto-setup --run-forever \
  -w <workdir>
```

Enabled: concolic + concolic-caller, flashloan (`-f`), 3 parallel workers (the
concolic cap shared: `--concolic-num-threads 1` per worker), invariants,
auto-setup, `--run-forever`, the Shanghai spec (ETC Mordor).

## Reproducibility (R1)

Two **independent** runs with different seeds (`1667840158231589000` and
`987654321`), 300 s each, 3 workers:

| Run | Executions | Files found | Set of finding types |
|-----|-----------|------------------|---------------------|
| 1 | 385,865,153 | 91 | 9 types |
| 2 | 430,108,236 | 103 | **the same 9 types** |

The set of finding types is **100% reproducible** across the two runs.

## Truth vs. noise — checked against the verified source

The installed bytecode **matches** the verified source (`deployed_bytecode` from
Blockscout == `eth_getCode`, 4427 B, solc 0.8.20+commit.a1b79de6, optimization
**off**). So every finding can be checked directly.

Source: `CyberScratchLottery.sol` (stored in this directory). Key point: the
source has **no** `ecrecover`, `unchecked` or `assembly`.

| # | Finding (tier) | Verdict | Evidence |
|---|---------------|---------|-------|
| 1 | **Weak Randomness** (sim-review) | **REAL** | source: `keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)) % 100` (SWC-120); pc 2084 |
| 2 | Centralization Risk (sim-review) | real, by design | `onlyOwner` on `withdrawFunds`/`setTicketPrice` |
| 3 | **Invariant Violation** (sim-confirmed) | **FALSE POSITIVE** | the operand `native_balance` in Address mode reads `post_state.balance[target]` = 0 (`contract_utils.rs:820`); the live balance is 1.06e19. `rhs=0` → the invariant trivially fails. On-chain `totalPayouts(1.3e18) <= balance(1.06e19)` HOLDS |
| 4 | **Fund Loss** (sim-confirmed) | **misleading / FP** | trace: `withdrawFunds()` calls **the owner** (slot 1 = `0xfF0f5263…`), so a privileged withdrawal by design, not "anyone can earn" |
| 5 | **Arbitrary Storage Write** (sim-confirmed) | **FALSE POSITIVE** | pc 962 = `PUSH1 0x02; … SSTORE` → the slot is a **constant 2** (`ticketPrice`), not attacker-chosen. It fires because the argument `setTicketPrice(2)` coincides with the constant slot index |
| 6 | **Unchecked ecrecover(0)** (sim-confirmed) | **FALSE POSITIVE** | the source has no `ecrecover`. Trace: `[Sender] 0x…01` → `buyTicket` → `payable(msg.sender).call{value:…}` targets `0x…01` (the ecrecover precompile address), because the fuzzer uses `0x01` as a caller |
| 7 | **Integer Overflow** (sim-review) | **FALSE POSITIVE** | pc 2616 = the ReentrancyGuard `_status == ENTERED` comparison (selector `0x3ee5aeb5`); pc 3666 = a compiler checked-math helper. Solidity 0.8.20 has checked arithmetic, and the source has no `unchecked` |
| 8 | **Zero Address Setter** (sim-review) | **FALSE POSITIVE** | pc 962, slot 2 = `ticketPrice` (a number, not an address). `setTicketPrice(0)` writes 0 into a numeric slot that, because of its small value, is "address-shaped" |
| 9 | **Stale Guard Counter** (sim-review) | benign | the guards read `_status` (slot 0), `winProbability` (slot 5 = 65) — constant by design |
| 10 | **Unbounded Loop** (sim-review) | benign | `getWinners(count)`: the loop is bounded by the caller's `count`, not by `winners.length` |

## Conclusion

- **One real bug**: Weak Randomness (SWC-120) — confirmed by the source and
  independently by Echidna.
- **8 additional "findings"** at the `sim-confirmed`/`sim-review` level are, in
  this run, **false positives or misleading labels** (6 FP + 2 benign
  heuristics), checked against the verified code.

This is an honest, measured result of the **full** pipeline on a live chain. An
earlier "minimal" comparison reported only a subset (Weak Randomness + Fund Loss)
and therefore **underestimated** the noise; the full run shows that the oracles
at the `sim-confirmed` level produce several false positives that must be checked
by hand.

Limitation of this environment: the `--invariants` operand `native_balance` in
Address mode is not populated with the live balance (item 3) — that is a tool bug,
not a target bug.

## Artifacts

- `run1_*.log`, `run2_*.log` — raw worker logs (both runs)
- `run{1,2}_supervisor.log` — the supervisor (finding merging)
- `CyberScratchLottery.sol` — the verified source
- `invariants.json` — the invariants used
- `runtime_disasm.txt` — a disassembly of the installed bytecode
