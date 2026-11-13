# Benchmark: Echidna vs ForkSploit on the same real contract

Comparison of two smart-contract fuzzers on **one and the same deployed
contract** on the ETC **Mordor** testnet.

- **Target (real, verified, deployed):**
  `CyberScratchLottery` at
  [`0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee`](https://etc-mordor.blockscout.com/address/0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee?tab=contract_bytecode)
  (Solidity 0.8.20, OpenZeppelin `ReentrancyGuard`).
- **Tools:** Echidna 2.4.0 (property mode) and ForkSploit
  (`forksploit evm`, Address mode, `-f` flashloan).
- **Budget per tool:** 120 seconds wall clock.
- **Date:** 2026-11-08.

## Why this target

`CyberScratchLottery` is not a toy: it has an owner-only admin surface
(`withdrawFunds`, `setTicketPrice`), an OpenZeppelin `nonReentrant` guard, an
economically meaningful payout loop, and a win/lose decision built from
`keccak256(block.timestamp, block.difficulty, msg.sender)`. That last part is
the classic SWC-120 weak-randomness bug, and it is the contract's *real*
vulnerability.

## How both tools ran on the identical contract

ForkSploit's `--target <address>` (Address mode) fetches the live bytecode and
ABI and fuzzes the real dispatcher -- no reimplementation.

Echidna cannot fuzz an address directly, so it runs a **property harness**
(`target/LotteryEchidna.sol`) that only *wraps* the real contract: it deploys
`CyberScratchLottery` unchanged and exposes `buyTicketExact()` (which pays the
exact `ticketPrice()`, because Echidna's value fuzzer almost never hits the
exact price the real `require(msg.value == ticketPrice)` demands). No game
logic is reimplemented; every state change goes through the real code.

Both tools ran against the Mordor state: Echidna on a local deployment of the
verified source, ForkSploit against the live deployed instance via an Anvil
fork of Mordor (`--fork-url https://rpc.mordor.etccooperative.org`).

## Results

| | Echidna 2.4.0 | ForkSploit (`30b7e96`) |
|---|---|---|
| Target | CyberScratchLottery (verified source, local deploy) | `0x1FD0769...D2Ee` (live bytecode + ABI, Anvil fork) |
| Budget | 120 s | 120 s |
| Executions | 1,454,000 calls | 496,702 execs (single client) |
| Weak randomness (SWC-120) | **found** (`echidna_randomness_not_publicly_predictable` falsified) | **found** (`[Weak Randomness]`, 6-8 hits) |
| Fund loss / drainability | not expressed | **found** (`[Fund Loss] sim-confirmed`, 6-9 hits) |
| Other findings | — | Arbitrary Storage Write, Integer Overflow, Stale Guard Counter, Unbounded Loop, Zero Address Setter |

Reproduced on a second independent run (same budget): both tools again found
the weak-randomness bug (Echidna falsified the property; ForkSploit reported
`[Weak Randomness]` and `[Fund Loss]`). Exact finding counts differ run to run
(ForkSploit 6-9 Fund Loss / 6-8 Weak Randomness hits; Echidna 1.33M-1.45M
calls) but the headline result -- both tools surface the real SWC-120 bug --
is stable.

**Both tools independently flagged the same real vulnerability: the
predictable randomness** that decides win/lose from public block data. That
agreement on a real target is the point of the benchmark -- it is not a
contrived "green" result.

### What each tool adds

- **Echidna** gives a minimal, reproducible counterexample: the property is
  falsified in a one-call sequence (a block whose public inputs already decide
  "win"), i.e. it proves the property *false* with the smallest witness.
- **ForkSploit** needs no property written by hand. From raw bytecode it
  independently fingerprints the weak-randomness pattern (SWC-120), and it
  additionally reports an economic `[Fund Loss]` finding, storage-write and
  overflow smells. It runs straight against the deployed address, so it needs
  neither the source nor a harness.

### Honest limits of this benchmark

- The two tools do not measure the identical quantity: Echidna's counterexample
  proves a *user-written* property false, while ForkSploit's findings are its
  own heuristics (`sim-review` for Weak Randomness, `sim-confirmed` for Fund
  Loss). The comparison is "did each tool surface the contract's real bug on
  the same target in the same budget", not "identical internal metric".
- Echidna's execution count (calls) and ForkSploit's (executions) are not the
  same unit and are reported side by side only for scale.
- The payout-solvency property (`echidna_payouts_within_revenue`) is **not**
  violated: the real contract's `require(address(this).balance >= prizeAmount)`
  keeps it solvent, so that property passes in both runs. It is included to
  show the negative result honestly rather than to pad the score.

## Reproduce

```bash
# prereqs: foundry (anvil, cast), echidna, solc 0.8.24, cargo build --release
benchmarks/echidna_vs_forksploit/run_benchmark.sh
```

Raw logs from the recorded run are `forksploit_run.log` and
`echidna_run.log`.
