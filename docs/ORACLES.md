# ORACLES — catalogue of oracles and bug types

> Standalone document. Related: [RUST_CORE.md](RUST_CORE.md),
> [PLAN_JSON.md](PLAN_JSON.md), [RUST_PYTHON_WIRING.md](RUST_PYTHON_WIRING.md).

An oracle is a module that observes execution during fuzzing and, on a hit,
returns a `bug_idx` and writes an `EVMBugResult` into `ORACLE_OUTPUT`. Every
oracle implements the `Oracle` trait (`src/oracle.rs`). The `bug_idx` values are
constants in `src/evm/oracles/mod.rs`.

---

## 1. How an oracle is connected to the fuzzer

* The list of oracles is built in `src/evm/mod.rs::evm_main` according to
  `OracleType::from_strs(args.detectors)` and stored in `Config::oracle`.
* `src/fuzzers/evm_fuzzer.rs::evm_fuzzer` starts with `let mut oracles =
  config.oracle;` and then adds oracles tied to individual flags
  (`state_comp_oracle`, `math_calculate_oracle` → `IntegerOverflowOracle`,
  `delegatecall_injection_oracle`, `ecrecover_zero_oracle`,
  `arbitrary_storage_write_oracle`, `token_accounting_mismatch_oracle`,
  `forced_eth_accounting_oracle`, `readonly_reentrancy_oracle`,
  `storage_collision_oracle`, `delegatecall_target_oracle`,
  `uninitialized_memory_oracle`, `unchecked_call_oracle`,
  `unbounded_loop_oracle`, `stale_guard_oracle`, `self_referral_oracle`,
  `tx_origin_oracle`, `zero_address_setter_oracle`, `gas_stipend_oracle`,
  `weak_randomness_oracle`, `precision_loss_oracle`, `revert_in_loop_oracle`,
  `assert_violation_oracle`, `arbitrary_external_call`, `typed_bug`,
  `selfdestruct_oracle`, `reentrancy_oracle`).
* An oracle fires via `OracleFeedback` (`src/oracle.rs`) after every
  transaction.
* The `oracle_should_skip!` macro checks `BugMetadata::known_bugs`, so the same
  hit is not repeated.

---

## 2. The `--detectors` presets

`OracleType::from_strs` (`src/evm/mod.rs`) supports:

* `all` — all 47 types (including `Invariant`).
* `high_confidence` — a narrower list. It contains: ERC20, Pair, Reentrancy,
  ArbitraryCall, TypedBug, SelfDestruct, Erc4626, AccessControl,
  SignatureReplay, SignatureMalleability, NftTransfer, ProxyIntegrity,
  ProxyUpgradeHijack, ArbTransfer, DelegatecallInjection, EcrecoverZero,
  ArbitraryStorageWrite, StorageCollision, DelegatecallTarget, TxOrigin,
  InitializerFrontRun, PreviewRounding, EthBacking, SelfReferral.
* A comma-separated list of names from `OracleType::as_str` (e.g.
  `--detectors reentrancy,access_control`).
* An unknown name → `panic!("Invalid detector type: {}", s)`.

---

## 3. Catalogue of oracles

The "bug_type" column lists the string(s) the oracle writes into
`EVMBugResult`. The "level" column is the result of
`oracle.rs::classify_confidence` for that bug_type.

| # | bug_idx constant | Module | `OracleType` | bug_type | level |
|---|-------------------|-------|--------------|----------|------|
| 0 | `ERC20_BUG_IDX` | `erc20.rs` | `erc20` | `Fund Loss` | Confirmed |
| 2 | `V2_PAIR_BUG_IDX` | `v2_pair.rs` | `pair` | `Imbalanced Uniswap Pair` | Confirmed |
| 4 | `TYPED_BUG_BUG_IDX` | `typed_bug.rs` | `typed_bug` | `Bug` | Confirmed |
| 5 | `SELFDESTRUCT_BUG_IDX` | `selfdestruct.rs` | `selfdestruct` | `Selfdestruct` | Confirmed |
| 7 | `STATE_COMP_BUG_IDX` | `state_comp.rs` | `state_comparison` | `state_comp` | Review |
| 8 | `ARB_CALL_BUG_IDX` | `arb_call.rs` | `arbitrary_call` | `Arbitrary Call` | Confirmed |
| 9 | `REENTRANCY_BUG_IDX` | `reentrancy.rs` | `reentrancy` | `Reentrancy` | Confirmed |
| 11 | `INTEGER_OVERFLOW_BUG_IDX` | `overflow.rs` | `math_calculate` | `Integer Overflow` | Review |
| 12 | `ERC4626_BUG_IDX` | `erc4626.rs` | `erc4626` | `ERC4626 Share Inflation` | Confirmed |
| 13 | `ACCESS_CONTROL_BUG_IDX` | `access_control.rs` | `access_control` | `Unauthorized Owner Change`, `Unauthorized Pause Toggle`, `Unauthorized Proxy Upgrade` | Confirmed |
| 14 | `SIGNATURE_REPLAY_BUG_IDX` | `signature_replay.rs` | `signature_replay` | `Signature Replay` | Confirmed |
| 15 | `NFT_TRANSFER_BUG_IDX` | `nft_transfer.rs` | `nft_transfer` | `Unauthorized NFT Transfer`, `Unauthorized ERC1155 Transfer` | Confirmed |
| 16 | `PROXY_INTEGRITY_BUG_IDX` | `proxy_integrity.rs` | `proxy_integrity` | `Proxy Reinitialization`, `Proxy Storage Collision` | Confirmed |
| 17 | `ARB_TRANSFER_BUG_IDX` | `arb_transfer.rs` | `arb_transfer` | `Unauthorized ERC20 Transfer` | Confirmed |
| 18 | `DELEGATECALL_INJECTION_BUG_IDX` | `delegatecall.rs` | `delegatecall_injection` | `Delegatecall Injection` | Confirmed |
| 19 | `ECRECOVER_ZERO_BUG_IDX` | `ecrecover.rs` | `ecrecover_zero` | `Unchecked ecrecover(0)` | Confirmed |
| 20 | `STORAGE_COLLISION_BUG_IDX` | `storage_collision.rs` | `storage_collision` | `Storage Collision` | Confirmed |
| 21 | `DELEGATECALL_TARGET_BUG_IDX` | `delegatecall_target.rs` | `delegatecall_target` | `Delegatecall Target From Calldata`, `Delegatecall Target From Calldata (Unconfirmed)` | first Confirmed, second Review |
| 22 | `UNINITIALIZED_MEMORY_BUG_IDX` | `uninitialized_memory.rs` | `uninitialized_memory` | `Uninitialized Memory Read` | Review |
| 23 | `UNCHECKED_CALL_BUG_IDX` | `unchecked_call.rs` | `unchecked_call` | `Unchecked Low-Level Call` | Review |
| 24 | `TX_ORIGIN_BUG_IDX` | `tx_origin.rs` | `tx_origin` | `Tx.Origin Phishing Bypass` | Confirmed |
| 25 | `INITIALIZER_FRONT_RUN_BUG_IDX` | `initializer_front_run.rs` | `initializer_front_run` | `Initializer Front-Running` | Confirmed |
| 26 | `CENTRALIZATION_RISK_BUG_IDX` | `centralization_risk.rs` | `centralization_risk` | `Centralization Risk: Owner-Only Function` | Review |
| 27 | `SIGNATURE_MALLEABILITY_BUG_IDX` | `signature_malleability.rs` | `signature_malleability` | `Signature Malleability` | Confirmed |
| 28 | `CURVE_VIRTUAL_PRICE_BUG_IDX` | `curve_virtual_price.rs` | `curve_virtual_price` | `Curve Virtual Price Decrease (Profit Confirmed)` / `Curve Virtual Price Decrease` | first Confirmed, second Review |
| 29 | `PRICE_FEED_STALENESS_BUG_IDX` | `price_feed_staleness.rs` | `price_feed_staleness` | `Price Feed Staleness` | Review |
| 30 | `TWAP_MANIPULATION_BUG_IDX` | `twap_manipulation.rs` | `twap_manipulation` | `TWAP Manipulation (Profit Confirmed)` / `TWAP Manipulation Precondition` | first Confirmed, second Review |
| 31 | `PREVIEW_ROUNDING_BUG_IDX` | `preview_rounding.rs` | `preview_rounding` | `ERC4626 Rounding Favors User` | Confirmed |
| 32 | `ETH_BACKING_BUG_IDX` | `eth_backing.rs` | `eth_backing` | `Insolvent: Promised Native Value Exceeds Real Balance` | Confirmed |
| 33 | `UNBOUNDED_LOOP_BUG_IDX` | `unbounded_loop.rs` | `unbounded_loop` | `Unbounded Loop` | Review |
| 34 | `STALE_GUARD_BUG_IDX` | `stale_guard.rs` | `stale_guard` | `Stale Guard Counter` | Review |
| 35 | `SELF_REFERRAL_BUG_IDX` | `self_referral.rs` | `self_referral` | `Validation-Independent Payment` | Confirmed |
| 36 | `ARBITRARY_STORAGE_WRITE_BUG_IDX` | `arbitrary_storage_write.rs` | `arbitrary_storage_write` | `Arbitrary Storage Write` | Confirmed |
| 37 | `TOKEN_ACCOUNTING_MISMATCH_BUG_IDX` | `token_accounting_mismatch.rs` | `token_accounting_mismatch` | `Token Accounting Mismatch` | Review |
| 38 | `FORCED_ETH_ACCOUNTING_BUG_IDX` | `forced_eth_accounting.rs` | `forced_eth_accounting` | `Forced Native Value Accounting` | Review |
| 39 | `READONLY_REENTRANCY_BUG_IDX` | `readonly_reentrancy.rs` | `readonly_reentrancy` | `Read-Only Reentrancy` | Review |
| 40 | `ZERO_ADDRESS_SETTER_BUG_IDX` | `zero_address_setter.rs` | `zero_address_setter` | `Zero Address Setter` | Review |
| 41 | `GAS_STIPEND_BUG_IDX` | `gas_stipend.rs` | `gas_stipend` | `Hardcoded Gas Stipend` | Review |
| 42 | `WEAK_RANDOMNESS_BUG_IDX` | `weak_randomness.rs` | `weak_randomness` | `Weak Randomness` | Review |
| 43 | `PRECISION_LOSS_BUG_IDX` | `precision_loss.rs` | `precision_loss` | `Precision Loss` | Review |
| 44 | `REVERT_IN_LOOP_BUG_IDX` | `revert_in_loop.rs` | `revert_in_loop` | `Revert In Loop (DoS)` | Review |
| 45 | `ASSERT_VIOLATION_BUG_IDX` | `assert_violation.rs` | `assert_violation` | `Assert Violation` | Review |
| 46 | `PROXY_UPGRADE_HIJACK_BUG_IDX` | `proxy_upgrade_hijack.rs` | `proxy_upgrade_hijack` | `Unprotected Proxy Upgrade (UUPS)` | Confirmed |
| 47 | `UNBACKED_MINT_BUG_IDX` | `unbacked_mint.rs` | `unbacked_mint` | `Unbacked Mint (Supply Growth Without Backing)` | Review |
| 48 | `FORGED_PROOF_BUG_IDX` | `forged_proof.rs` | `forged_proof` | `Forged Proof (Caller-Supplied Root Accepted)` | Review |
| 49 | `TRANSIENT_GUARD_BUG_IDX` | `transient_guard.rs` | `transient_guard` | `Transient Guard Released Before External Call` | Review |
| 50 | `INVARIANT_BUG_IDX` | `invariant.rs` | `invariant` | `Invariant Violation` | Confirmed |

Notes:

* The level is determined by `oracle.rs::classify_confidence`, which this table
  summarizes. For some types the level is **not** 1:1 with `OracleType`:
  `twap_manipulation` and `curve_virtual_price` each have two bug types (the
  base Review, and "(Profit Confirmed)" Confirmed).
* The `high_confidence` preset contains exactly these `OracleType`s: ERC20,
  Pair, Reentrancy, ArbitraryCall, TypedBug, SelfDestruct, Erc4626,
  AccessControl, SignatureReplay, SignatureMalleability, NftTransfer,
  ProxyIntegrity, ProxyUpgradeHijack, ArbTransfer, DelegatecallInjection,
  EcrecoverZero, ArbitraryStorageWrite, StorageCollision, DelegatecallTarget,
  TxOrigin, InitializerFrontRun, PreviewRounding, EthBacking, SelfReferral.
  All the other oracles (`unbacked_mint`, `forged_proof`, `transient_guard`,
  `readonly_reentrancy`, `token_accounting_mismatch`,
  `forced_eth_accounting`, `zero_address_setter`, `gas_stipend`,
  `weak_randomness`, `precision_loss`, `revert_in_loop`, `assert_violation`,
  `unbounded_loop`, `stale_guard`, `centralization_risk`,
  `price_feed_staleness`, `twap_manipulation`, `curve_virtual_price`,
  `uninitialized_memory`, `unchecked_call`, `math_calculate`) are in `all`, but
  not in `high_confidence`.
* The `Confirmed` level here means **simulation**-confirmed (`sim-confirmed`),
  not confirmed on-chain. That is the dividing line documented in
  [RUST_PYTHON_WIRING.md](RUST_PYTHON_WIRING.md).

---

## 4. Declarative invariant oracle (`--invariants`)

`src/evm/oracles/invariant.rs` lets the user express their own economic
invariant in a JSON file.

Format:

```json
{ "invariants": [
  { "name": "vault solvent",
    "op": "le",
    "lhs": { "sum_over_callers": { "sig": "balances(address)" } },
    "rhs": { "native_balance": true } }
] }
```

Operands:
* `{"native_balance": true}` — the target's real balance;
* `{"literal": "1000"}` — a decimal or `0x` constant;
* `{"call": {"sig": "...", "args": ["$caller", "0x..", "123"]}}` — a static
  call; `$caller` is the transaction caller;
* `{"sum_over_callers": {"sig": "balanceOf(address)"}}` — a call once per
  observed caller, summed.

Operations: `le`, `lt`, `ge`, `gt`, `eq`, `ne`.

A violation is reported as `Invariant Violation` (Confirmed-tier). If the file
cannot be parsed, `evm_main` prints an `error!` and **no** user invariants are
checked (not silently).

---

## 5. Diagram: an oracle's path to plan.json

```mermaid
flowchart LR
    A[evm_main: OracleType::from_strs] --> B[Config::oracle]
    B --> C[evm_fuzzer: oracles]
    C --> D[OracleFeedback after every tx]
    D --> E{oracle returns a bug_idx?}
    E -->|no| D
    E -->|yes| F[EVMBugResult::push_to_output]
    F --> G[ORACLE_OUTPUT]
    G --> H[evaluate_input_events → Solution]
    H --> I[generate_test_with_full_trace]
    I --> J[*.plan.json + *.t.sol]
    I --> K[*.s.sol, if Confirmed + replayable + 1 caller]
```

---

## 6. Open / unmeasured

* **Unverified:** whether the list of Review-tier types is complete with respect
  to all possible strings the oracles write. The table is derived from
  `classify_confidence` and `oracles/*.rs`; for a type not in
  `classify_confidence`, `classify_confidence` defaults to `Review`.
* **Unmeasured:** this document does not state how often an individual oracle
  hits; those are measurements, not part of this document.
* The `state_comp` bug type is literally the string `"state_comp"`, not a
  descriptive name (`src/evm/oracles/state_comp.rs`).
