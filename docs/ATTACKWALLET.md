# ATTACKWALLET — the contract and the execution model (W1–W5)

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it. See [`DISCLAIMER.md`](../DISCLAIMER.md).**

> Standalone document. Related: [DATA_FLOW.md](DATA_FLOW.md),
> [SECURITY_MODEL.md](SECURITY_MODEL.md), [PLAN_JSON.md](PLAN_JSON.md).

Source: `onchain_scripts/contracts/AttackWallet.sol` and its use in
`onchain_scripts/auto_pipeline.py`. Every claim is verified in code.

---

## 1. Why a single contract

`AttackWallet` is the only on-chain primitive the pipeline needs. It is deployed
**once per chain** and reused (`auto_pipeline.py::get_or_deploy_attack_wallet`).
Instead of generating, compiling and deploying a new Solidity contract for each
finding, Python replays `*.plan.json` through this contract.

Reasons (from the docstrings in the code):
* a single, reviewed primitive instead of generated code per finding;
* `safeWallet` is locked, so a compromised `owner` cannot redirect payouts;
* atomicity via `executeBatch` (one transaction).

---

## 2. Contract state

| Element | Type | Meaning |
|---------|-----|-------|
| `owner` | address | set in the constructor (`owner = msg.sender`) |
| `safeWallet` | address | the target of all `sweep*` calls; locked once |
| `pendingCallbackTarget` | address | the target of the reentrancy callback |
| `pendingCallback` | bytes | the callback calldata |
| `pendingFlashloanPool` | address | the Aave pool borrowed from |
| `pendingFlashloanSteps` | `Step[]` | the sequence executed on the flashloan |
| `MAX_BUILDER_TIP_BPS` | `uint256 constant` | `1000` (a 10% hard limit) |

Events: `Executed`, `CallbackFired`, `SlotWarmed`,
`FlashloanActionFired`, `SafeWalletLocked`.

---

## 3. Functions

| Function | Visibility | Purpose |
|----------|------------|-------|
| `setSafeWallet(address)` | `onlyOwner`, once | locks `safeWallet`; requires `safeWallet == 0` and `wallet != 0` |
| `execute(address,bytes,uint256)` | `payable onlyOwner` | one call as the contract's identity |
| `executeBatch(address[],bytes[],uint256[])` | `payable onlyOwner` | an atomic sequence in one transaction |
| `armCallback(address,bytes)` | `onlyOwner` | prepares a callback for the next ETH |
| `disarmCallback()` | `onlyOwner` | clears the callback |
| `receive()` | `payable` | on received ETH it executes `pendingCallback`, if set |
| `armFlashloanActions(address[],bytes[],uint256[])` | `onlyOwner` | prepares a sequence for the flashloan |
| `disarmFlashloanActions()` | `onlyOwner` | clears the flashloan steps |
| `startFlashLoan(address,address,uint256,bytes)` | `onlyOwner` | triggers the Aave V3 `flashLoanSimple` |
| `executeOperation(...)` | Aave callback | executes the flashloan steps and approves the repayment |
| `sweep()` | `onlyOwner` | sends all ETH to `safeWallet` |
| `sweepWithBuilderTip(uint256)` | `onlyOwner` | part of the ETH to `block.coinbase`, the rest to `safeWallet` |
| `sweepToken(address,uint256)` | `onlyOwner` | sends tokens to `safeWallet` |
| `transferOwnership(address)` | `onlyOwner` | changes the `owner` |

`_bubbleRevert(bytes,string)` is an internal helper; `_safeSend(address,uint256)`
is an internal transfer using `call` (full gas), not `.transfer()`.

---

## 4. The W1–W5 execution model

### W1 — `execute()` reverts on failure

`execute(target, data, value)`:
```solidity
(success, ret) = target.call{value: value}(data);
emit Executed(target, value, success);
if (!success) {
    _bubbleRevert(ret, "AttackWallet: execute target call reverted with no reason");
}
```

Previously a failure silently returned `success=false`; the outer `execute()`
succeeded and the pipeline saw `receipt.status==1` and reported "every step
succeeded, no profit", even though a middle step reverted. Now a failure reverts
the whole transaction and the reason is bubbled. This matches
`executeOperation`'s `if (!ok) revert(...)`.

### W2 — `executeBatch()` atomically

`executeBatch(targets, datas, values)` executes the whole sequence in one
transaction; if any step fails, the **whole** batch reverts. Python uses this
path for `kind == "flat"` and `len(steps) > 1`
(`auto_pipeline.py::execute_plan`, `use_batch`).

### W3 — `_safeSend` instead of `.transfer()`

`sweep()`, `sweepWithBuilderTip()` and `sweepToken()` use `call` (full gas) via
`_safeSend`, not `.transfer()` (2300 gas). A contract recipient (Gnosis
Safe/multisig) cannot run within 2300 gas, so `.transfer()` would revert and the
funds would be stuck.

The same fix is in the generated Solidity templates (`foundry_script.hbs`,
`foundry_script_reentrancy.hbs`, the `collectAndDestroy()` function), which also
use a full-gas `call`. Rust test:
`evm::solution::tests::generated_exploit_scripts_use_full_gas_call_not_transfer`.

### W4 — naming the failing step

`auto_pipeline.first_failing_step_index` replays growing prefixes of the batch
via `eth_call` and reports `best-effort prefix replay points at step i/n`. This
is a diagnostic; a single `eth_call` cannot reproduce an inter-step dependency.

### W5 — topological ordering of dependencies

`strategy_layer.order_steps_by_dependencies` stably topo-sorts prerequisites
before their consumers (`approve` → `transferFrom`, `deposit` → `withdraw`) and
**reports** a cycle rather than silently reordering.

---

## 5. `safeWallet`: the security boundary

`safeWallet` is set **once** (`setSafeWallet`; `require(safeWallet ==
address(0))`). All `sweep*` functions have **no** destination argument:

```solidity
function sweep() external onlyOwner {
    require(safeWallet != address(0), "AttackWallet: safe wallet not set");
    uint256 bal = address(this).balance;
    if (bal > 0) { _safeSend(safeWallet, bal); }
}
```

So even a compromised `owner` cannot redirect payouts. The only way to change
the destination is to deploy a new `AttackWallet`.

`get_or_deploy_attack_wallet` refuses to reuse an existing instance whose locked
`safeWallet` does not match the expected one (`raise SystemExit`). If the
instance predates the `safeWallet` feature (slot is 0), this function locks it
now (backfill).

---

## 6. Reentrancy arm/disarm

For a `kind == "reentrancy"` plan Python:

1. before the **last** step it calls `armCallback(repeat_step.contract,
   repeat_step.calldata)`;
2. it executes the last step (the trigger), which sends ETH and fires
   `receive()`;
3. `receive()` executes the prepared call;
4. afterwards it calls `disarmCallback()`.

`receive()` deliberately does **not** clear `pendingCallbackTarget` (see the
comment in the contract), so the callback can repeat until it is disarmed.

---

## 7. Flashloan path

`execute_flat_plan_via_flashloan` (and `AttackWallet`) enables an attack with no
initial capital:

1. `armFlashloanActions(targets, datas, values)` — the sequence (e.g. WETH
   `withdraw`, trigger the vulnerability, `deposit` again).
2. `startFlashLoan(pool, asset, amount, params)` — calls Aave V3
   `flashLoanSimple` (selector `0x42b0b77c`).
3. Aave calls `executeOperation(...)`:
   * `require(msg.sender == pendingFlashloanPool)`;
   * `emit SlotWarmed(pendingCallbackTarget)` — warms the storage slot
     (EIP-2929), because WETH9 `withdraw()` uses `msg.sender.transfer()`
     (2300 gas) and `receive()`'s first SLOAD without warming would use too much
     gas ("EvmError: OutOfGas");
   * executes each step; a failure `_bubbleRevert`s;
   * `asset.call(approve(msg.sender, amount + premium))`.

The Aave pool and WETH addresses are in `chains.py::AAVE_V3_POOLS` /
`WETH_ADDRESSES` (only `eth` and `sepolia`).

---

## 8. Flashbots bundle path

If `total_value >= FLASHBOTS_THRESHOLD_ETH` and the chain has a relay
(`bundle_relay_for(chain)`), Python pre-signs all protected calls and submits
them as one bundle (`flashbots_bundle.py`). The last call in the bundle is
`sweepWithBuilderTip(BUNDLE_BUILDER_TIP_BPS)`:

```solidity
function sweepWithBuilderTip(uint256 tipBps) external onlyOwner {
    require(tipBps <= MAX_BUILDER_TIP_BPS, "AttackWallet: tip too large");
    require(safeWallet != address(0), "AttackWallet: safe wallet not set");
    uint256 bal = address(this).balance;
    if (bal == 0) { return; }
    uint256 tip = (bal * tipBps) / 10000;
    if (tip > 0) { _safeSend(block.coinbase, tip); }
    uint256 remainder = address(this).balance;
    if (remainder > 0) { _safeSend(safeWallet, remainder); }
}
```

The tip is computed from the **real** balance at execution time, not from the
estimated profit.

---

## 9. Diagram: plan execution through AttackWallet

```mermaid
sequenceDiagram
    participant P as auto_pipeline.execute_plan
    participant AW as AttackWallet
    participant T as Target

    Note over P,AW: kind=flat, len(steps)>1
    P->>AW: executeBatch(targets, datas, values)
    AW->>T: step 0
    AW->>T: step 1
    AW->>T: ...
    P->>AW: sweep()
    AW->>AW: _safeSend(safeWallet, balance)

    Note over P,AW: kind=reentrancy
    P->>AW: armCallback(repeat)
    P->>AW: execute(trigger)
    AW->>T: trigger call
    T-->>AW: ETH → receive() → callback
    P->>AW: disarmCallback()
    P->>AW: sweep()
```

---

## 10. Open / unmeasured

* **Unverified:** whether `executeOperation` correctly handles all kinds of Aave
  V3 pools (the code was verified only for WETH `flashLoanSimple`).
* **Unmeasured:** gas usage per function is not part of this document.
* `W4` (`first_failing_step_index`) is a diagnostic and does not guarantee that
  the flagged step is the real cause (a single `eth_call` cannot reproduce an
  inter-step dependency).
