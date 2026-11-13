// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to SWC-132 (Unexpected Ether Balance): assumes
// address(this).balance EXACTLY equals its own internal accounting
// variable. A SELFDESTRUCT targeting this contract's address (always
// succeeds, bypasses receive()/payable entirely) with even 1 extra wei
// permanently breaks this equality -- withdraw() reverts forever after
// that, for every depositor, with no recovery path. No outgoing value
// transfer here on purpose (see oracles/forced_eth_accounting.rs's own
// test-fixture notes): a payable-value outgoing call is exactly the
// shape the fuzzer's OWN control-leak exploration (host.rs's
// call_allow_control_leak) most aggressively tries to intercept to
// probe reentrancy, which discards this execution's oracle hits
// entirely (feedback.rs's `has_post_exec` check) regardless of whether
// the vulnerable EQ already ran earlier in the SAME transaction --
// confirmed empirically this session. The vulnerable pattern itself
// (the fragile EQ check) doesn't need an outgoing call to demonstrate.
contract main {
    uint256 public totalDeposits;
    uint256 public successfulWithdrawals;

    function deposit() public payable {
        totalDeposits += msg.value;
    }

    function withdraw() public {
        require(address(this).balance == totalDeposits, "accounting mismatch");
        totalDeposits = 0;
        successfulWithdrawals += 1;
    }
}
