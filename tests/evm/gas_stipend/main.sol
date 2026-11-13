// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to SWC-134 (hardcoded gas stipend): payout()
// uses `.transfer()` (EIP-150's 2300-gas stipend, forwarded verbatim by
// solc). A recipient whose receive()/fallback() needs more than 2300 gas
// -- e.g. WETH9's own transfer() -- makes this revert forever. No
// value-carrying outgoing call is needed to demonstrate the pattern: the
// hardcoded stipend is visible in the call instruction itself.
contract main {
    address payable public recipient;
    uint256 public totalDeposits;

    function setRecipient(address payable r) public {
        require(r != address(0), "zero");
        recipient = r;
    }

    function deposit() public payable {
        totalDeposits += msg.value;
    }

    function payout() public {
        // `.send()` still forwards the hardcoded 2300-gas stipend, but
        // returns a bool instead of reverting -- so the top-level tx
        // still succeeds and the oracle's finding is not discarded by
        // feedback.rs's reverted-tx gate. The ignored result is itself
        // part of the bug (a silent failure).
        recipient.send(address(this).balance);
    }
}
