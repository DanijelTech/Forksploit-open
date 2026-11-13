// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to the push-payment DoS (SWC-113):
// payoutAll() calls each recipient inside a loop. The first recipient is
// this contract itself, whose receive() reverts, so that call site always
// fails; a real distribution would then block every other recipient too.
contract main {
    address payable[] public recipients;

    constructor() {
        // Two recipients so the loop body executes at least twice: one
        // (this contract) that always reverts, one plain EOA-style address.
        recipients.push(payable(address(this)));
        recipients.push(payable(address(0xBEEF)));
    }

    receive() external payable {
        revert("no thanks");
    }

    function addRecipient(address payable r) public {
        require(r != address(0), "zero");
        recipients.push(r);
    }

    function payoutAll() public {
        for (uint256 i = 0; i < recipients.length; i++) {
            // `.send()` swallows the failure (top-level tx still
            // succeeds) but the call site fails inside the loop.
            recipients[i].send(1 wei);
        }
    }

    function recipientCount() public view returns (uint256) {
        return recipients.length;
    }
}
