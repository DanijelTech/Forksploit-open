// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable: setOwner() never checks the new owner against
// address(0). Calling it with the zero address permanently cements the
// owner role to the burn address -- a missing
// `require(newOwner != address(0))` guard (SWC-131). No outgoing call
// here on purpose (see forced_eth_accounting's own fixture note): a
// value-carrying outgoing call is exactly what the fuzzer's control-leak
// exploration intercepts, which discards this execution's oracle hits.
contract main {
    address public owner;
    uint256 public totalDeposits;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) public {
        // No zero-check.
        owner = newOwner;
    }

    function deposit() public payable {
        totalDeposits += msg.value;
    }
}
