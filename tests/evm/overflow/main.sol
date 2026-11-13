// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to silent underflow: `withdraw` uses an
// `unchecked` block, so subtracting more than the current balance wraps
// around to a huge number instead of reverting.
contract main {
    uint256 public balance;

    function withdraw(uint256 amount) public {
        unchecked {
            balance = balance - amount;
        }
    }
}
