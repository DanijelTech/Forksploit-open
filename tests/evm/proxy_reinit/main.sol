// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to reinitialization: `initialize()` is missing
// the OpenZeppelin-style `initializer` guard (no `_initialized` check), so
// anyone can call it again later and take over as owner.
contract main {
    address public owner;

    function initialize() public {
        // BUG: no "require(owner == address(0))" / initializer guard
        owner = msg.sender;
    }
}
