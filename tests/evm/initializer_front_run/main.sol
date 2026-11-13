// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to initializer front-running: `initialize()` has
// no access-control guard, so whoever calls it first (not necessarily the
// intended deployer) becomes owner. Unlike tests/evm/proxy_reinit, the bug
// here is exercised by the FIRST successful call, from a non-deployer
// caller -- not a second call re-claiming an already-initialized contract.
contract main {
    address public owner;

    function initialize() public {
        // BUG: no "require(owner == address(0))" guard, and no restriction
        // on who is allowed to call this at all.
        owner = msg.sender;
    }
}
