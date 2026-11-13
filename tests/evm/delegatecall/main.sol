// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to delegatecall injection: `execute` lets the
// caller pick ANY address to delegatecall into (no allowlist / fixed
// implementation slot), which can corrupt this contract's own storage.
contract main {
    function execute(address target, bytes calldata data) public {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
