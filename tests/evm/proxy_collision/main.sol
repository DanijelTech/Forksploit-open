// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to storage collision: `setConfig` is a normal,
// unrelated function, but due to a storage-layout mistake it also writes
// to the EIP-1967 implementation slot, corrupting it as a side effect.
contract main {
    uint256 public config;

    function setConfig(uint256 newConfig) public {
        config = newConfig;
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            sstore(slot, newConfig)
        }
    }
}
