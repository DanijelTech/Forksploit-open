// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally reads a memory word that was never written, used to
// smoke-test the uninitialized-memory oracle.
contract main {
    function readRaw() public pure returns (uint256 result) {
        assembly {
            result := mload(0x200)
        }
    }
}
