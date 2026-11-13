// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to SWC-124 (Write to Arbitrary Storage
// Location): `write()` takes the storage slot to overwrite straight from
// its own calldata, via raw `assembly { sstore(slot, value) }` -- not the
// safe, compiler-generated `mapping[key] = value` pattern (which always
// hashes the key with the mapping's own base slot via KECCAK256 first).
// Anyone can overwrite `owner` (slot 0) by calling write(0, <their own
// address>) -- the 2017 Parity multisig library pattern.
contract main {
    address public owner;

    function write(uint256 slot, uint256 value) public {
        assembly {
            sstore(slot, value)
        }
    }
}
