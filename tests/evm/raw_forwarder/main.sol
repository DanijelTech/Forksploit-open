// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Used to validate that the fuzzer's mutator can construct a raw `bytes`
// blob matching a specific function selector when that blob is forwarded
// into a nested call -- `found` only flips if `forward()`'s opaque `data`
// happens to decode as a valid `secret(uint256)` call.
contract Target {
    bool public found;

    function secret(uint256 x) public {
        found = true;
    }
}

contract Forwarder {
    function forward(address target, bytes calldata data) public {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
