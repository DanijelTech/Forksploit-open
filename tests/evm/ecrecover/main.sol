// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to the classic "unchecked ecrecover(0)" bug:
// `owner` is never initialized (stays address(0)), and `claim` never checks
// that the recovered signer is non-zero, so ANY invalid signature (which
// makes ecrecover return address(0)) satisfies `signer == owner`.
contract main {
    address public owner;
    bool public claimed;

    function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public {
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "bad signature");
        claimed = true;
    }
}
