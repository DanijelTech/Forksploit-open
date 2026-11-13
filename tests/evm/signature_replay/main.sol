// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable EIP-2612-style permit used to smoke-test the
// signature-replay oracle: it never tracks/invalidates used signatures (no
// nonce check), so the exact same (owner, spender, value, deadline, v, r, s)
// calldata can be replayed to set the allowance again.
contract main {
    mapping(address => uint256) public allowance;

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        // BUG: no nonce / "already used" check -- pretend signature
        // verification happened and recovered `owner`.
        allowance[spender] = value;
    }
}
