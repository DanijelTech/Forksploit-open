// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Cross-chain message receiver with a FORGED-PROOF hole (Nomad/KelpDAO
// shape): `processMessage` trusts a `root` supplied in calldata and never
// compares it to the contract's own authoritative `trustedRoot`, so anyone
// can finalize an arbitrary message by supplying a matching (root, proof).
contract main {
    mapping(bytes32 => bool) public processed;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    bytes32 public trustedRoot;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setTrustedRoot(bytes32 r) public {
        require(msg.sender == owner, "not owner");
        trustedRoot = r;
    }

    // BUG: `root` comes from the caller and is never checked against
    // `trustedRoot` -- the proof is verified against whatever root the
    // attacker chose.
    function processMessage(bytes32 messageHash, bytes32[] calldata proof, bytes32 root, address to, uint256 amount) public {
        require(_verifyProof(messageHash, proof, root), "bad proof");
        require(!processed[messageHash], "already processed");
        processed[messageHash] = true;
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function _verifyProof(bytes32 messageHash, bytes32[] calldata proof, bytes32 root) internal pure returns (bool) {
        bytes32 h = messageHash;
        for (uint256 i = 0; i < proof.length; i++) {
            h = keccak256(abi.encodePacked(h, proof[i]));
        }
        return h == root;
    }
}
