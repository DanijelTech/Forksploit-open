// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Control fixture: same proof-verification shape as forged_proof, but the
// caller-supplied `root` IS tied to the contract's own authoritative
// `trustedRoot` before anything is credited -- so a forged (root, proof)
// pair is rejected. The oracle must stay SILENT here.
contract main {
    mapping(bytes32 => bool) public processed;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    bytes32 public trustedRoot;

    function setTrustedRoot(bytes32 r) public {
        trustedRoot = r;
    }

    function processMessage(bytes32 messageHash, bytes32[] calldata proof, bytes32 root, address to, uint256 amount) public {
        require(root == trustedRoot, "untrusted root");
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
