// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to SWC-120 (weak randomness): the "lottery"
// winner is derived from block.timestamp and block.prevrandao, both of
// which a transaction submitter can predict (and a block producer can
// influence). No outgoing call, so the top-level tx always succeeds and
// the oracle's finding is not discarded by the reverted-tx gate.
contract main {
    uint256 public lastWinner;

    function draw() public {
        // Block attributes as "randomness".
        uint256 r = uint256(blockhash(block.number - 1)) ^ block.prevrandao ^ block.timestamp;
        lastWinner = r % 100;
    }

    function drawTimestampOnly() public {
        lastWinner = block.timestamp % 7;
    }
}
