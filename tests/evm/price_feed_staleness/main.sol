// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Minimal Chainlink-style feed stuck at an ancient updatedAt timestamp --
// used to smoke-test the price_feed_staleness oracle.
contract main {
    function latestRoundData()
        public
        pure
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        return (1, 200000000000, 1000, 1000, 1);
    }
}
