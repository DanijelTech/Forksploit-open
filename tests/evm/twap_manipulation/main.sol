// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Minimal Uniswap-V2-shaped pair used to smoke-test the twap_manipulation
// oracle: skew() lets anyone directly move one reserve with no invariant
// enforcement at all, simulating a single-transaction price-manipulation
// primitive.
contract main {
    uint112 public reserve0 = 1000 ether;
    uint112 public reserve1 = 1000 ether;

    function getReserves() public view returns (uint112, uint112, uint32) {
        return (reserve0, reserve1, uint32(block.timestamp));
    }

    // BUG: no x*y=k enforcement, no access control.
    function skew(uint112 newReserve0) public {
        require(newReserve0 > 0);
        reserve0 = newReserve0;
    }
}
