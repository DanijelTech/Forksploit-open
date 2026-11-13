// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Minimal stand-in for a Curve-style StableSwap pool, used to smoke-test
// the curve_virtual_price oracle: get_virtual_price() should only ever go
// up (fees) or stay flat (proportional liquidity changes). This fixture
// is intentionally vulnerable -- anyone can set it directly, simulating
// the kind of mid-transaction state corruption real Curve incidents
// (e.g. read-only reentrancy) exploited.
contract main {
    uint256 public virtualPrice = 1 ether;

    function get_virtual_price() public view returns (uint256) {
        return virtualPrice;
    }

    // BUG: no access control, no monotonicity check.
    function corrupt(uint256 newPrice) public {
        virtualPrice = newPrice;
    }
}
