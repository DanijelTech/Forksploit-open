// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Minimal ERC4626-shaped vault with a broken preview round trip, used to
// smoke-test the preview_rounding oracle: previewRedeem(previewDeposit(x))
// returns MORE than x, which EIP-4626 forbids (rounding must favor the
// vault, never the depositor).
contract main {
    function deposit(uint256, address) public pure returns (uint256) {
        return 0;
    }

    function mint(uint256, address) public pure returns (uint256) {
        return 0;
    }

    function withdraw(uint256, address, address) public pure returns (uint256) {
        return 0;
    }

    function redeem(uint256, address, address) public pure returns (uint256) {
        return 0;
    }

    function previewDeposit(uint256 assets) public pure returns (uint256) {
        return assets;
    }

    // BUG: always hands back one extra wei of "assets" versus what was
    // deposited -- a guaranteed, repeatable profit for any caller.
    function previewRedeem(uint256 shares) public pure returns (uint256) {
        return shares + 1;
    }
}
