// SPDX-License-Identifier: UNLICENSED
// Author: DanyTech
pragma solidity ^0.8.19;

interface IERC20Like {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

// ERC4626-shaped vault (so the already-existing PreviewRoundingOracle
// fingerprints and checks it with zero new Rust work) whose redeem()
// rounds in the DEPOSITOR'S favor by 0.1% instead of the vault's -- a
// violation of EIP-4626's rounding requirement, same bug CLASS as
// tests/evm/preview_rounding, but the profit SCALES with the amount
// processed and comfortably exceeds Aave V3's 0.05% flashloan premium.
// At realistic human-wallet scale the profit is pocket change, not worth
// the gas; at flashloan scale (depositing/redeeming hundreds of thousands
// of the underlying in one atomic transaction) it is real money, with
// zero attacker capital required beyond gas and the flash premium.
// Verified live on Sepolia with a real Aave V3 flashloan -- see
// onchain_scripts/aave_flashloan_runner.py.
contract Vault {
    IERC20Like public immutable asset;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address _asset) {
        asset = IERC20Like(_asset);
    }

    function previewDeposit(uint256 assets) public pure returns (uint256) {
        return assets;
    }

    function previewRedeem(uint256 shares) public pure returns (uint256) {
        // BUG: +0.1% instead of rounding down in the vault's favor --
        // comfortably more than Aave V3's 0.05% flashloan premium, so a
        // flashloan-funded round trip is net profitable for real, not
        // just technically "exploitable".
        return shares + (shares / 1000);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        asset.transferFrom(msg.sender, address(this), assets);
        shares = previewDeposit(assets);
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = shares;
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        assets = previewRedeem(shares);
        asset.transfer(receiver, assets);
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        shares = assets;
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        asset.transfer(receiver, assets);
    }
}
