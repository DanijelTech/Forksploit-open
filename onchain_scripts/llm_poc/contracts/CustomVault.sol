// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Proof-of-concept target for the LLM-hypothesis-generation engine
// (onchain_scripts/llm_poc/). Deliberately NOT an ERC4626-standard vault --
// it uses its own deposit(uint256)/redeem(uint256) names, not
// deposit(uint256,address)/previewDeposit/previewRedeem -- so
// src/evm/oracles/preview_rounding.rs (which only probes the standard
// ERC4626 function selectors) can never see it, even though it has the
// EXACT SAME underlying vulnerability class that oracle already catches
// on real ERC4626 vaults: share price computed from the vault's raw
// token balance, which an attacker can inflate directly via a plain
// transfer, bypassing deposit() entirely.
//
// This is the motivating gap for the LLM-hypothesis layer: a tool that
// only matches fixed bytecode/ABI patterns (ForkSploit's ~37 oracles)
// cannot recognize "this is the SAME bug class, just under different
// function names" -- that requires actually understanding what the
// contract's deposit/redeem math is trying to do.
interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract CustomVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    IERC20Like public asset;

    constructor(address _asset) {
        asset = IERC20Like(_asset);
    }

    // Mints shares proportional to the vault's CURRENT real token
    // balance (`bal`), not to totalShares alone -- the classic
    // donation/inflation precondition. First depositor gets 1 share per
    // token 1:1.
    function deposit(uint256 amount) external {
        uint256 bal = asset.balanceOf(address(this));
        uint256 newShares;
        if (totalShares == 0 || bal == 0) {
            newShares = amount;
        } else {
            newShares = (amount * totalShares) / bal;
        }
        require(newShares > 0, "zero shares");
        bool ok = asset.transferFrom(msg.sender, address(this), amount);
        require(ok, "transferFrom failed");
        shares[msg.sender] += newShares;
        totalShares += newShares;
    }

    function redeem(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "insufficient shares");
        uint256 bal = asset.balanceOf(address(this));
        uint256 amount = (shareAmount * bal) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        bool ok = asset.transfer(msg.sender, amount);
        require(ok, "transfer failed");
    }
}
