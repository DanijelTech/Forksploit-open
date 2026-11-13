// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to UNBACKED MINT: an ETH-backed share token.
// `deposit()` is the honest path -- it takes real ETH and mints matching
// shares. `mint()` is the BUG: it mints new supply to the caller for free,
// with no payment and no change to the contract's real ETH balance, so the
// attacker's free shares become a claim on the ETH existing depositors put
// in (diluting/stealing their backing).
//
// Deliberately NOT the `balances(address)` bank shape that `eth_backing.rs`
// fingerprints (this is ERC20-shaped: it exposes totalSupply()), and NOT an
// ERC4626 (no deposit/withdraw share math), so it falls through the existing
// oracles.
contract main {
    string public name = "UnbackedShare";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // Honest path: pay ETH, get shares. Establishes real backing.
    function deposit() public payable {
        totalSupply += msg.value;
        balanceOf[msg.sender] += msg.value;
    }

    // BUG: mints new supply to the caller with no payment and no backing.
    function mint(uint256 amount) public {
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
    }
}
