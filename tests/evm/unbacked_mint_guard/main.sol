// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Control fixture: supply ONLY ever grows through a paid `deposit()` --
// every new share is backed 1:1 by incoming ETH. There is no free-mint path,
// so the unbacked-mint oracle must stay SILENT here (a false positive on a
// correctly-backed token would be worse than a miss).
contract main {
    string public name = "BackedShare";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function deposit() public payable {
        totalSupply += msg.value;
        balanceOf[msg.sender] += msg.value;
    }
}
