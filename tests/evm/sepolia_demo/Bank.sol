// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to classic reentrancy: sends ETH before updating
// the caller's balance, so a malicious receiver can re-enter withdraw()
// before its balance is zeroed out.
contract Bank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}
