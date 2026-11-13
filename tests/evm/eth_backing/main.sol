// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Minimal "bank" shape used to smoke-test the eth_backing oracle:
// creditMyself() lets anyone credit their own recorded balance without
// ever sending real ETH -- the classic "internal accounting detached
// from real holdings" bug.
contract main {
    mapping(address => uint256) public balances;

    function creditMyself(uint256 amount) public {
        balances[msg.sender] += amount;
    }

    receive() external payable {}
}
