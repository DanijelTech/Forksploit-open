// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Negative control for the declarative invariant oracle
// (src/evm/oracles/invariant.rs). Same "bank" shape as
// tests/evm/eth_backing/main.sol, but CORRECTLY backed: a balance can only
// be credited by an equal, actually-received msg.value. sum(balances) can
// therefore never exceed the contract's real ETH, so the invariant
// "sum(balances) <= native balance" MUST never fire here. Proving that is
// what separates "the oracle found a real violation" from "the oracle
// alarms on everything".
contract main {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
