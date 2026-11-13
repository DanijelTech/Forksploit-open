// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// EIP-1153 transient-storage reentrancy guard that is UNLOCKED before the
// external call -- the guard's protection window closes too early, so the
// classic reentrancy is still possible. State is updated AFTER the call.
contract main {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        uint256 locked;
        assembly {
            locked := tload(0)
        }
        require(locked == 0, "reentrant");
        assembly {
            tstore(0, 1)
        }
        require(balances[msg.sender] >= amount);
        // BUG: unlock BEFORE the external call
        assembly {
            tstore(0, 0)
        }
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }

    receive() external payable {}
}
