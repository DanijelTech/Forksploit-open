// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Control fixture: the SAME EIP-1153 transient guard as transient_guard,
// but correctly RELEASED AFTER the external call -- the standard
// checks-effects-interactions ordering. The oracle must stay SILENT here.
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
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        // correct ordering: release only AFTER the external call
        assembly {
            tstore(0, 0)
        }
    }

    receive() external payable {}
}
