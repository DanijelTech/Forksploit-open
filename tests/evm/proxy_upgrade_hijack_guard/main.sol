// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Control fixture for the proxy-upgrade-hijack oracle: `upgradeTo` DOES
// enforce `onlyOwner`, so a non-owner call reverts and a successful call can
// only come from the owner. The oracle must stay SILENT here -- a false
// positive on a correctly-guarded upgrade would be worse than a miss.
contract main {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function upgradeTo(address newImplementation) public onlyOwner {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            sstore(slot, newImplementation)
        }
    }
}
