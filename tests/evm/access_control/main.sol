// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable contract used to smoke-test the access-control
// oracle: `setOwner` is missing the `onlyOwner` check that `pause`/`unpause`
// correctly enforce, so anyone can take over ownership.
contract main {
    address public owner;
    bool public paused;

    constructor() {
        owner = msg.sender;
    }

    // BUG: missing `require(msg.sender == owner)`
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function pause() public {
        require(msg.sender == owner, "not owner");
        paused = true;
    }

    function unpause() public {
        require(msg.sender == owner, "not owner");
        paused = false;
    }
}
