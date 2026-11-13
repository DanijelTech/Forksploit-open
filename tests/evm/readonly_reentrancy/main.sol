// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// Intentionally vulnerable to read-only reentrancy: getPrice() returns
// an inconsistent, mid-update value while a reentrant callback window
// is open. Mirrors tests/evm/reentrancy/main.sol's own proven shape
// (attacker-controlled callback target `x`, no value transfer) so the
// fuzzer's existing control-leak exploration of "what does x's callback
// do" is what discovers calling back into getPrice() during the window,
// same as it already discovers classic reentrancy there.
interface Someone {
    function something() external;
}

contract main {
    uint256 public price;

    constructor() {
        price = 100;
    }

    function attack(address x) public {
        this.getPrice(); // baseline read, no reentrancy pending yet
        price = 1; // temporarily inconsistent mid-update value
        Someone(x).something(); // reentrant window -- x may call back into getPrice() here
        price = 100; // restored
    }

    function getPrice() public view returns (uint256) {
        return price;
    }
}
