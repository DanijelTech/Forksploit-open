// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract main {
    function helper(uint256 x) external pure returns (uint256) {
        return x * 2;
    }

    // PHASE 2.5 fixture: the gate depends on the CALL's RETURN VALUE, not on
    // storage or calldata directly. `this.helper(y)` is an external self-call
    // that returns `y * 2`; the secret is EVEN, so `y = secret / 2` exists.
    // Before PHASE 2.5 the concolic result of a CALL was always concrete, so
    // this gate was unreachable; the symbolic return-value splice makes
    // `y * 2 == secret` solvable.
    function process(uint256 y) public {
        uint256 r = this.helper(y);
        require(r == 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEE, "bad return");
        typed_bug("0x3322");
    }
}
