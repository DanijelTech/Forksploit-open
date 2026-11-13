// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract main {
    function helper(uint256 x) external pure returns (uint256) {
        return x * 2;
    }

    // NEGATIVE control for PHASE 2.5: `x * 2` is always EVEN, but the gate
    // demands an ODD secret, so NO `y` satisfies it and `solved` can never
    // become 1. A correct concolic must NOT report this -- it proves the
    // return-value splice does not turn an unsatisfiable gate into a false
    // positive (e.g. by guessing a constant return).
    function process(uint256 y) public {
        uint256 r = this.helper(y);
        require(r == 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEF, "bad return");
        typed_bug("0x3322");
    }
}
