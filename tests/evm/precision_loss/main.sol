// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable: `(a / b) * c` divides before scaling, so
// integer truncation loses the remainder. The correct, lossless ordering
// is `(a * c) / b`. This is the classic share/interest/fee rounding bug
// (SWC-101 class). `unchecked` is used so solc emits the DIV immediately
// followed by the MUL (no overflow-check helper in between).
contract main {
    uint256 public shares;

    function compute(uint256 a, uint256 b, uint256 c) public {
        require(b != 0, "zero");
        unchecked {
            shares = (a / b) * c;
        }
    }
}
