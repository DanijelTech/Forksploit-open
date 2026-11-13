// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;
contract HardKeccakNonLin {
    uint256 public secret;
    uint256 public solved;
    constructor() { secret = uint256(keccak256(abi.encodePacked("a-real-secret-string-xyz"))); }
    // SAME storage read as HardKeccak, but the gate is non-invertible and
    // secret (a fixed keccak) is not a perfect square -> NO x exists.
    function win(uint256 x) public { require(x * x == secret, "gate"); solved = 1; }
}
