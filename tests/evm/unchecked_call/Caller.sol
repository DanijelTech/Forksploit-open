// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable: `relay()` makes a plain low-level call into
// `Victim.alwaysReverts()` and never checks whether it succeeded. Used to
// smoke-test the unchecked-low-level-call oracle: the sub-call fails, the
// success flag is discarded, and `relay()` itself still returns normally.
contract Victim {
    function alwaysReverts() public pure {
        revert("nope");
    }
}

contract Caller {
    function relay(address target) public {
        target.call(abi.encodeWithSignature("alwaysReverts()"));
    }
}
