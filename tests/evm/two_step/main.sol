// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// A bug reachable ONLY through a 2-transaction sequence:
//   step 1  arm()   -> stage = 1   (value stays 0; invariant value<=1 holds)
//   step 2  fire()  -> requires stage==1, then sets value = 2 (breaks value<=1)
// A single transaction can never do it: arm() alone leaves value at 0, and
// fire() alone reverts because stage is still 0. Only the SEQUENCE breaks the
// declared invariant (checked by the `--invariants` oracle).
contract TwoStep {
    uint256 public stage;
    uint256 public value;

    function arm() public {
        stage = 1;
    }

    function fire() public {
        require(stage == 1, "not armed");
        value = 2;
    }
}
