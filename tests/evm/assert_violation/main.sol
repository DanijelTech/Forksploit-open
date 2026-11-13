// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable: guarded() uses `assert()` for what is really
// input validation. `assert` is meant for internal invariants that can
// never fail if the code is correct; an attacker-supplied value reaching
// it burns ALL remaining gas (SWC-110) instead of reverting cheaply.
//
// probe() calls guarded() via a low-level call and ignores the result, so
// the OUTER transaction still succeeds even when the assertion fires. The
// fuzzer's feedback layer discards oracle findings from reverted
// transactions, so this swallowed-nested-call shape is exactly how a
// reachable assertion shows up as a finding.
contract main {
    function guarded(uint256 x) public pure {
        // Should be `require`, not `assert`.
        assert(x != 0);
    }

    function probe(uint256 x) public {
        // Result deliberately ignored: the inner revert (Panic(0x01)) is
        // swallowed, keeping the top-level transaction successful.
        (bool ok, ) = address(this).call(abi.encodeWithSelector(this.guarded.selector, x));
        ok; // silence unused-variable warning
    }
}
