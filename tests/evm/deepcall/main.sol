// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

// Verifies the --max-call-depth fix (sha3_bypass.rs's push/pop symmetry,
// and the configurable analysis depth itself) against a REAL call chain
// deeper than both the old hardcoded 3 and the new default 15 -- not
// just "doesn't crash up to 15", but genuinely depth-independent now.
// Each level does a real external CALL (so host.call_depth actually
// increments, unlike a plain internal function call) and a real SHA3
// (keccak256) so sha3_bypass's taint tracking has something to do at
// every depth, not just pass through untouched.
contract main {
    mapping(bytes32 => bool) public seen;
    uint256 public deepestReached;

    // Guarded so the fuzzer can't shortcut the chain by calling
    // recurse() directly with a small depth of its own choosing -- the
    // only way in is through start()'s own address(this).call, which
    // makes every subsequent recursive call's msg.sender == address(this)
    // too. Forces the ACTUAL call chain to be walked every time.
    function recurse(uint256 depth) external returns (uint256) {
        require(msg.sender == address(this), "only via start()");
        bytes32 h = keccak256(abi.encodePacked(depth, block.timestamp));
        seen[h] = true;
        if (depth > deepestReached) {
            deepestReached = depth;
        }
        if (depth == 0) {
            // Only reachable once the chain actually bottoms out --
            // confirms real recursion happened, not an early revert.
            typed_bug("reached-bottom");
            return 0;
        }
        (bool ok, bytes memory ret) = address(this).call(
            abi.encodeWithSignature("recurse(uint256)", depth - 1)
        );
        require(ok, "inner call failed");
        return abi.decode(ret, (uint256));
    }

    // 20 > both the old hardcoded MAX_CALL_DEPTH (3) and the new default
    // (15) -- exercises real call_depth past the configured analysis
    // limit, which should gracefully stop deep taint/Z3 analysis but
    // must NOT corrupt the ctxs stack or crash the process either way.
    function start() public {
        (bool ok, ) = address(this).call(abi.encodeWithSignature("recurse(uint256)", uint256(20)));
        require(ok, "start failed");
    }
}
