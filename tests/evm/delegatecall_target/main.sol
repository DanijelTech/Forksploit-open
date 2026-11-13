// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// Intentionally vulnerable to delegatecall-target-from-returndata, with the
// RETURNDATACOPY-decoded target and the vulnerable DELEGATECALL deliberately
// split across a control-leak boundary: `getTarget()` is read (self-call, no
// separate deployed contract needed -- same "avoid an unguessable second
// address" lesson as token_accounting_mismatch/main.sol) BEFORE the leak,
// `Someone(x).something()` is the leak point (mirrors reentrancy/main.sol's
// and readonly_reentrancy/main.sol's own proven attacker-callback shape),
// and the actual `target.delegatecall(...)` only happens in the resumed
// continuation AFTER the leak. This specifically exercises whether
// `current_returndata_addresses`/`current_calldata_addresses` survive a
// control-leak resumption boundary (see vm.rs's execute_from_pc cleanup
// block, 2026-11-03 fix).
interface Someone {
    function something() external;
}

contract main {
    address stored;

    // Derived from `stored`, not a raw copy of it -- so a direct
    // calldata-byte-match (via_calldata_taint / via_byte_coincidence)
    // can't explain the eventual target; only the RETURNDATACOPY
    // dataflow path can.
    function getTarget() external view returns (address) {
        return address(uint160(stored) ^ uint160(0xdead));
    }

    function attack(address x) public {
        stored = x;
        (bool ok1, bytes memory data) = address(this).call(abi.encodeWithSignature("getTarget()"));
        require(ok1 && data.length == 32);
        address target = abi.decode(data, (address));

        Someone(x).something(); // leak point -- x may be attacker-controlled

        (bool ok2, ) = target.delegatecall(""); // uses target decoded BEFORE the leak
        ok2;
    }
}
