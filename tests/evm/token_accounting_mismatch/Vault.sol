// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to the token_accounting_mismatch bug class:
// `deposit()` credits the full requested `amount`, not the real,
// observed balance delta a fee-on-transfer/rebasing token would actually
// produce. Self-calls with transferFrom-shaped calldata (falling through
// the empty fallback, which always succeeds) so the fuzzer only needs to
// find ONE function, `deposit(uint256)`, instead of also having to guess
// a separately-deployed token contract's randomly-assigned address --
// the detection itself (host.rs's call()/0x55 SSTORE handling) only
// cares about the shape of the outgoing call and the following SSTORE,
// not which contract actually receives it.
contract Vault {
    mapping(address => uint256) public balances;

    fallback() external {}

    function deposit(uint256 amount) public {
        (bool ok,) = address(this).call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), amount)
        );
        require(ok, "transfer failed");
        balances[msg.sender] += amount;
    }
}
