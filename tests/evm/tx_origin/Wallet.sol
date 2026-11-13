// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable: `withdraw()` gates on `tx.origin == owner`
// instead of `msg.sender == owner`. A malicious intermediary contract can
// trick `owner` into calling it, then relay the call into `withdraw()` --
// `tx.origin` is still `owner` even though the immediate caller is the
// attacker's contract, so the check wrongly passes.
contract Wallet {
    address public owner;
    uint256 public withdrawn;

    function setOwner(address o) public {
        owner = o;
    }

    function withdraw(uint256 amount) public {
        require(tx.origin == owner, "not owner");
        withdrawn += amount;
    }
}

contract AttackerRelay {
    function relay(address wallet, uint256 amount) public {
        (bool ok, ) = wallet.call(abi.encodeWithSignature("withdraw(uint256)", amount));
        require(ok, "relay failed");
    }
}
