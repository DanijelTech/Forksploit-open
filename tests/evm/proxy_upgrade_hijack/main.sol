// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable to a UUPS-style unprotected proxy upgrade:
// `upgradeTo` writes the EIP-1967 implementation slot but has NO access
// control at all (no `onlyOwner`, no `_authorizeUpgrade`). Because the
// EIP-1967 *admin* slot is never set (admin == 0), this is neither
// `access_control.rs`'s "Unauthorized Proxy Upgrade" (which requires a
// non-zero admin slot to compare the caller against) nor
// `proxy_integrity.rs`'s storage-collision check (which deliberately
// skips the `upgradeTo`/`upgradeToAndCall`/`changeAdmin` selectors).
contract main {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BUG: no `require(msg.sender == owner)` / `_authorizeUpgrade` guard --
    // anyone can point the implementation slot at an arbitrary address.
    function upgradeTo(address newImplementation) public {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            sstore(slot, newImplementation)
        }
    }
}
