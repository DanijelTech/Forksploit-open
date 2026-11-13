// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable proxy used to smoke-test the storage-collision
// oracle: `nativeSlot` (the proxy's own variable) and Implementation's
// `implSlot` both land at storage slot 0, so delegating into Implementation
// silently corrupts the proxy's own state.
contract Proxy {
    uint256 public nativeSlot;

    function setNative(uint256 v) public {
        nativeSlot = v;
    }

    function delegateSetImpl(address impl, uint256 v) public {
        (bool ok, ) = impl.delegatecall(abi.encodeWithSignature("setImpl(uint256)", v));
        require(ok, "delegatecall failed");
    }
}

contract Implementation {
    uint256 public implSlot;

    function setImpl(uint256 v) public {
        implSlot = v;
    }
}
