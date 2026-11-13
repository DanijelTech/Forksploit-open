// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Minimal, dependency-free harness contracts for proving AttackWallet's
// W1/W2/W3 fixes against a local anvil node (no forge-std needed).

/// Always reverts with a reason, to prove W1 (a failing step must revert the
/// whole execute()/executeBatch() tx, not be swallowed).
contract Reverter {
    function boom() external pure {
        revert("BOOM: step failed");
    }
}

/// A CONTRACT recipient whose receive() writes storage -- needs far more than
/// the 2300-gas stipend `.transfer()` forwards, so it proves W3 (a contract
/// recovery wallet must be able to receive the sweep).
contract StorageReceiver {
    uint256 public hits;
    receive() external payable {
        hits += 1;
    }
}

/// Records every call it receives, so executeBatch atomicity can be checked:
/// if the batch reverts, its counter must be unchanged.
contract Counter {
    uint256 public count;
    function bump() external {
        count += 1;
    }
}
