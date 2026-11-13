pragma solidity ^0.8.0;

// Positive fixture for the "Unbounded Loop" oracle: `members` only ever
// grows (join() pushes, nothing ever pops/shrinks it), and poke() loops
// over the WHOLE array on every single call -- the classic
// unbounded-loop-over-growing-storage gas-griefing shape. Each
// successive poke() after more join() calls costs strictly more gas,
// forever, with no cap -- eventually exceeding the block gas limit and
// making poke() permanently unusable.
contract main {
    address[] public members;

    function join() external {
        members.push(msg.sender);
    }

    function poke() external returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < members.length; i++) {
            sum += uint256(uint160(members[i]));
        }
        return sum;
    }
}
