pragma solidity ^0.8.0;

// Positive fixture for correlated multi-address mutation
// (`BoxedABI::mutate_with_vm_slots`'s TArray branch, src/evm/abi.rs):
// createPair-style state change/selfdestruct is only reachable when BOTH
// address args are simultaneously non-zero AND distinct from each other
// in the SAME call. Mutating one address slot at a time (the old default
// behavior) essentially never produces two different fresh non-zero
// addresses together in one call -- this needed the correlated
// multi-slot mutation added this session to be practically reachable.
contract main {
    mapping(address => mapping(address => bool)) public pairs;

    function createPair(address tokenA, address tokenB) external {
        require(tokenA != address(0), "zero A");
        require(tokenB != address(0), "zero B");
        require(tokenA != tokenB, "identical");
        pairs[tokenA][tokenB] = true;
        selfdestruct(payable(tokenA));
    }
}
