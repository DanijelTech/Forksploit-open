pragma solidity ^0.8.0;

// Positive fixture for the "Stale Guard Counter" oracle
// (src/evm/oracles/stale_guard.rs): directly mirrors a real deployed ETC
// contract found this session, where `mint()` was gated on
// `require(numTokens < MAX_TOKENS)`, but `numTokens`'s own increment was
// commented out -- the guard read the SAME value on every single
// successful call, no matter how many times mint() succeeded, making the
// advertised cap completely ineffective.
contract main {
    uint256 public numTokens;
    uint256 public constant MAX_TOKENS = 20000;

    function mint() external {
        require(numTokens < MAX_TOKENS, "cap reached");
        // BUG: numTokens++ is missing here -- this guard can never
        // actually progress toward MAX_TOKENS.
    }
}
