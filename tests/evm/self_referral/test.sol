pragma solidity ^0.8.0;

// Positive fixture for the "Validation-Independent Payment" oracle
// (src/evm/oracles/self_referral.rs): directly mirrors a real deployed
// ETC contract found this session, where `mint(to, referral)` paid a 10%
// fee to `referral` regardless of whether `referral` passed the
// contract's own "valid referral" check -- that check only gated a
// separate bonus counter, never the payment itself. Net effect: anyone
// can pass their own address as `referral` and collect the fee.
contract main {
    mapping(address => uint256) public selfReferralFlagged;

    function mint(address referral) external payable {
        require(msg.value > 0, "need value");
        if (referral == msg.sender) {
            // Flagged as a self-referral attempt -- but this only
            // records a flag, it does NOT actually block the payment
            // below.
            selfReferralFlagged[referral]++;
        }
        // BUG: fee paid to `referral` regardless of whether it was
        // flagged as self-referral above -- the check never actually
        // gates the payment itself.
        payable(referral).transfer(msg.value);
    }
}
