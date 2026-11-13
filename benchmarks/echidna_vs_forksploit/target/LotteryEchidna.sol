// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./CyberScratchLottery.sol";

/// Echidna property harness for the REAL CyberScratchLottery contract
/// (0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee on Mordor). The harness only
/// wraps the real contract and tracks ticket revenue; it reimplements no
/// game logic.
contract LotteryEchidna {
    CyberScratchLottery public lottery;
    address public initialOwner;
    uint256 public revenue;

    constructor() {
        lottery = new CyberScratchLottery();
        initialOwner = lottery.owner();
    }

    /// `buyTicket` requires msg.value == ticketPrice exactly, which a value
    /// fuzzer almost never hits by chance; this wrapper pays the exact price
    /// so the real code path is exercised.
    function buyTicketExact() public payable {
        uint256 price = lottery.ticketPrice();
        lottery.buyTicket{value: price}();
        revenue += price;
    }

    function buyTicket() public payable {
        lottery.buyTicket{value: msg.value}();
        revenue += msg.value;
    }

    function withdrawFunds() public {
        lottery.withdrawFunds();
    }

    /// Property (SWC-120): the win/lose outcome must NOT be a pure function
    /// of public, pre-transaction block data. The real contract derives its
    /// random number from (block.timestamp, block.difficulty, msg.sender),
    /// so a player can compute the result before sending and only play on a
    /// winning block. This property restates exactly that derivation; it is
    /// violated whenever the public inputs already decide "win".
    function echidna_randomness_not_publicly_predictable() public view returns (bool) {
        uint256 r = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            address(this)
        ))) % 100;
        return r >= lottery.winProbability();
    }

    /// Property: ownership must never change.
    function echidna_owner_unchanged() public view returns (bool) {
        return lottery.owner() == initialOwner;
    }

    /// Property: payouts must stay within ticket revenue.
    function echidna_payouts_within_revenue() public view returns (bool) {
        return lottery.totalPayouts() <= revenue;
    }

    receive() external payable {}
}
