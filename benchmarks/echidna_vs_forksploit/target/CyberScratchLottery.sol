
// File: @openzeppelin/contracts/utils/ReentrancyGuard.sol


// OpenZeppelin Contracts (last updated v5.1.0) (utils/ReentrancyGuard.sol)

pragma solidity ^0.8.20;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If EIP-1153 (transient storage) is available on the chain you're deploying at,
 * consider using {ReentrancyGuardTransient} instead.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private _status;

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    constructor() {
        _status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if (_status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        _status = ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == ENTERED;
    }
}

// File: Lottery.sol


pragma solidity ^0.8.20;


contract CyberScratchLottery is ReentrancyGuard {
    address public owner;
    uint256 public ticketPrice = 0.1 ether;
    uint256 public maxPrize = 10 ether;
    uint256 public minPrize = 0.1 ether;
    uint256 public winProbability = 65; // 65%
    
    uint256 public totalTickets;
    uint256 public totalPayouts;
    uint256 public biggestWin;
    
    struct Winner {
        address player;
        uint256 amount;
        uint256 timestamp;
    }
    
    Winner[] public winners;
    
    event TicketPurchased(address indexed player, uint256 ticketId);
    event PrizeWon(address indexed winner, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function buyTicket() external payable nonReentrant {
        require(msg.value == ticketPrice, "Incorrect ticket price");
        
        // Generate random number using chain variables
        uint256 randomNumber = uint256(keccak256(abi.encodePacked(
            block.timestamp, 
            block.difficulty, 
            msg.sender
        ))) % 100;
        
        bool isWinner = randomNumber < winProbability;
        uint256 prizeAmount = 0;
        
        if (isWinner) {
            prizeAmount = minPrize + (randomNumber % (maxPrize - minPrize + 1));
            
            // Check contract has enough balance
            require(address(this).balance >= prizeAmount, "Not enough funds in contract");
            
            // Transfer prize
            (bool success, ) = payable(msg.sender).call{value: prizeAmount}("");
            require(success, "Prize transfer failed");
            
            // Record winner
            winners.push(Winner(msg.sender, prizeAmount, block.timestamp));
            totalPayouts += prizeAmount;
            
            if (prizeAmount > biggestWin) {
                biggestWin = prizeAmount;
            }
            
            emit PrizeWon(msg.sender, prizeAmount);
        }
        
        totalTickets++;
        emit TicketPurchased(msg.sender, totalTickets);
    }
    
    function withdrawFunds() external onlyOwner nonReentrant {
        payable(owner).transfer(address(this).balance);
    }
    
    function setTicketPrice(uint256 _price) external onlyOwner {
        ticketPrice = _price;
    }
    
    function getWinners(uint256 count) external view returns (Winner[] memory) {
        uint256 resultCount = count < winners.length ? count : winners.length;
        Winner[] memory result = new Winner[](resultCount);
        
        for (uint256 i = 0; i < resultCount; i++) {
            result[i] = winners[winners.length - 1 - i];
        }
        
        return result;
    }
    
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    // Fallback function to receive ETH
    receive() external payable {}
}