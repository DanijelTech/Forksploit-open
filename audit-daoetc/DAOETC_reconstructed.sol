// SPDX-License-Identifier: UNLICENSED
// REKONSTRUIRANO iz runtime bytecode (ETC mainnet 0x9f53...5ce3) z pyevmasm.
// Ni uradna izvorna koda; logika prebrana iz disassemblyja in potrjena s forkom.
pragma solidity ^0.4.24;

interface ILedger {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function totalAccounts() external view returns (uint256);
    function sealed() external view returns (bool);
    function fill(uint256[] calldata) external;
    function seal() external;
    function owner() external view returns (address);
}

contract DAOETC {
    address public owner;                     // slot 0
    ILedger public ledger;                    // slot 1 = 0x180826b0...
    mapping(address => uint256) public balances; // slot 2 (getter: getPaidOut)
    mapping(bytes32 => bool) public used;     // slot 3  (porabljene signature)
    uint256 public totalDeposits;             // slot 4
    uint256 public closingTime;               // slot 5  (= block.timestamp ob deployu)
    uint256 public extension;                 // slot 6  (privzeto 0xdd7c00 = 14515200 s)
    address public whgDonationAddress;        // slot 7  (getter: getWHGDonationAddress)
    address public escapeAddress;             // slot 8  (escapeHatch cilj)
    address public claimAddress;              // slot 9  (claimRemaining cilj)
    // bit 0xa0 v slot 9 = "sealed" zastavica

    // ---- VIEW ----
    function getPaidOut(address a) public view returns (uint256) { return balances[a]; }        // 0x57211ac0
    function getWHGDonationAddress() public view returns (address) { return whgDonationAddress; } // 0x64dab283
    function getMyBalance(address a) public view returns (uint256) { return ledger.balanceOf(a); } // 0x7e3ef7cd
    function getTotalFunds() public view returns (uint256) { return ledger.totalSupply(); }     // 0xeb8bbd28
    function getOwner() public view returns (address) { return owner; }                         // 0x893d20e8

    // KONCNO IZPLACILO: tvoj deleZ v ledgerju, omejen z dejansko bilanco v ledgerju
    function calculateWithdraw(address a) public view returns (uint256) {                        // 0x02ef6c86
        uint256 B = ledger.balanceOf(a);
        uint256 T = ledger.totalSupply();
        uint256 S = balances[a];
        uint256 amount = S * T / totalDeposits;   // tvoj deleZ supply-a
        if (B < amount) amount = 0;               // kapica: potrebujes ledger.balanceOf >= amount
        return amount;
    }

    // ---- MUTATIVE ----
    // POZOR: NE pripise balances[msg.sender]! Samo totalDeposits += msg.value.
    function deposit() public payable returns (bool) {                                           // 0xd0e30db0
        totalDeposits += msg.value;
        emit Deposit(msg.value);
        return true;
    }

    function withdraw(address to, uint256 amount) public {                                       // 0xf3fef3a3
        require(msg.value == 0);
        _withdraw(msg.sender, to, amount, 0);
    }

    function proxyWithdraw(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {   // 0xe3ce9714
        require(msg.value == 0);
        bytes32 h = keccak256(abi.encodePacked("Withdraw DAOETC to ", to, amount));
        require(!used[h]);
        address signer = ecrecover(h, v, r, s);   // <-- NE OVREDNOTENO: ni preverbe signer != 0
        used[h] = true;
        _withdraw(signer, to, amount, 1);
    }

    function fill(uint256[] data) public {                                                       // 0x884b5dc2
        require(msg.sender == owner || sealed);
        for (uint256 i = 0; i < data.length; i += 2) {
            balances[address(data[i])] = data[i + 1];
            totalDeposits += data[i + 1];
        }
    }

    function seal() public { require(msg.sender == owner || sealed); sealed = true; }            // 0x3fb27b85
    function extendClosingTime(uint256 t) public { require(msg.sender == owner); extension += t; } // 0x3e2640d6
    function escapeHatch() public { require(msg.sender == owner); escapeAddress.transfer(address(this).balance); } // 0x1554611f
    function claimRemaining() public {                                                           // 0xc01c1ca3
        require(closingTime + extension <= now);
        claimAddress.transfer(address(this).balance);
    }
    function transferOwnership(address a) public { require(msg.sender == owner); owner = a; }    // 0xa6f9dae1

    function _withdraw(address user, address to, uint256 amount, uint256 isProxy) internal {
        uint256 amt = calculateWithdraw(user);
        if (amt > address(this).balance) amt = address(this).balance;
        balances[user] += amt;
        uint256 fee = amt * 100 / FEE_DENOM;    // provizija
        require(address(this).balance - amt <= address(this).balance);
        whgDonationAddress.call.value(fee)("");
        if (amt - fee > 0) to.call.value(amt - fee)("");
        emit Withdrawal(user, to, amt, fee);
    }

    uint256 constant FEE_DENOM = 10000;
    bool public sealed;
    event Deposit(uint256 value);
    event Withdrawal(address indexed user, address indexed to, uint256 amount, uint256 fee);
}
