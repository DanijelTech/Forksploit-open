// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable ERC1155-shaped contract used to smoke-test the
// batch-transfer path of the NFT-transfer oracle: `safeBatchTransferFrom`
// is missing the caller authorization check.
contract main {
    mapping(address => mapping(uint256 => uint256)) public balanceOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function mint(address to, uint256 id, uint256 amount) public {
        balanceOf[to][id] += amount;
    }

    // BUG: missing caller == from / isApprovedForAll check
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) public {
        for (uint256 i = 0; i < ids.length; i++) {
            require(balanceOf[from][ids[i]] >= amounts[i], "insufficient balance");
            balanceOf[from][ids[i]] -= amounts[i];
            balanceOf[to][ids[i]] += amounts[i];
        }
    }
}
