// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Intentionally vulnerable ERC721-shaped contract used to smoke-test the
// NFT-transfer oracle: `transferFrom` is missing the
// `_isApprovedOrOwner(msg.sender, tokenId)` check, so anyone can move any
// token regardless of ownership/approval.
contract main {
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function mint(address to, uint256 tokenId) public {
        require(ownerOf[tokenId] == address(0), "already minted");
        ownerOf[tokenId] = to;
    }

    // BUG: missing caller authorization check
    function transferFrom(address from, address to, uint256 tokenId) public {
        require(ownerOf[tokenId] == from, "not owner");
        ownerOf[tokenId] = to;
    }
}
