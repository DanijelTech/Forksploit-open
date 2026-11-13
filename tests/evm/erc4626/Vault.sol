// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

interface IAsset {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

// Intentionally vulnerable ERC4626-style vault (no virtual-shares / dead-shares
// protection) used to smoke-test the ERC4626 share-inflation oracle: a direct
// `Asset.transfer` to this contract inflates totalAssets() without touching
// totalSupply(), which is exactly the donation/inflation attack setup step.
contract Vault {
    IAsset public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function setAsset(address _asset) public {
        asset = IAsset(_asset);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        uint256 supply = totalSupply;
        if (supply == 0) {
            shares = assets;
        } else {
            shares = (assets * supply) / totalAssets();
        }
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
        totalSupply = supply + shares;
        balanceOf[receiver] += shares;
    }

    function mint(uint256 shares, address receiver) public returns (uint256 assets) {
        uint256 supply = totalSupply;
        if (supply == 0) {
            assets = shares;
        } else {
            assets = (shares * totalAssets()) / supply;
        }
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
        totalSupply = supply + shares;
        balanceOf[receiver] += shares;
    }
}
