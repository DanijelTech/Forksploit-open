#!/usr/bin/env python3
"""Deploy a set of intentionally-vulnerable demo contracts to Sepolia and
save their addresses to deployed.json -- used to validate forksploit's
detectors/exploit-generators end to end against a real chain (Foundry
isn't required: this signs and broadcasts raw transactions with web3.py).

Prerequisites (none of these are committed -- keep them local, next to this
script, or point HERE at wherever they live):
  - key.txt: the deployer's private key, one line, no "0x" needed either way.
  - <Name>.bin: each contract's compiled init bytecode (`solc --bin`), named
    to match the `deploy(...)` calls below.

This is a template for "how we deployed the demo fixtures", not a generic
multi-project deployer -- the contract list and the one `Vault.setAsset`
wiring call at the bottom are specific to this demo set. Adjust both for a
different set of contracts.

Uses gas_utils.py (same directory) for every transaction's gas limit and
fee fields -- see that module's docstring for why a flat/guessed gas value
is never correct, especially here where contract sizes vary a lot.
"""
import json
import sys
from pathlib import Path

from web3 import Web3
from eth_account import Account

from gas_utils import build_precise_tx, describe_actual_cost

HERE = Path(__file__).parent
RPC_URL = "https://ethereum-sepolia.publicnode.com"

with open(HERE / "key.txt") as f:
    PRIVATE_KEY = f.read().strip()

w3 = Web3(Web3.HTTPProvider(RPC_URL))
acct = Account.from_key(PRIVATE_KEY)
print("Deployer:", acct.address)

balance = w3.eth.get_balance(acct.address)
print("Balance:", w3.from_wei(balance, "ether"), "ETH")
if balance == 0:
    print("ERROR: account not funded yet. Fund it and re-run.")
    sys.exit(1)

chain_id = w3.eth.chain_id
print("Chain ID:", chain_id)
nonce = w3.eth.get_transaction_count(acct.address)


def deploy(name, bin_file):
    global nonce
    bytecode = (HERE / bin_file).read_text().strip()
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]
    data = bytes.fromhex(bytecode)
    # No flat/guessed gas limit: build_precise_tx simulates the CREATE
    # itself (so contract size differences between fixtures are each
    # measured individually, not covered by one shared guess), which is
    # exactly what prevents an out-of-gas CREATE -- that burns all the gas
    # it's given AND leaves no contract deployed, the worst possible
    # outcome for a deploy tx.
    tx = build_precise_tx(w3, {"from": acct.address, "nonce": nonce, "data": data, "chainId": chain_id})
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"{name}: sent tx {tx_hash.hex()} (gas limit {tx['gas']}), waiting for receipt...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    addr = receipt.contractAddress
    print(f"{name}: deployed at {addr} (status={receipt.status}) -- {describe_actual_cost(w3, receipt)}")
    nonce += 1
    if receipt.status != 1:
        raise RuntimeError(f"{name} deployment failed")
    return addr


def call(name, to_addr, data_hex, value=0):
    global nonce
    data = bytes.fromhex(data_hex[2:] if data_hex.startswith("0x") else data_hex)
    tx = build_precise_tx(
        w3,
        {
            "from": acct.address,
            "to": Web3.to_checksum_address(to_addr),
            "nonce": nonce,
            "data": data,
            "value": value,
            "chainId": chain_id,
        },
    )
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"{name}: sent tx {tx_hash.hex()} (gas limit {tx['gas']}), waiting for receipt...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    print(f"{name}: status={receipt.status} -- {describe_actual_cost(w3, receipt)}")
    nonce += 1
    if receipt.status != 1:
        raise RuntimeError(f"{name} call failed")


if __name__ == "__main__":
    deployed = {}
    deployed["Asset"] = deploy("Asset", "Asset.bin")
    deployed["Vault"] = deploy("Vault", "Vault.bin")
    deployed["AccessControl"] = deploy("AccessControl", "AccessControl.bin")
    deployed["SigReplay"] = deploy("SigReplay", "SigReplay.bin")
    deployed["Bank"] = deploy("Bank", "Bank.bin")

    # Vault.setAsset(address) selector 0xd0d552dd
    asset_padded = deployed["Asset"][2:].lower().rjust(64, "0")
    call("Vault.setAsset", deployed["Vault"], "0xd0d552dd" + asset_padded)

    with open(HERE / "deployed.json", "w") as f:
        json.dump(deployed, f, indent=2)

    print("\n=== Deployed addresses ===")
    for name, addr in deployed.items():
        print(f"{name}: {addr}")
