"""flashbots_bundle.py -- real Flashbots bundle submission (eth_sendBundle
/ eth_callBundle against the official relay), not privacy-preserving RPC
redirection. A bundle is a set of pre-signed transactions submitted
together for ATOMIC inclusion in one target block: either every tx in it
lands, or none do. That is a materially different (and stronger)
guarantee than just pointing send_raw_transaction at a different RPC
(Flashbots Protect): a multi-step exploit plan (armCallback -> execute ->
disarmCallback) sent as separate Protect-routed transactions still gives
a front-runner a window between each one landing in its own block; sent
as one bundle, there is no such window -- the whole sequence lands in a
single block or none of it does.

Request signing follows docs.flashbots.net/flashbots-auction/advanced/
rpc-endpoint exactly: keccak256 the raw JSON request body, hex-encode
that hash (keeping the "0x" prefix), EIP-191/personal-sign that hex
STRING (not the raw body) with any ECDSA key, and send
"X-Flashbots-Signature: <signer address>:<signature>" where <signature>
ALSO keeps its own "0x" prefix. The signing key is only a reputation
identity for the relay -- it does not need to be the same key that signs
the bundle's own transactions, though reusing the real signer here is
fine for this project's low-volume use.

Fixed live, 2026-11-02 (previously wrongly blamed on relay-side
datacenter-IP blocking -- it was never that): `sign_request()` used to
build the header as f"{address}:{signed.signature.hex()}" -- no "0x" on
the signature half. That matched the official docs' own published
Python example byte-for-byte (`messages.encode_defunct(text=Web3.keccak
(text=body).hex())`, same missing prefix) -- but NOT the docs' own Go
example, which uses `hexutil.Encode(sig)` and therefore always keeps the
"0x". The real relay was tested directly (eth_callBundle, read-only,
zero cost) against all 4 combinations of {digest with/without "0x",
signature with/without "0x"} -- ONLY "0x" on BOTH parts got past
signature verification (confirmed via a clean transition from
`{"code":-32025,"message":"invalid flashbots signature"}` to a normal
`{"code":-32003,"message":"insufficient funds..."}`, i.e. the relay
actually simulating the (deliberately unfunded, throwaway-key) tx
instead of rejecting the signature). The published Python docs example
is simply wrong for any eth_account/hexbytes version where `.hex()`
doesn't auto-prefix "0x" (hexbytes>=2.0, confirmed current) -- this
project's `sign_request()` happened to already get the DIGEST's "0x"
right (per this module's own original comment) but not the SIGNATURE's.
Reproduced identically from this sandboxed environment AND from a real
residential network (both got the exact same 403/-32025 before this fix)
-- never was a datacenter-IP issue.
"""
import json
import time

import requests
from eth_utils import keccak
from eth_account.messages import encode_defunct
from web3 import Web3

# relay.flashbots.net is mainnet-only; relay-sepolia.flashbots.net is a
# real, separate testnet relay (confirmed via docs.flashbots.net) -- used
# here only to verify the signing/request plumbing without needing real
# mainnet funds or risk.
RELAY_URLS = {
    "eth": "https://relay.flashbots.net",
    "sepolia": "https://relay-sepolia.flashbots.net",
}


def sign_request(acct, payload: dict) -> tuple[bytes, dict]:
    """Returns (raw_body_bytes, headers) for a Flashbots relay POST,
    signed exactly per docs.flashbots.net's spec: keccak256(body) ->
    hex-encode (keep "0x") -> personal-sign that hex STRING -> header is
    "<address>:<sig>", where <sig> ALSO keeps its own "0x" prefix --
    see this module's own doc comment for why that second "0x" is easy
    to miss (hexbytes>=2's .hex() doesn't add it, unlike the docs' Go
    example) and how it was confirmed live against the real relay."""
    body = json.dumps(payload).encode()
    digest_hex = "0x" + keccak(body).hex()
    message = encode_defunct(text=digest_hex)
    signed = acct.sign_message(message)
    header_value = f"{acct.address}:0x{signed.signature.hex()}"
    return body, {"Content-Type": "application/json", "X-Flashbots-Signature": header_value}


def _post(relay_url: str, acct, payload: dict) -> dict:
    body, headers = sign_request(acct, payload)
    resp = requests.post(relay_url, data=body, headers=headers, timeout=30)
    resp.raise_for_status()
    result = resp.json()
    if "error" in result:
        raise RuntimeError(f"Flashbots relay error: {result['error']}")
    return result["result"]


def call_bundle(relay_url: str, acct, raw_txs: list, target_block: int, state_block="latest") -> dict:
    """Simulates the bundle (eth_callBundle) WITHOUT submitting it for
    real -- the standard pre-flight check: a bundle that would revert
    simply never gets included anyway, so simulating first catches that
    for free instead of wasting (and revealing, via a failed real
    submission attempt) a doomed attempt."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_callBundle",
        "params": [{"txs": raw_txs, "blockNumber": hex(target_block), "stateBlockNumber": state_block}],
    }
    return _post(relay_url, acct, payload)


def send_bundle(relay_url: str, acct, raw_txs: list, target_block: int) -> str:
    """Submits the bundle for real, valid for exactly ONE target block --
    returns the relay's bundleHash. No inclusion guarantee; the relay
    just forwards it to builders for that block's auction."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendBundle",
        "params": [{"txs": raw_txs, "blockNumber": hex(target_block)}],
    }
    result = _post(relay_url, acct, payload)
    return result["bundleHash"]


def submit_bundle_and_wait(
    w3: Web3,
    acct,
    raw_txs: list,
    tx_hashes: list,
    relay_url: str,
    tee,
    max_blocks: int = 5,
) -> bool:
    """Simulates once, then resubmits the SAME already-signed bundle
    targeting each of the next `max_blocks` blocks in turn (a bundle is
    only valid for the one block it names, and inclusion is never
    guaranteed, so retargeting the next few blocks is the standard way to
    give a genuinely good bundle a real chance) until it lands or the
    window passes. Returns whether it landed; never silently invents a
    False-looking "it failed" when really it just means "try again
    later" -- the caller treats "did not land" as inconclusive, same as
    every other real-chain-state outcome in this project that isn't a
    confirmed revert."""
    start_block = w3.eth.block_number
    sim = call_bundle(relay_url, acct, raw_txs, start_block + 1)
    if sim.get("firstRevert"):
        tee.log(f"Bundle simulation reverted before any real submission -- not sending: {sim['firstRevert']}", alert=True)
        return False
    tee.log(f"Bundle simulation OK (totalGasUsed={sim.get('totalGasUsed')}), submitting for real...")

    for i in range(1, max_blocks + 1):
        target = start_block + i
        try:
            bundle_hash = send_bundle(relay_url, acct, raw_txs, target)
        except Exception as e:
            tee.log(f"Bundle submission targeting block {target} failed: {e}", alert=True)
            continue
        tee.log(f"Bundle {bundle_hash} submitted, targeting block {target}.")
        while w3.eth.block_number < target:
            time.sleep(3)
        try:
            w3.eth.get_transaction_receipt(tx_hashes[0])
            tee.log(f"Bundle included in block {target}.")
            return True
        except Exception:
            tee.log(f"Not included in block {target} -- retrying for block {target + 1}.")
    tee.log(f"Bundle not included within {max_blocks} blocks of {start_block} -- giving up this attempt.", alert=True)
    return False
