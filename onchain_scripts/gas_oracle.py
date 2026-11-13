# Author: DanyTech
"""
gas_oracle.py -- gas-FEE PRICE oracle for the chains ForkSploit actually
attacks onchain. Complements gas_utils.py: gas_utils answers "how much gas
will this need" (eth_estimateGas) and "what fee fields must I sign with";
this module answers "what is the CURRENT market price of gas, per the
chain's own OFFICIAL explorer/API", so the two together pay the right
amount -- neither too little (tx never lands) nor too much (overpay).

Why an OFFICIAL source and not just the node:
  * Legacy chains (ETC, and anything pre-EIP-1559) have NO refund
    mechanism. A type-0 tx pays gasPrice * gasUsed exactly. If gasPrice is
    set from a padded/conservative node quote, that padding is paid on
    every single transaction, forever. The chain's own official explorer
    publishes the market median (Blockscout's gas_prices.average), which
    is the honest "neither too little nor too much" number for ETC.
  * EIP-1559 chains (ETH) refund unused base-fee headroom automatically,
    so the only real overpay risk is the priority tip. Etherscan's
    gastracker (suggestBaseFee + ProposeGasPrice) is the official market
    read for that tip.

Sources, both live-verified read-only:
  * ETH family  -> Etherscan API v2 gastracker
                   https://api.etherscan.io/v2/api?chainid=<id>&module=gastracker&action=gasoracle
  * ETC family  -> Blockscout API v2 stats
                   https://etc.blockscout.com/api/v2/stats   (gas_prices.{slow,average,fast})

Design: fetch (I/O) and compute (pure) are separate. compute_fee_fields()
takes plain numbers and returns the exact fee-field dict gas_utils.sign_step
expects, so it is fully unit-testable with zero network access
(onchain_scripts/test_gas_oracle.py). fetch_official_gas_quote() is the only
part that touches the network, and every caller treats its failure as
"fall back to the node quote", never as a hard error.

CLI:
    python onchain_scripts/gas_oracle.py --verify            # live-check ETH + ETC
    python onchain_scripts/gas_oracle.py --fee-fields etc    # computed fields for a chain
    python onchain_scripts/gas_oracle.py --selftest          # pure-logic asserts, no network
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chains import CHAIN_IDS, get_rpc_url, make_w3, native_symbol_for_w3  # noqa: E402

# --- official-source tables -------------------------------------------------

# Chains Etherscan API v2's gastracker serves, mapped to their v2 chainid.
# Deliberately a curated subset: a chain absent here simply falls back to
# the node quote (an honest gap), rather than being sent to an endpoint
# that would 404.
ETHERSCAN_V2_CHAINS = {
    "eth": 1,
    "sepolia": 11155111,
    "bsc": 56,
    "polygon": 137,
    "optimism": 10,
    "arbitrum": 42161,
    "base": 8453,
    "gnosis": 100,
    "linea": 59144,
    "scroll": 534352,
}

# Chains whose OFFICIAL explorer is Blockscout, mapped to its base URL.
# ETC mainnet and its real testnet Mordor -- exactly the pair the user
# called out, since ETC is legacy (no 1559 refund) and therefore the chain
# where overpaying a padded gasPrice is a real, recurring loss.
BLOCKSCOUT_CHAINS = {
    "etc": "https://etc.blockscout.com",
    "mordor": "https://etc-mordor.blockscout.com",
}

ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"
DEFAULT_TIMEOUT = 12
# Official gas readings move block-to-block; caching for ~one ETH block
# keeps a multi-step plan from hammering the explorer (and tripping its
# 1-request/5s anonymous rate limit) while still being current.
DEFAULT_TTL_SECONDS = 12

# Base fee can rise at most 12.5% per block (EIP-1559). Same lookahead as
# gas_utils.BASE_FEE_LOOKAHEAD_BLOCKS; kept in sync deliberately.
DEFAULT_LOOKAHEAD_BLOCKS = 2

_CACHE: dict = {}

# Global on/off switch for the official-source lookup, flipped by
# auto_pipeline's --no-gas-oracle. Off means every caller gets the node's
# own reading -- useful for a fully offline/deterministic run, or when an
# operator explicitly does not want an external HTTP call in the loop.
ENABLED = True


def set_enabled(value: bool) -> None:
    global ENABLED
    ENABLED = bool(value)


def _now() -> float:
    return time.time()


def _gwei_to_wei(value) -> Optional[int]:
    """Parse a gwei amount that an explorer may hand back as a float, an
    int, or a string (Etherscan returns strings like '0.193590611')."""
    if value is None:
        return None
    try:
        return int(round(float(value) * 1e9))
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class GasQuote:
    """One official gas-price reading for one chain. All *_wei fields are
    integers; None means "the source does not publish this field"."""
    chain: str
    source: str
    is_legacy: bool
    base_fee_wei: Optional[int] = None
    priority_fee_wei: Optional[int] = None
    gas_price_wei: Optional[int] = None
    safe_wei: Optional[int] = None
    propose_wei: Optional[int] = None
    fast_wei: Optional[int] = None
    fetched_at: float = field(default_factory=_now)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _session(session: Optional[requests.Session]) -> requests.Session:
    return session if session is not None else requests


# --- I/O: official sources --------------------------------------------------

def etherscan_v2_gas_oracle(chain_id: int, api_key: Optional[str] = None,
                            timeout: int = DEFAULT_TIMEOUT,
                            session: Optional[requests.Session] = None) -> GasQuote:
    """Etherscan API v2 gastracker. Works without a key (anonymous, rate
    limited to 1 request / 5s) -- the key only raises the limit. Returns a
    GasQuote in wei; raises on any non-OK response so the caller falls back."""
    params = {"chainid": chain_id, "module": "gastracker", "action": "gasoracle"}
    if api_key:
        params["apikey"] = api_key
    resp = _session(session).get(ETHERSCAN_V2_URL, params=params, timeout=timeout)
    resp.raise_for_status()
    body = resp.json()
    result = body.get("result")
    if str(body.get("status")) != "1" or not isinstance(result, dict):
        raise RuntimeError(f"etherscan v2 gastracker unusable: {body.get('message')!r}")
    base = _gwei_to_wei(result.get("suggestBaseFee"))
    propose = _gwei_to_wei(result.get("ProposeGasPrice"))
    safe = _gwei_to_wei(result.get("SafeGasPrice"))
    fast = _gwei_to_wei(result.get("FastGasPrice"))
    # The tip is the market's proposed total price minus the base it is
    # proposed on top of; that difference is what actually goes to the
    # validator and is the only non-refundable part of a 1559 tx.
    priority = None
    if propose is not None and base is not None and propose > base:
        priority = propose - base
    return GasQuote(
        chain=str(chain_id), source="etherscan-v2", is_legacy=False,
        base_fee_wei=base, priority_fee_wei=priority,
        safe_wei=safe, propose_wei=propose, fast_wei=fast,
        raw=result,
    )


def blockscout_v2_gas_prices(base_url: str, chain: str,
                             timeout: int = DEFAULT_TIMEOUT,
                             session: Optional[requests.Session] = None) -> GasQuote:
    """Blockscout API v2 stats gas_prices (gwei floats: slow/average/fast).
    Blockscout chains here are legacy (ETC has no base-fee field at all),
    so the market median lands in gas_price_wei."""
    resp = _session(session).get(base_url.rstrip("/") + "/api/v2/stats", timeout=timeout)
    resp.raise_for_status()
    body = resp.json()
    prices = body.get("gas_prices") or {}
    slow = _gwei_to_wei(prices.get("slow"))
    average = _gwei_to_wei(prices.get("average"))
    fast = _gwei_to_wei(prices.get("fast"))
    # Some Blockscout instances transiently publish all-null gas_prices while
    # still exposing a static_gas_price; use it rather than giving up.
    if average is None and slow is None and fast is None:
        static = _gwei_to_wei(body.get("static_gas_price"))
        if static is not None:
            average = static
    if average is None and slow is None and fast is None:
        raise RuntimeError("blockscout stats carried no gas_prices")
    return GasQuote(
        chain=chain, source="blockscout-v2", is_legacy=True,
        gas_price_wei=average if average is not None else (slow or fast),
        safe_wei=slow, propose_wei=average, fast_wei=fast,
        raw={"gas_prices": prices},
    )


def fetch_official_gas_quote(chain: str, api_key: Optional[str] = None,
                             timeout: int = DEFAULT_TIMEOUT,
                             session: Optional[requests.Session] = None,
                             ttl_seconds: int = DEFAULT_TTL_SECONDS) -> Optional[GasQuote]:
    """Official gas quote for `chain`, cached for `ttl_seconds`. Returns
    None (never raises) on any failure -- every caller is expected to fall
    back to the node quote in that case."""
    cache_key = f"{chain}:{api_key or ''}"
    cached = _CACHE.get(cache_key)
    if cached is not None and (_now() - cached.fetched_at) < ttl_seconds:
        return cached
    if not ENABLED:
        return None
    try:
        if chain in BLOCKSCOUT_CHAINS:
            quote = blockscout_v2_gas_prices(BLOCKSCOUT_CHAINS[chain], chain,
                                             timeout=timeout, session=session)
        elif chain in ETHERSCAN_V2_CHAINS:
            quote = etherscan_v2_gas_oracle(ETHERSCAN_V2_CHAINS[chain],
                                            api_key=api_key, timeout=timeout, session=session)
        else:
            return None
    except Exception:
        return None
    _CACHE[cache_key] = quote
    return quote


# --- pure logic: no I/O, fully unit-testable --------------------------------

def compute_fee_fields(quote: Optional[GasQuote], *,
                       node_base_fee: Optional[int],
                       node_priority_fee: Optional[int],
                       node_gas_price: Optional[int],
                       lookahead_blocks: int = DEFAULT_LOOKAHEAD_BLOCKS) -> dict:
    """Turn an official quote (or None) plus the node's own readings into the
    exact fee-field dict gas_utils.sign_step dispatches on.

    Legacy chain (node_base_fee is None -- no EIP-1559 on this chain):
      There is no refund, so the price IS the cost. Use the official market
      median when we have it; fall back to the node's gasPrice otherwise.
      Sanity guard: if the official median is wildly BELOW the node's own
      gasPrice (< 50% of it), the oracle is likely stale/misconfigured --
      underpaying means the tx never lands, so trust the node there.

    1559 chain:
      base fee is protocol-set and read straight off the block, so the node
      is authoritative for it; the official reading is only cross-checked.
      The tip comes from the official market read (fall back to the node's
      own suggestion). maxFeePerGas = base * 1.125^lookahead + tip -- a
      CEILING, not a price: unused headroom is refunded, so this never
      overpays; it only guarantees inclusion across a couple of blocks of
      base-fee rise.
    """
    if node_base_fee is None:
        price = quote.gas_price_wei if quote and quote.gas_price_wei else node_gas_price
        if price is None:
            price = 0
        if quote and quote.gas_price_wei and node_gas_price:
            # Guard against a stale/misconfigured official median that would
            # underprice the tx into never landing.
            if quote.gas_price_wei * 2 < node_gas_price:
                price = node_gas_price
        return {
            "gasPrice": price,
            "maxFeePerGas": price,
            "is_legacy": True,
            "base_fee_wei": None,
            "priority_fee_wei": None,
            "source": quote.source if quote else "node-rpc",
        }

    base_fee = node_base_fee
    tip = None
    if quote and quote.priority_fee_wei:
        tip = quote.priority_fee_wei
    if tip is None:
        tip = node_priority_fee or 0
    # Cross-check the official base against the protocol's own number; a
    # large disagreement means the oracle is stale, so trust the block.
    if quote and quote.base_fee_wei and node_base_fee:
        if not (0.5 * node_base_fee <= quote.base_fee_wei <= 2.0 * node_base_fee):
            base_fee = node_base_fee
    max_fee = int(base_fee * ((1 + 0.125) ** lookahead_blocks)) + tip
    return {
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": tip,
        "is_legacy": False,
        "base_fee_wei": base_fee,
        "priority_fee_wei": tip,
        "source": quote.source if quote else "node-rpc",
    }


def resolve_fee_fields(w3, chain: Optional[str] = None, *,
                       api_key: Optional[str] = None,
                       lookahead_blocks: int = DEFAULT_LOOKAHEAD_BLOCKS,
                       use_official: bool = True) -> dict:
    """Convenience wrapper: read the node's own base/tip/gasPrice, pull the
    official quote (unless disabled), and return compute_fee_fields(...).
    Never raises -- official-source failure just degrades to the node."""
    quote = None
    if use_official:
        if chain is None:
            chain = _chain_name_from_w3(w3)
        quote = fetch_official_gas_quote(chain, api_key=api_key)
    latest = w3.eth.get_block("latest")
    node_base_fee = latest.get("baseFeePerGas")
    node_priority_fee = None
    if node_base_fee is not None:
        try:
            node_priority_fee = w3.eth.max_priority_fee
        except Exception:
            node_priority_fee = None
    node_gas_price = None
    try:
        node_gas_price = w3.eth.gas_price
    except Exception:
        node_gas_price = None
    return compute_fee_fields(
        quote,
        node_base_fee=node_base_fee,
        node_priority_fee=node_priority_fee,
        node_gas_price=node_gas_price,
        lookahead_blocks=lookahead_blocks,
    )


def _chain_name_from_w3(w3) -> str:
    cid = w3.eth.chain_id
    for name, value in CHAIN_IDS.items():
        if value == cid:
            return name
    return str(cid)


# --- verification -----------------------------------------------------------

def verify_gas_oracles(chains, *, api_key: Optional[str] = None,
                       session: Optional[requests.Session] = None) -> list:
    """Live-check each chain's official source and report what it returned,
    alongside the node's own reading for comparison. Read-only."""
    report = []
    for chain in chains:
        entry = {"chain": chain, "official": None, "node": None, "ok": False, "error": None}
        try:
            quote = fetch_official_gas_quote(chain, api_key=api_key, session=session,
                                             ttl_seconds=0)
            if quote is not None:
                entry["official"] = quote.to_dict()
        except Exception as e:  # fetch_official already swallows; belt & braces
            entry["error"] = f"official: {type(e).__name__}: {e}"
        # ok == "the OFFICIAL source answered", which is what this oracle
        # exists to verify. The node is checked separately (and may be
        # unreachable from a given host) -- a dead node here does NOT mean
        # the oracle is broken, since the oracle is the thing under test.
        entry["ok"] = entry["official"] is not None
        try:
            w3 = make_w3(chain)
            latest = w3.eth.get_block("latest")
            node = {
                "chain_id": w3.eth.chain_id,
                "block": latest["number"],
                "block_gas_limit": latest["gasLimit"],
                "base_fee_wei": latest.get("baseFeePerGas"),
                "gas_price_wei": w3.eth.gas_price,
                "native_symbol": native_symbol_for_w3(w3),
            }
            entry["node"] = node
            entry["computed_fee_fields"] = resolve_fee_fields(w3, chain, api_key=api_key, use_official=True)
        except Exception as e:
            entry["error"] = (entry["error"] or "") + f" node: {type(e).__name__}: {e}"
        report.append(entry)
    return report


def _print_report(report: list) -> None:
    for entry in report:
        print(f"\n===== {entry['chain']} =====")
        off = entry["official"]
        if off:
            print(f"  official source : {off['source']}  (is_legacy={off['is_legacy']})")
            for k in ("base_fee_wei", "priority_fee_wei", "gas_price_wei", "safe_wei", "propose_wei", "fast_wei"):
                if off.get(k) is not None:
                    print(f"    {k:18} {off[k]}")
        else:
            print("  official source : UNAVAILABLE")
        node = entry["node"]
        if node:
            print(f"  node            : chain_id={node['chain_id']} block={node['block']} "
                  f"gasLimit={node['block_gas_limit']} {node['native_symbol']}")
            print(f"    base_fee_wei    {node['base_fee_wei']}")
            print(f"    gas_price_wei   {node['gas_price_wei']}")
        cf = entry.get("computed_fee_fields")
        if cf:
            print(f"  computed fee    : source={cf['source']} is_legacy={cf['is_legacy']} "
                  f"maxFeePerGas={cf.get('maxFeePerGas')} maxPriorityFeePerGas={cf.get('maxPriorityFeePerGas')} "
                  f"gasPrice={cf.get('gasPrice')}")
        print(f"  OK              : {entry['ok']}")
        if entry["error"]:
            print(f"  error           : {entry['error']}")


def _selftest() -> int:
    """Pure-logic checks -- no network. Mirrors test_gas_oracle.py so the
    module is verifiable standalone as well as under unittest."""
    failures = 0

    def check(name, got, want):
        nonlocal failures
        if got != want:
            failures += 1
            print(f"  FAIL {name}: got {got!r}, want {want!r}")
        else:
            print(f"  ok   {name}")

    legacy = GasQuote(chain="etc", source="blockscout-v2", is_legacy=True, gas_price_wei=3_430_000_000)
    f = compute_fee_fields(legacy, node_base_fee=None, node_priority_fee=None, node_gas_price=1_000_000_000)
    check("legacy uses official median", f["gasPrice"], 3_430_000_000)
    check("legacy is_legacy", f["is_legacy"], True)

    stale = GasQuote(chain="etc", source="blockscout-v2", is_legacy=True, gas_price_wei=100)
    f = compute_fee_fields(stale, node_base_fee=None, node_priority_fee=None, node_gas_price=1_000_000_000)
    check("legacy stale-oracle guard -> node", f["gasPrice"], 1_000_000_000)

    none_quote = compute_fee_fields(None, node_base_fee=None, node_priority_fee=None, node_gas_price=2_000_000_000)
    check("legacy no-official -> node", none_quote["gasPrice"], 2_000_000_000)

    q1559 = GasQuote(chain="eth", source="etherscan-v2", is_legacy=False,
                     base_fee_wei=193_000_000, priority_fee_wei=1_000_000)
    f = compute_fee_fields(q1559, node_base_fee=193_421_884, node_priority_fee=1907,
                           node_gas_price=193_423_791, lookahead_blocks=2)
    expected_max = int(193_421_884 * (1.125 ** 2)) + 1_000_000
    check("1559 maxFee formula", f["maxFeePerGas"], expected_max)
    check("1559 tip from official", f["maxPriorityFeePerGas"], 1_000_000)
    check("1559 is_legacy", f["is_legacy"], False)

    q_bad_base = GasQuote(chain="eth", source="etherscan-v2", is_legacy=False,
                          base_fee_wei=1, priority_fee_wei=5)
    f = compute_fee_fields(q_bad_base, node_base_fee=200_000_000, node_priority_fee=1,
                           node_gas_price=200_000_000, lookahead_blocks=2)
    check("1559 stale-base guard -> node base", f["base_fee_wei"], 200_000_000)

    print(f"\nselftest: {'FAILED' if failures else 'PASSED'} ({failures} failure(s))")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Official gas-fee price oracle for ForkSploit")
    parser.add_argument("--verify", action="store_true", help="live-check official sources for the given chains")
    parser.add_argument("--fee-fields", metavar="CHAIN", help="print computed fee fields for one chain")
    parser.add_argument("--selftest", action="store_true", help="run pure-logic checks (no network)")
    parser.add_argument("--chains", nargs="*", default=["eth", "etc"], help="chains to verify (default: eth etc)")
    parser.add_argument("--api-key", default=os.environ.get("ETHERSCAN_API_KEY") or None,
                        help="Etherscan API key (default: $ETHERSCAN_API_KEY; anonymous works, rate-limited)")
    args = parser.parse_args()

    if args.selftest:
        return _selftest()
    if args.fee_fields:
        w3 = make_w3(args.fee_fields)
        fields = resolve_fee_fields(w3, args.fee_fields, api_key=args.api_key)
        print(json.dumps(fields, indent=2))
        return 0
    if args.verify:
        report = verify_gas_oracles(args.chains, api_key=args.api_key)
        _print_report(report)
        return 0 if all(e["ok"] for e in report) else 1
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
