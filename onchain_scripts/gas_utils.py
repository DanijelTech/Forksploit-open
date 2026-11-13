# Author: DanyTech
"""
gas_utils.py -- precise gas limit and fee calculation for onchain test/demo
transactions (e.g. deploying and exercising the intentionally-vulnerable
Sepolia demo contracts, or broadcasting a generated exploit by hand while
Foundry isn't available). Never hand-guess a gas limit or reuse a flat
"gasPrice" number; both of those fail in different, easy-to-hit ways.

Two independent things have to be right, and they fail in DIFFERENT
directions, so they need different fixes:

1. GAS LIMIT (how much gas the tx is allowed to use). Getting this wrong
   low = the tx reverts with "out of gas" and you lose 100% of the gas it
   did consume for nothing (the worst outcome: you pay and get nothing).
   Getting it high does NOT cost anything extra by itself -- Ethereum only
   ever charges for gas actually USED, never for unused headroom in the
   limit. So there is no "too much gas limit" fee problem; there is only
   "too little" (revert) vs "wasteful to guess instead of calculate".
   Fix: always call eth_estimateGas (the node's own precise simulation of
   exactly how much the call needs against CURRENT chain state), then add
   a small, justified margin -- not to compensate for a bad guess, but
   because state can drift by a few gas units between the estimate and
   the block the tx actually lands in (e.g. a storage slot that was
   "warm" during estimation could be "cold" by inclusion time, which is
   genuinely more expensive, not an estimation error). Note that gas need
   is state-dependent, not a fixed property of the function being called
   -- the same call can cost very different amounts of gas depending on
   whether storage it touches is already initialized, which is exactly why
   a fixed, hand-picked gas limit is never the right approach.

2. GAS PRICE (what you pay per unit of gas actually used). This is where
   real overpaying happens, and only for legacy (type-0) transactions:
   a type-0 tx pays EXACTLY gasPrice * gasUsed, no refund mechanism, so if
   you fetch a padded/conservative w3.eth.gas_price and use it directly,
   you overpay by exactly that padding, every single transaction. EIP-1559
   (type-2) transactions fix this structurally: you only ever pay
   (baseFee + priorityFee) per gas, where baseFee is set by the PROTOCOL
   from the previous block (not something you can underpay/overpay since
   it's not your choice), and any headroom between your maxFeePerGas
   ceiling and the real baseFee is automatically refunded. The only
   genuine overpay risk left on a 1559 tx is setting the priority tip
   (maxPriorityFeePerGas) higher than needed -- that part IS fully paid to
   the validator, no refund.
   Fix: always send type-2 transactions with maxPriorityFeePerGas pulled
   from the node's own market-based suggestion (w3.eth.max_priority_fee),
   and maxFeePerGas computed from the CURRENT base fee with headroom for a
   couple of blocks of base-fee increase (the standard formula most
   wallets/libraries use), never a flat guessed number.

Usage:
    from gas_utils import build_precise_tx, describe_actual_cost

    tx = {"from": acct.address, "to": target, "data": calldata, "value": 0,
          "nonce": w3.eth.get_transaction_count(acct.address),
          "chainId": w3.eth.chain_id}
    precise_tx = build_precise_tx(w3, tx)
    signed = acct.sign_transaction(precise_tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(describe_actual_cost(w3, receipt))
"""
from __future__ import annotations

from web3 import Web3
from web3.types import TxParams

from chains import native_symbol_for_w3


# How much extra gas-limit headroom to add on top of eth_estimateGas's own
# number, as a fraction (0.1 = +10%). This is NOT compensation for a bad
# guess -- eth_estimateGas already gives the precise minimum against
# *current* state. It's insurance against that minimum shifting slightly
# by the time the tx actually gets included (a different block number,
# a storage slot's warm/cold status changing, etc.). 10% is the same order
# of magnitude most wallets/SDKs use for this exact reason.
DEFAULT_GAS_LIMIT_MARGIN = 0.10

# ABSOLUTE, HARD ceiling on any transaction's gas limit -- no code path may
# ever sign a tx above this, on any chain, for any reason. Confirmed
# necessary live on ETC mainnet: the block gasLimit there fluctuates
# (observed 8,000,000 in most blocks, 8,007,811 in others). estimate_gas_limit
# used to fall back to the bare block gasLimit when eth_estimateGas returned
# an inflated number, so a tx was signed with gas=8,007,811 -- valid only
# while the block limit happened to sit at that value, and permanently
# un-includable the instant it dropped back to 8,000,000. Worse, that stuck
# tx then poisoned the wallet's nonce: every later tx queued behind it
# forever (observed as web3 TimeExhausted after 180s, aborting the whole
# run). Capping every tx at a fixed 8,000,000 (and never at the raw,
# fluctuating block limit) makes that impossible.
MAX_GAS_LIMIT = 8_000_000

# How many blocks of base-fee *increase* to protect maxFeePerGas against.
# Base fee can change by at most 12.5% per block (EIP-1559 rule, true on
# both Sepolia and mainnet), so covering 2 blocks of worst-case increase is
# standard practice (this is what ethers.js and most wallets use) -- and
# again, none of this headroom is actually paid unless the base fee really
# rises that much; it's a ceiling, not a price.
BASE_FEE_LOOKAHEAD_BLOCKS = 2


class GasExceedsBlockLimitError(Exception):
    """Raised by estimate_gas_limit only when eth_estimateGas's own number
    (before any margin) exceeds the chain's REAL current block.gasLimit
    AND a direct eth_call probe at exactly that block.gasLimit ALSO
    reverts -- i.e. only when actually, verifiably impossible, not merely
    "estimateGas said a big number."

    First observed 2026-11-02 (real ETC mainnet, plan C9f53_2) without
    any such probe: estimate_gas_limit returned ~50M gas against a real
    block.gasLimit of exactly 8,000,000, and the only way the caller
    found out back then was eth_sendRawTransaction rejecting the
    already-signed tx after a real signature had already been produced.
    That version of this check assumed "estimateGas's own number exceeds
    block.gasLimit" was ALWAYS proof of genuine impossibility.

    Found WRONG 2026-11-03, on the SAME real contract (0x9f5304..., a
    different plan this time): eth_estimateGas again claimed ~49.6M gas,
    but a direct eth_call with EXACTLY block.gasLimit (8,000,000)
    succeeded cleanly -- the estimate itself was simply wrong, not proof
    of impossibility. Root cause: eth_estimateGas's binary search can
    return a wildly inflated, wrong number when a call's real gas need is
    NON-MONOTONIC in the gas it's given (e.g. something in the call chain
    branches on `gasleft()`) -- a known EVM/geth gotcha, not a
    ForkSploit-specific bug. estimate_gas_limit now cross-checks any
    over-limit estimate against a real eth_call at the block's own gas
    limit before giving up, and uses that verified, real block_gas_limit
    value directly when the probe succeeds -- this error now only fires
    when the probe ALSO reverts, meaning the trace really is unexecutable
    on this chain, not just "estimateGas returned something big." Callers
    (execute_plan, execute_flat_plan_via_flashloan, etc.) should catch
    this ALONGSIDE GasBudgetExceeded and report it as a clean NOT
    CONFIRMED, not let it surface as a raw RPC rejection."""


def estimate_gas_limit(w3: Web3, tx: TxParams, margin: float = DEFAULT_GAS_LIMIT_MARGIN) -> int:
    """
    Precise gas limit: ask the node to simulate the exact call against
    current state (this ALSO means a tx that would revert is caught here,
    for free, before any real gas is spent broadcasting it), then add a
    small margin for state drift between now and inclusion.

    Also checked HERE, before any margin or signing happens: the raw
    estimate against the chain's REAL current block.gasLimit. A trace
    that already needs more gas than any real block can ever hold is not
    a "needs more margin" situation -- it is permanently unexecutable on
    this chain, and the caller needs to know that cleanly and early
    rather than via an eth_sendRawTransaction rejection after signing.
    """
    estimated = w3.eth.estimate_gas(tx)
    block_gas_limit = w3.eth.get_block("latest")["gasLimit"]
    # The hard ceiling is the MINIMUM of the configured cap and the chain's
    # own current block limit -- never above either. The block limit is
    # read fresh every call because it is not a constant: on ETC mainnet it
    # moves between 8,000,000 and 8,007,811 block to block, and a tx signed
    # at the higher value is un-includable once it drops back (and then
    # blocks the nonce forever).
    hard_ceiling = min(MAX_GAS_LIMIT, block_gas_limit)
    if estimated > hard_ceiling:
        # eth_estimateGas's binary search can return a wildly wrong,
        # inflated number when a call's real gas consumption is
        # NON-MONOTONIC in the gas it's given (e.g. something in the call
        # chain branches on `gasleft()`) -- a known EVM/geth gotcha, not
        # a ForkSploit-specific bug. Confirmed live on a real ETC mainnet
        # contract (0x9f5304..., via AttackWallet.execute()):
        # eth_estimateGas claimed 49,610,942 gas was needed (over 6x the
        # real 8,000,000 block gas limit), yet a direct eth_call with
        # EXACTLY the real block_gas_limit succeeded cleanly, proving the
        # estimate itself was simply wrong, not that the trace is
        # unexecutable. Before giving up, sanity-check the inflated
        # estimate against reality: a real eth_call at the hard ceiling.
        # If THAT doesn't revert, the ceiling is a real, working gas value
        # -- use it directly (no margin multiplication, since that would
        # push back over the ceiling this value already sits at).
        probe_tx = dict(tx)
        probe_tx["gas"] = hard_ceiling
        try:
            w3.eth.call(probe_tx)
        except Exception as probe_exc:
            raise GasExceedsBlockLimitError(
                f"required gas ({estimated}) exceeds the hard ceiling ({hard_ceiling} = min(MAX_GAS_LIMIT={MAX_GAS_LIMIT}, "
                f"block_gas_limit={block_gas_limit})) -- I also checked with eth_call at this ceiling, and it "
                f"really does revert ({probe_exc}), so this trace is genuinely not executable on the real chain, regardless of margin."
            ) from probe_exc
        return hard_ceiling
    # Margin for state drift, but never past the hard ceiling: a trace that
    # estimates just under the cap must not be pushed back over it by the
    # margin, or the resulting tx becomes un-includable for exactly the
    # fluctuation reason above.
    return min(int(estimated * (1 + margin)), hard_ceiling)


def get_fee_fields(w3: Web3, lookahead_blocks: int = BASE_FEE_LOOKAHEAD_BLOCKS,
                   chain: str | None = None, use_official: bool = True) -> dict:
    """
    Precise fee fields -- EIP-1559 where the chain supports it, legacy
    gasPrice where it doesn't. maxPriorityFeePerGas comes straight from
    the node's own market-based suggestion (what it thinks validators are
    actually accepting right now), not a guess. maxFeePerGas is the
    current base fee multiplied up to cover `lookahead_blocks` worth of
    the maximum possible 12.5%-per-block base-fee increase, plus the tip --
    a ceiling, not a price: you only ever pay the real base fee (set by
    the protocol, not you) plus your tip, and the unused headroom between
    your ceiling and the real base fee is automatically refunded.

    Gas-FEE PRICE is additionally cross-checked against the chain's own
    OFFICIAL explorer (Etherscan v2 for ETH, Blockscout v2 for ETC) via
    gas_oracle.py, so the price paid is the real market median rather than
    a single node's padded quote -- this matters most on legacy chains
    (ETC), where there is no refund mechanism and a padded gasPrice is
    paid in full on every transaction. This is best-effort: any official-
    source failure degrades silently to the node's own reading, so it can
    never break a run that would otherwise work. Pass use_official=False
    to skip it entirely.

    Some chains never activated EIP-1559 at all -- confirmed live on ETC
    mainnet via two independent nodes (a local core-geth and a public
    endpoint): `baseFeePerGas` is simply absent from every block, not a
    transient zero, so reading it unconditionally used to raise a bare
    KeyError on the very first real signed transaction on that chain.
    Falls back to a plain legacy gasPrice quote in that case instead.
    The returned dict's "maxFeePerGas" key is always present either way
    (every caller doing GasBudget worst-case math reads that key
    regardless of chain type) -- "is_legacy" says which actual tx shape
    `build_precise_tx` needs to produce from it.
    """
    latest = w3.eth.get_block("latest")
    if "baseFeePerGas" not in latest:
        node_base_fee = None
        node_gas_price = w3.eth.gas_price
        node_priority_fee = None
        base_fields = {
            "gasPrice": node_gas_price,
            "maxFeePerGas": node_gas_price,
            "is_legacy": True,
        }
    else:
        node_base_fee = latest["baseFeePerGas"]
        node_priority_fee = w3.eth.max_priority_fee
        node_gas_price = None
        max_fee = int(node_base_fee * ((1 + 0.125) ** lookahead_blocks)) + node_priority_fee
        base_fields = {
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": node_priority_fee,
            "is_legacy": False,
        }

    if not use_official:
        return base_fields
    try:
        import gas_oracle
        if chain is None:
            chain = gas_oracle._chain_name_from_w3(w3)
        quote = gas_oracle.fetch_official_gas_quote(chain)
        official = gas_oracle.compute_fee_fields(
            quote,
            node_base_fee=node_base_fee,
            node_priority_fee=node_priority_fee,
            node_gas_price=node_gas_price,
            lookahead_blocks=lookahead_blocks,
        )
        # Keep the node-derived fields as the authority for anything the
        # official path didn't override, and preserve maxFeePerGas's
        # presence for every caller that reads it unconditionally.
        merged = dict(base_fields)
        merged.update({k: v for k, v in official.items() if v is not None})
        merged["maxFeePerGas"] = official.get("maxFeePerGas") or base_fields.get("maxFeePerGas")
        return merged
    except Exception:
        return base_fields


def tx_worst_case_price(tx: TxParams) -> int:
    """The per-gas price to multiply by `tx["gas"]` for a worst-case-cost
    estimate, regardless of whether `tx` ended up EIP-1559- or
    legacy-shaped (see get_fee_fields/build_precise_tx)."""
    return tx.get("maxFeePerGas") or tx["gasPrice"]


def build_precise_tx(w3: Web3, tx: TxParams, margin: float = DEFAULT_GAS_LIMIT_MARGIN,
                     chain: str | None = None) -> TxParams:
    """
    Takes a tx dict with from/to/data/value/nonce/chainId already set (but
    no gas/gasPrice/maxFeePerGas fields -- those are what this function
    calculates), and returns it ready to sign: precise gas limit via
    simulation + margin, precise fee fields from current network
    conditions (EIP-1559 or legacy, see get_fee_fields). Raises (via
    estimate_gas) if the call would revert, so a bad transaction is
    caught before it ever costs real gas.

    The returned dict is deliberately EITHER fully EIP-1559-shaped
    (maxFeePerGas/maxPriorityFeePerGas/type=2) OR fully legacy-shaped
    (gasPrice, no type key at all) -- never both. Confirmed live: passing
    both maxFeePerGas and gasPrice to eth_account's sign_transaction (or
    passing an explicit type=0) raises a TypeError ("Unknown kwargs"/
    "Unknown Transaction type: 0"); for a legacy chain, the "type" key
    must be omitted entirely, not set to 0.
    """
    tx = dict(tx)
    tx["gas"] = estimate_gas_limit(w3, tx, margin)
    # Defence in depth: estimate_gas_limit already clamps to MAX_GAS_LIMIT on
    # every path, but this is the ONE place a gas limit becomes a signed tx,
    # so clamp again here. A future change to estimate_gas_limit must not be
    # able to sign a tx above the cap by accident.
    tx["gas"] = min(tx["gas"], MAX_GAS_LIMIT)
    fee_fields = get_fee_fields(w3, chain=chain)
    if fee_fields["is_legacy"]:
        tx["gasPrice"] = fee_fields["gasPrice"]
    else:
        tx["maxFeePerGas"] = fee_fields["maxFeePerGas"]
        tx["maxPriorityFeePerGas"] = fee_fields["maxPriorityFeePerGas"]
        tx["type"] = 2
    return tx


def describe_actual_cost(w3: Web3, receipt) -> str:
    """
    After a tx lands, report what it ACTUALLY cost -- gasUsed and
    effectiveGasPrice are both real, final numbers from the receipt, not
    estimates -- so there's no ambiguity about whether the calculation
    above was accurate.
    """
    gas_used = receipt["gasUsed"]
    effective_price = receipt.get("effectiveGasPrice", 0)
    cost_wei = gas_used * effective_price
    return (
        f"gasUsed={gas_used}, effectiveGasPrice={effective_price} wei "
        f"({w3.from_wei(effective_price, 'gwei')} gwei), "
        f"actual fee paid={w3.from_wei(cost_wei, 'ether')} {native_symbol_for_w3(w3)}"
    )


class GasBudgetExceeded(Exception):
    """Raised by GasBudget.reserve() -- a plan's own send_call()/sign_step()
    calls are expected to let this propagate up and abort the plan
    (PLAN_NOT_CONFIRMED-style, safe to retry), never swallow it."""


class GasLedger:
    """Accumulates the REAL gas actually paid by the funding wallet across
    one plan (every tx it sent: funding, deploys, exploit steps, cleanup
    sweeps), so the reported profit is NET of cost rather than a gross
    balance delta that overstates the win.

    Distinct from GasBudget: GasBudget is a forward-looking circuit breaker
    (reserve worst-case BEFORE each send, cap the total). GasLedger is
    backward-looking bookkeeping (record the receipt's real cost AFTER
    each send) -- one answers "may I send this?", the other "what did this
    plan really cost me?". Both are needed: a plan can stay well under its
    budget and still have cost real money that must be netted out.

    Every record() call takes a real receipt's own gasUsed *
    effectiveGasPrice, never an estimate -- the same discipline as
    GasBudget.settle and describe_actual_cost.
    """

    def __init__(self):
        self.spent_wei = 0
        self.tx_count = 0
        # Total GAS UNITS (receipts' own gasUsed summed), distinct from the
        # wei cost above: the proof gate reports "gas_used" in units, while
        # profitability is decided in wei. Both come from the same real
        # receipts, never an estimate.
        self.gas_units = 0

    def record(self, receipt) -> int:
        """Adds one real receipt's actual cost. Returns that cost."""
        cost = receipt["gasUsed"] * receipt.get("effectiveGasPrice", 0)
        self.spent_wei += cost
        self.gas_units += receipt["gasUsed"]
        self.tx_count += 1
        return cost

    def record_many(self, receipts) -> int:
        return sum(self.record(r) for r in receipts)


def net_profit_wei(gross_delta_wei: int, gas_spent_wei: int) -> int:
    """Profit that is actually kept: what landed on the recovery wallet
    MINUS what the funding wallet paid in real gas to make it land.

    This is the honest bottom line -- a plan whose gross delta is smaller
    than its own gas bill is a NET LOSS, and reporting the gross number
    alone (as a bare "gained X" line does) would overstate it. Kept as a
    plain function so the arithmetic is unit-testable with no chain
    involved; can go negative on purpose, since "this cost more than it
    made" is exactly the fact a caller needs to see, not something to
    clamp away."""
    return gross_delta_wei - gas_spent_wei


def format_wei_signed(w3, wei: int) -> str:
    """Formats `wei` as a native-unit string, allowing NEGATIVE values.

    Web3.from_wei() rejects anything below 0 ("value must be between 0 and
    2**256 - 1"), which is exactly what a net loss is -- so a bare
    from_wei(net) crashes precisely in the case this reporting exists to
    surface. Formats the magnitude and prepends the sign instead."""
    if wei < 0:
        return "-" + str(w3.from_wei(-wei, "ether"))
    return str(w3.from_wei(wei, "ether"))



class GasBudget:
    """Hard, per-plan ceiling on the funding wallet's own gas spending --
    one plan/bundle gets ONE bounded budget (a REAL estimate, computed
    before any real send, times 1.10), never an unbounded "however many
    transactions it takes". This is a circuit breaker, not a prediction:
    it is checked BEFORE every real send (reserve, using that
    transaction's own worst-case cost: gas limit * maxFeePerGas, the most
    it could ever cost under EIP-1559 -- never the as-yet-unknown real
    cost), and the plan is aborted rather than sent if that would exceed
    the cap. After a transaction lands, `settle()` reconciles the
    reservation with the real receipt cost, freeing the (usually
    nonzero, thanks to EIP-1559's automatic refund of unused headroom)
    difference for whatever in the same plan sends next.

    The cap itself should come from a REAL estimate for THIS plan, not a
    guessed constant: the atomic-bundle path's eth_callBundle simulation
    already reports a real totalGasUsed before any real submission; the
    sequential path's build_precise_tx already calls eth_estimateGas for
    every step it sends (accurate there specifically because, unlike the
    bundle case, each step is estimated against real chain state AFTER
    every earlier step in the same plan has already landed).
    """

    def __init__(self, cap_wei: int):
        self.cap_wei = cap_wei
        self.reserved_wei = 0
        self.spent_wei = 0

    def reserve(self, worst_case_wei: int, label: str) -> None:
        if self.reserved_wei + worst_case_wei > self.cap_wei:
            raise GasBudgetExceeded(
                f"Refusing to send '{label}': reserving its worst-case cost ({worst_case_wei} wei) would push "
                f"this plan's total reserved gas spend to {self.reserved_wei + worst_case_wei} wei, over its "
                f"{self.cap_wei} wei budget ({self.reserved_wei} wei already reserved, {self.spent_wei} wei "
                "actually spent so far this plan) -- aborting rather than risk spending more than this plan was "
                "ever estimated to need."
            )
        self.reserved_wei += worst_case_wei

    def settle(self, worst_case_wei: int, actual_wei: int) -> None:
        self.reserved_wei -= worst_case_wei
        self.spent_wei += actual_wei

    def release(self, worst_case_wei: int) -> None:
        """Undo a reserve() for a send that was never actually submitted
        (e.g. the node rejected it and the caller will retry with a higher
        price). Without this the reservation leaks and the retry looks
        like it would exceed the plan's budget."""
        self.reserved_wei -= worst_case_wei


def gas_fit(gas_estimate: int, block_gas_limit: int, margin: float = DEFAULT_GAS_LIMIT_MARGIN) -> dict:
    """PHASE 1.2/1.3: turn a real `eth_estimateGas` result and the chain's
    current `block.gasLimit` into the three plan fields the report carries
    -- `gas_estimate`, `fits_block_gas_limit`, `gas_headroom_pct`.

    This is the honest, non-metered answer to "does this plan fit in a
    block": the revm model has no gas metering, so the authoritative
    number is the node's own estimate, and the honest question is whether
    that estimate -- PLUS the same margin a real send would add -- fits
    under the real block limit. A plan whose estimate only fits WITHOUT the
    margin would be signed at the cap and rejected the moment the block
    limit drifts, so `fits` is judged on the margin-inclusive limit, not
    the raw estimate.

    Pure arithmetic, no Web3, so it is unit-testable with no chain. Returns
    {"gas_estimate", "gas_limit_with_margin", "block_gas_limit",
     "fits_block_gas_limit", "gas_headroom_pct"} where headroom is the
    fraction of the block limit left unused by the margin-inclusive limit
    (negative when it does not fit)."""
    if block_gas_limit <= 0:
        raise ValueError("block_gas_limit must be positive")
    limit_with_margin = int(gas_estimate * (1 + margin))
    headroom_pct = round((block_gas_limit - limit_with_margin) / block_gas_limit * 100, 4)
    return {
        "gas_estimate": gas_estimate,
        "gas_limit_with_margin": limit_with_margin,
        "block_gas_limit": block_gas_limit,
        "fits_block_gas_limit": limit_with_margin <= block_gas_limit,
        "gas_headroom_pct": headroom_pct,
    }
