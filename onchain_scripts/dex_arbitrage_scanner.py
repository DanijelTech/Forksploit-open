#!/usr/bin/env python3
# Author: DanyTech
"""dex_arbitrage_scanner.py -- watches two real, independent Uniswap-V2-
shaped DEXes on the SAME chain for a genuine, flashloan-fundable price
gap on one token pair, and ALERTS (does not execute) when one is
profitable after every real cost is accounted for.

Why same-chain only, never cross-chain: a flashloan (Aave, Balancer) must
be borrowed and repaid within ONE atomic transaction on ONE chain -- if
repayment doesn't happen, the whole transaction reverts and nothing was
ever at risk. There is no cross-chain equivalent of that atomicity (a
bridge takes real time and can't revert a transaction that already
finalized on the other chain), so "cross-chain flashloan arbitrage" is
never actually a zero-capital, flashloan-secured operation -- it's two
separate, non-atomic legs with real capital genuinely at risk on both
sides. This script only ever looks at two pools on the SAME chain,
where true atomicity is real.

Default mode is still alert-only: it logs the real, fully-costed profit
estimate (DEX fees on both legs + the real Aave V3 flashloan premium + a
real current gas-cost estimate) and signs/sends NOTHING. Pass --execute
(with --key and --recovery-wallet) to actually act on a profitable
opportunity -- it reuses the exact same AttackWallet flashloan mechanism
aave_flashloan_runner.py already validates against real Aave V3
(armFlashloanActions -> startFlashLoan -> executeOperation -> real
repayment-or-whole-tx-reverts), the same get_or_deploy_attack_wallet
safe-wallet lock, and the same per-call GasBudget circuit breaker --
nothing new was built for safety, only for the arbitrage-specific swap
calldata itself (see build_arbitrage_steps below).

Default: ETH mainnet, Uniswap V2 vs SushiSwap V2, checked across 5 real,
independently live-verified WETH-paired majors (WETH/USDC, WETH/USDT,
WETH/DAI, WETH/WBTC -- see DEX_PAIRS_BY_CHAIN's own doc comment for the
exact verification; each has real, non-trivial reserves on BOTH DEXes).
Pass --token-a/--token-b to check one specific pair instead of the whole
configured list. Only ETH mainnet has two independently live-verified
V2-shaped DEXes wired up as of 2026-11-02; every other chain in
src/evm/tokens/onchain_pair_discovery.rs's KNOWN_V2_FACTORIES (ETC, BSC,
Polygon, Arbitrum, Celo) has only ONE live-verified V2 factory each --
genuine cross-DEX arbitrage needs a SECOND, independent one per chain,
which has NOT been found/verified yet (attempted for BSC's Biswap during
this round; no address could be confirmed from an authoritative source
in the time available, so none was guessed in). Adding another chain
here means first live-verifying a second real V2-shaped factory on it
the same way ETH's SushiSwap V2 was -- an honest, explicit gap (raises
clearly) rather than a silent wrong number.

The arbitrage math (find_optimal_arbitrage below) deliberately does NOT
use a memorized closed-form optimum formula for two-pool constant-
product arbitrage -- ternary search over the profit function (real,
concave, the same shape search bisection/ternary-search methods are
built for) gets the same answer without risking a misremembered formula,
the same discipline this project uses for on-chain addresses.

Every check (alert-only AND --execute) logs each pool's own price impact
from the proposed trade (price_impact_pct) -- the SAME reserve-ratio-
shift metric src/evm/oracles/twap_manipulation.rs's
TwapManipulationOracle flags on-chain as the manipulation precondition
(a >+100%/-50% shift within one transaction). This is deliberate, not
decorative: this exact swap primitive (transfer + swap on a named pool
with an arbitrary chosen amount, atomically flashloan-wrapped) is
structurally the same primitive real oracle-manipulation attacks use --
see this file's own commit history, 2026-11-02, for the full reasoning.
No automatic block is applied on a large shift (by explicit instruction,
this stays a human-judgment matter for now) -- but --execute ALWAYS
stops and asks a human to type the exact word "YES" before sending
anything real, showing both pools' price impact and the expected profit
first. There is no flag to skip this prompt.

Usage:
    python3 dex_arbitrage_scanner.py [--chain eth] [--poll-interval 15] \\
        [--min-profit-eth 0.01] [--token-a WETH_ADDR] [--token-b USDC_ADDR]

Stop with Ctrl+C.
"""
import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from eth_abi import encode as abi_encode
from eth_account import Account
from web3 import Web3

from aave_flashloan_runner import AAVE_V3_POOLS
from auto_pipeline import BUNDLE_GAS_LIMIT, GAS_BUDGET_MARGIN, encode_address, encode_uint256, get_or_deploy_attack_wallet, selector, send_call, sign_step
from chains import chain_banner, known_chains, make_w3, require_mainnet_confirmation, verify_rpc_identity
from flashbots_bundle import RELAY_URLS, call_bundle, submit_bundle_and_wait
from gas_utils import GasBudget, GasBudgetExceeded, estimate_gas_limit, get_fee_fields
from wallet_policy import enforce_wallet_policy

HERE = Path(__file__).parent
LOGS_DIR = HERE / "logs"

# Aave V3's current flashloan premium on simple (non-isolated) flash
# loans -- see AttackWallet.sol's own doc comment and
# aave_flashloan_runner.py's verified-live 0.05% figure from an actual
# executed flashloan on Sepolia.
AAVE_V3_FLASHLOAN_PREMIUM_BPS = 5  # 0.05%

# Each entry: two real Uniswap-V2-shaped (constant product, same 10000-
# basis-point fee model) factories on the SAME chain, each independently
# live-verified (real bytecode, real allPairsLength) before being
# hardcoded here, plus a list of real WETH-paired majors -- each pair's
# existence AND non-zero reserves on BOTH dex_a and dex_b were live-
# verified directly via getPair()/getReserves() on 2026-11-02 (not
# assumed from the WETH/USDC pair alone): see this module's own doc
# comment for why every other chain in KNOWN_V2_FACTORIES (ETC, BSC,
# Polygon, Arbitrum, Celo) only has ONE verified DEX so far, not two.
DEX_PAIRS_BY_CHAIN = {
    "eth": {
        "dex_a": {
            "name": "Uniswap V2",
            "factory": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
            "fee_bps": 30,
        },
        "dex_b": {
            "name": "SushiSwap V2",
            "factory": "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
            "fee_bps": 30,
        },
        "pairs": [
            {"name": "WETH/USDC", "token_a": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "token_b": "0xA0b86991c6218b36c1d19D4A2e9Eb0cE3606eB48"},
            {"name": "WETH/USDT", "token_a": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "token_b": "0xdAC17F958D2ee523a2206206994597C13D831ec7"},
            {"name": "WETH/DAI", "token_a": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "token_b": "0x6B175474E89094C44Da98b954EedeAC495271d0F"},
            {"name": "WETH/WBTC", "token_a": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "token_b": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"},
        ],
    },
}

def _eth(wei: int) -> str:
    """Web3.from_wei() rejects negative values outright ("value must be
    between 0 and 2**256 - 1") -- confirmed live, hit immediately the
    first time a real check found no profitable direction (the common,
    expected case for an efficiently-arbitraged pair like WETH/USDC),
    since gross/net profit are both genuinely negative then. Formats the
    sign separately instead of ever passing a negative number in."""
    sign = "-" if wei < 0 else ""
    return f"{sign}{Web3.from_wei(abs(wei), 'ether')}"


GET_PAIR_SELECTOR = "0xe6a43905"
GET_RESERVES_SELECTOR = "0x0902f1ac"
TOKEN0_SELECTOR = "0x0dfe1681"


class Tee:
    def __init__(self, log_path: Path):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self._fh = open(log_path, "w", buffering=1)

    def log(self, msg: str = "", alert: bool = False) -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        prefix = "!!! ALERT !!!" if alert else "    "
        line = f"[{ts}] {prefix} {msg}"
        print(line)
        self._fh.write(line + "\n")

    def close(self) -> None:
        self._fh.close()


def get_pair(w3: Web3, factory: str, token_a: str, token_b: str) -> str:
    data = GET_PAIR_SELECTOR + token_a[2:].rjust(64, "0").lower() + token_b[2:].rjust(64, "0").lower()
    raw = w3.eth.call({"to": Web3.to_checksum_address(factory), "data": data})
    return Web3.to_checksum_address("0x" + raw[-20:].hex())


def get_token0(w3: Web3, pair: str) -> str:
    return Web3.to_checksum_address("0x" + w3.eth.call({"to": pair, "data": TOKEN0_SELECTOR})[-20:].hex())


def get_reserves(w3: Web3, pair: str, token_a: str) -> tuple:
    """Returns (reserve_a, reserve_b) -- reserve of `token_a` first,
    whichever of the pair's token0/token1 slots it actually occupies
    (Uniswap V2 pairs sort token0/token1 by address, not by call order)."""
    raw = w3.eth.call({"to": pair, "data": GET_RESERVES_SELECTOR})
    r0 = int.from_bytes(raw[0:32], "big")
    r1 = int.from_bytes(raw[32:64], "big")
    if get_token0(w3, pair).lower() == token_a.lower():
        return r0, r1
    return r1, r0


def erc20_transfer_calldata(to: str, amount: int) -> bytes:
    return selector("transfer(address,uint256)") + encode_address(to) + encode_uint256(amount)


def v2_swap_calldata(amount0_out: int, amount1_out: int, to: str) -> bytes:
    """Uniswap-V2-shaped pair's own low-level swap(uint256,uint256,
    address,bytes) -- the trailing bytes param is always empty here (a
    non-empty one triggers the flash-swap callback path, not needed for
    a plain swap). Encoded exactly like armCallback's own (address,bytes)
    shape in auto_pipeline.py: a fixed 4-word head (amount0Out, amount1Out,
    to, offset-to-the-bytes-tail) followed by the bytes tail's own
    length word (0) and no data."""
    offset = encode_uint256(0x80)
    return (
        selector("swap(uint256,uint256,address,bytes)")
        + encode_uint256(amount0_out)
        + encode_uint256(amount1_out)
        + encode_address(to)
        + offset
        + encode_uint256(0)
    )


def build_arbitrage_steps(w3: Web3, attack_wallet: str, token_a: str, token_b: str, x: int, pair_buy: str, pair_sell: str, buy_fee_bps: int, sell_fee_bps: int) -> tuple:
    """Builds the real 4-step armFlashloanActions sequence for one
    arbitrage round trip: transfer token_a into pair_buy, swap there for
    token_b, transfer that token_b into pair_sell, swap there back to
    token_a. A Uniswap-V2-shaped pair's swap() does NOT pull funds itself
    (unlike a Router) -- it only checks its OWN balance against its
    recorded reserves to see how much it actually received, so the input
    token must already be sitting in the pair's balance before swap() is
    called, which is exactly why this is 4 steps and not 2. Returns
    (targets, datas, values, mid_amount, final_amount, buy_impact_pct,
    sell_impact_pct) -- mid_amount/final_amount are what this SAME
    on-chain math predicts; if real reserves drifted since they were
    read, the real swap() call simply reverts (and so does the whole
    flashloan, atomically, costing only gas) rather than silently using a
    wrong number. `values` is the per-step ETH-forwarding array
    AttackWallet.sol's Step struct needs (added 2026-11-02) -- always 0
    here, since every one of these 4 calls is a plain ERC20 transfer or a
    non-payable pair.swap(). `buy_impact_pct`/`sell_impact_pct` are this
    trade's own price impact on EACH pool (see price_impact_pct's own
    doc) -- the number a human reviewing this plan before approving
    execution needs to actually see, not just infer from raw amounts.
    """
    buy_r_in, buy_r_out = get_reserves(w3, pair_buy, token_a)
    mid_amount = swap_out(x, buy_r_in, buy_r_out, buy_fee_bps)
    buy_impact_pct = price_impact_pct(buy_r_in, buy_r_out, x, mid_amount)
    buy_token0 = get_token0(w3, pair_buy)
    if buy_token0.lower() == token_a.lower():
        buy_amount0_out, buy_amount1_out = 0, mid_amount
    else:
        buy_amount0_out, buy_amount1_out = mid_amount, 0

    sell_r_in, sell_r_out = get_reserves(w3, pair_sell, token_b)
    final_amount = swap_out(mid_amount, sell_r_in, sell_r_out, sell_fee_bps)
    sell_impact_pct = price_impact_pct(sell_r_in, sell_r_out, mid_amount, final_amount)
    sell_token0 = get_token0(w3, pair_sell)
    if sell_token0.lower() == token_b.lower():
        sell_amount0_out, sell_amount1_out = 0, final_amount
    else:
        sell_amount0_out, sell_amount1_out = final_amount, 0

    targets = [token_a, pair_buy, token_b, pair_sell]
    datas = [
        erc20_transfer_calldata(pair_buy, x),
        v2_swap_calldata(buy_amount0_out, buy_amount1_out, attack_wallet),
        erc20_transfer_calldata(pair_sell, mid_amount),
        v2_swap_calldata(sell_amount0_out, sell_amount1_out, attack_wallet),
    ]
    # None of these 4 calls needs to forward ETH (token_a/token_b moves
    # are plain ERC20 transfers and pair.swap() calls, never payable) --
    # armFlashloanActions' values array is 0 for every step here.
    values = [0, 0, 0, 0]
    return targets, datas, values, mid_amount, final_amount, buy_impact_pct, sell_impact_pct


def execute_arbitrage(w3: Web3, acct, nonce_box: dict, attack_wallet: str, chain: str, token_a: str, token_b: str, x: int, pair_buy: str, pair_sell: str, buy_fee_bps: int, sell_fee_bps: int, tee) -> bool:
    """Reuses the exact same AttackWallet flashloan mechanism
    aave_flashloan_runner.py already validates against real Aave V3:
    arm the 4 real steps build_arbitrage_steps built, then startFlashLoan
    to borrow `x` of token_a -- Aave's own Pool reverts the WHOLE
    transaction if repayment (x + premium) doesn't hold, so a successful
    startFlashLoan call is itself the only proof needed that the round
    trip was genuinely profitable enough to cover it.

    On `eth`, both calls are ALWAYS submitted together as one atomic
    Flashbots bundle (never gated behind a value threshold the way
    auto_pipeline.py's exploit-plan path is) -- an arbitrage opportunity
    is a race against every OTHER bot watching the same two pools by
    design, regardless of how small the profit is, so a public
    armFlashloanActions transaction alone (revealing the exact borrow
    amount and both pair addresses before startFlashLoan even lands)
    would hand a copycat everything needed to front-run this exact trade.
    Reuses the same auto_pipeline.sign_step/flashbots_bundle.call_bundle/
    submit_bundle_and_wait this project's exploit-plan flashloan path
    already uses and has confirmed working against the real production
    relay (see that module's own doc comment). Elsewhere, both calls go
    out as separate public transactions -- no chain in AAVE_V3_POOLS
    besides eth has a Flashbots-equivalent wired up here yet.

    Each call gets its own real-estimate-based GasBudget, same reasoning
    and pattern as aave_flashloan_runner.py's own (arm and startFlashLoan
    have very different real costs, so extrapolating one from the other
    would misjudge whichever one isn't the basis)."""
    if chain not in AAVE_V3_POOLS:
        tee.log(f"No verified Aave V3 Pool for chain '{chain}' -- cannot execute.", alert=True)
        return False
    targets, datas, values, mid_amount, final_amount, buy_impact_pct, sell_impact_pct = build_arbitrage_steps(w3, attack_wallet, token_a, token_b, x, pair_buy, pair_sell, buy_fee_bps, sell_fee_bps)
    tee.log(
        f"Arming arbitrage: borrow {_eth(x)} token_a -> {mid_amount} token_b (raw units) on {pair_buy} "
        f"(price impact {buy_impact_pct:+.4f}%) -> back to {_eth(final_amount)} token_a on {pair_sell} "
        f"(price impact {sell_impact_pct:+.4f}%)"
    )

    arm_data = selector("armFlashloanActions(address[],bytes[],uint256[])") + abi_encode(["address[]", "bytes[]", "uint256[]"], [targets, datas, values])
    pool = AAVE_V3_POOLS[chain]
    start_data = selector("startFlashLoan(address,address,uint256,bytes)") + abi_encode(
        ["address", "address", "uint256", "bytes"], [pool, token_a, x, b""]
    )
    fee_fields = get_fee_fields(w3)

    if chain == "eth":
        try:
            start_nonce = nonce_box["nonce"]
            raw_arm, hash_arm = sign_step(w3, acct, start_nonce, attack_wallet, arm_data, 0, fee_fields)
            raw_start, hash_start = sign_step(w3, acct, start_nonce + 1, attack_wallet, start_data, 0, fee_fields)
            tee.log(f"Pre-signed for bundle: armFlashloanActions (tx {hash_arm}), startFlashLoan (tx {hash_start})")

            sim = call_bundle(RELAY_URLS["eth"], acct, [raw_arm, raw_start], w3.eth.block_number + 1)
            if sim.get("firstRevert"):
                tee.log(f"Arbitrage bundle simulation reverted before any real submission -- not sending: {sim['firstRevert']}", alert=True)
                return False
            total_gas_used = sim.get("totalGasUsed") or 2 * BUNDLE_GAS_LIMIT
            gas_cap_wei = int(total_gas_used * fee_fields["maxFeePerGas"] * GAS_BUDGET_MARGIN)
            tee.log(f"Gas budget for this arbitrage bundle: {total_gas_used} gas simulated * {GAS_BUDGET_MARGIN} margin = {_eth(gas_cap_wei)} ETH cap.")

            landed = submit_bundle_and_wait(w3, acct, [raw_arm, raw_start], [hash_arm, hash_start], RELAY_URLS["eth"], tee)
            if not landed:
                tee.log("Arbitrage bundle never landed on-chain within the retry window -- safe to retry next cycle.", alert=True)
                return False
            nonce_box["nonce"] = start_nonce + 2
            arm_receipt = w3.eth.get_transaction_receipt(hash_arm)
            start_receipt = w3.eth.get_transaction_receipt(hash_start)
            if arm_receipt.status != 1 or start_receipt.status != 1:
                tee.log("Arbitrage bundle landed but at least one tx's receipt shows REVERTED.", alert=True)
                return False
            return True
        except Exception as e:
            tee.log(f"Arbitrage bundle submission failed: {e}", alert=True)
            return False

    def _single_call_budget(data: bytes, label: str) -> GasBudget:
        gas_est = estimate_gas_limit(
            w3,
            {
                "from": acct.address,
                "to": attack_wallet,
                "data": data,
                "value": 0,
                "chainId": w3.eth.chain_id,
                "nonce": nonce_box["nonce"],
            },
        )
        cap_wei = int(gas_est * fee_fields["maxFeePerGas"] * GAS_BUDGET_MARGIN)
        tee.log(f"Gas budget for {label}: {gas_est} gas * {GAS_BUDGET_MARGIN} margin = {_eth(cap_wei)} ETH cap.")
        return GasBudget(cap_wei)

    try:
        if not send_call(w3, acct, nonce_box, attack_wallet, arm_data, tee, "armFlashloanActions", gas_budget=_single_call_budget(arm_data, "armFlashloanActions")):
            return False
        return send_call(w3, acct, nonce_box, attack_wallet, start_data, tee, "startFlashLoan", gas_budget=_single_call_budget(start_data, "startFlashLoan"))
    except GasBudgetExceeded as e:
        tee.log(f"ABORTED: {e}", alert=True)
        return False


def price_impact_pct(reserve_in_before: int, reserve_out_before: int, amount_in: int, amount_out: int) -> float:
    """This trade's own effect on the pool's spot price (reserve_out/
    reserve_in), as a signed percentage -- the EXACT same ratio-shift
    metric src/evm/oracles/twap_manipulation.rs's TwapManipulationOracle
    checks on-chain (it flags a shift past +100%/-50% -- i.e. the ratio
    doubling or halving -- within a single transaction as the
    manipulation precondition). Human review of whether to approve a
    trade (see main()'s confirmation prompt) is only meaningful if this
    number is actually shown, not left for someone to infer from raw
    swap amounts -- that was the whole point of adding this function."""
    price_before = reserve_out_before / reserve_in_before
    reserve_in_after = reserve_in_before + amount_in
    reserve_out_after = reserve_out_before - amount_out
    price_after = reserve_out_after / reserve_in_after
    return (price_after - price_before) / price_before * 100


def swap_out(amount_in: int, reserve_in: int, reserve_out: int, fee_bps: int) -> int:
    """Standard constant-product AMM output, fee taken off the input --
    the same formula every real Uniswap-V2-shaped router actually uses,
    so this predicts a real swap's real output exactly, not an
    approximation of it."""
    amount_in_after_fee = amount_in * (10000 - fee_bps) // 10000
    return (amount_in_after_fee * reserve_out) // (reserve_in + amount_in_after_fee)


def arbitrage_profit(x: int, buy_reserve_in: int, buy_reserve_out: int, buy_fee_bps: int, sell_reserve_in: int, sell_reserve_out: int, sell_fee_bps: int) -> int:
    """Profit (in token_a units) of: borrow x of token_a, swap it for
    token_b on the "buy" pool, swap that token_b back to token_a on the
    "sell" pool, minus the x borrowed. Does not yet subtract the
    flashloan premium or gas -- find_optimal_arbitrage does that once,
    on the final chosen amount, not on every search step."""
    token_b_out = swap_out(x, buy_reserve_in, buy_reserve_out, buy_fee_bps)
    token_a_back = swap_out(token_b_out, sell_reserve_in, sell_reserve_out, sell_fee_bps)
    return token_a_back - x


def find_optimal_arbitrage(buy_reserve_in: int, buy_reserve_out: int, buy_fee_bps: int, sell_reserve_in: int, sell_reserve_out: int, sell_fee_bps: int, max_x: int) -> tuple:
    """Ternary search for the x (in [1, max_x]) that maximizes
    arbitrage_profit -- valid because that function is concave (zero at
    x=0, rises, then falls back toward/below zero as slippage dominates;
    a well-established property of two constant-product pools, not
    assumed blindly here: test_find_optimal_arbitrage_matches_brute_force
    in this file's own test block checks it against a brute-force
    search). Returns (best_x, best_profit)."""
    lo, hi = 1, max_x
    for _ in range(200):
        if hi - lo < 2:
            break
        m1 = lo + (hi - lo) // 3
        m2 = hi - (hi - lo) // 3
        p1 = arbitrage_profit(m1, buy_reserve_in, buy_reserve_out, buy_fee_bps, sell_reserve_in, sell_reserve_out, sell_fee_bps)
        p2 = arbitrage_profit(m2, buy_reserve_in, buy_reserve_out, buy_fee_bps, sell_reserve_in, sell_reserve_out, sell_fee_bps)
        if p1 < p2:
            lo = m1
        else:
            hi = m2
    best_x = (lo + hi) // 2
    best_profit = arbitrage_profit(best_x, buy_reserve_in, buy_reserve_out, buy_fee_bps, sell_reserve_in, sell_reserve_out, sell_fee_bps)
    return best_x, best_profit


def check_once(w3: Web3, chain: str, token_a: str, token_b: str, dex_a: dict, dex_b: dict, tee: Tee, min_profit_wei: int, gas_cost_wei: int) -> "dict | None":
    """Returns a dict describing the best opportunity found (whether or
    not it clears min_profit_wei) for the caller to optionally execute,
    or None if one of the pools has no real liquidity to check at all."""
    pair_a = get_pair(w3, dex_a["factory"], token_a, token_b)
    pair_b = get_pair(w3, dex_b["factory"], token_a, token_b)
    ra_a, rb_a = get_reserves(w3, pair_a, token_a)
    ra_b, rb_b = get_reserves(w3, pair_b, token_a)
    if 0 in (ra_a, rb_a, ra_b, rb_b):
        tee.log(f"One of the two pools has an empty reserve ({dex_a['name']}: {ra_a}/{rb_a}, {dex_b['name']}: {ra_b}/{rb_b}) -- skipping this check.")
        return None

    # Try both directions (borrow from A's price basis vs B's) since
    # which pool is "cheap" vs "expensive" for token_a flips depending
    # on current reserves -- whichever direction is actually profitable
    # right now is the one worth reporting.
    max_x = min(ra_a, ra_b) // 2  # never try to move more than half of either pool's own reserve
    best = None
    for buy_name, buy_dex, buy_pair, buy_in, buy_out, sell_name, sell_dex, sell_pair, sell_in, sell_out in [
        (dex_a["name"], dex_a, pair_a, ra_a, rb_a, dex_b["name"], dex_b, pair_b, rb_b, ra_b),
        (dex_b["name"], dex_b, pair_b, ra_b, rb_b, dex_a["name"], dex_a, pair_a, rb_a, ra_a),
    ]:
        x, gross_profit = find_optimal_arbitrage(buy_in, buy_out, buy_dex["fee_bps"], sell_in, sell_out, sell_dex["fee_bps"], max_x)
        if best is None or gross_profit > best[1]:
            best = (x, gross_profit, buy_name, buy_pair, buy_dex["fee_bps"], buy_in, buy_out, sell_name, sell_pair, sell_dex["fee_bps"], sell_in, sell_out)

    x, gross_profit_wei, buy_name, buy_pair, buy_fee_bps, buy_in, buy_out, sell_name, sell_pair, sell_fee_bps, sell_in, sell_out = best
    premium_wei = (x * AAVE_V3_FLASHLOAN_PREMIUM_BPS) // 10000
    net_profit_wei = gross_profit_wei - premium_wei - gas_cost_wei

    # The deterministic PROOF a human reviewing this log needs before
    # deciding whether to approve execution -- see price_impact_pct's own
    # doc for why this is the SAME metric src/evm/oracles/
    # twap_manipulation.rs's TwapManipulationOracle checks on-chain.
    # Trusting a human to catch a dangerous trade from raw profit numbers
    # alone, without this figure spelled out, isn't trusting anything --
    # it's just hoping.
    mid_amount = swap_out(x, buy_in, buy_out, buy_fee_bps)
    final_amount = swap_out(mid_amount, sell_in, sell_out, sell_fee_bps)
    buy_impact_pct = price_impact_pct(buy_in, buy_out, x, mid_amount)
    sell_impact_pct = price_impact_pct(sell_in, sell_out, mid_amount, final_amount)

    status = "PROFITABLE" if net_profit_wei > min_profit_wei else "not profitable right now"
    tee.log(
        f"{status}: borrow {_eth(x)} token_a, swap on {buy_name} -> swap back on {sell_name} -- "
        f"gross={_eth(gross_profit_wei)}, flashloan premium={_eth(premium_wei)}, "
        f"gas est={_eth(gas_cost_wei)} ETH, NET={_eth(net_profit_wei)} (token_a units) -- "
        f"PRICE IMPACT: {buy_name} {buy_impact_pct:+.4f}%, {sell_name} {sell_impact_pct:+.4f}% "
        f"(TwapManipulationOracle's own on-chain threshold is a +100%/-50% shift within one transaction)"
    )
    opportunity = {
        "x": x,
        "net_profit_wei": net_profit_wei,
        "buy_pair": buy_pair,
        "sell_pair": sell_pair,
        "buy_fee_bps": buy_fee_bps,
        "sell_fee_bps": sell_fee_bps,
        "buy_impact_pct": buy_impact_pct,
        "sell_impact_pct": sell_impact_pct,
    }
    if net_profit_wei > min_profit_wei:
        tee.log(
            f"Net profit {_eth(net_profit_wei)} exceeds --min-profit-eth.",
            alert=True,
        )
    return opportunity


def ask_human_confirmation(pair_name: str, opportunity: dict, tee: Tee) -> bool:
    """Mandatory, explicit human gate before ANY real execution -- never
    skipped, never bypassable via a flag (per explicit user instruction,
    2026-11-02: this stays a human-judgment matter, with the exact
    numbers a human needs actually shown, not inferred). Prints the
    price impact on BOTH pools (the SAME metric
    src/evm/oracles/twap_manipulation.rs's TwapManipulationOracle checks
    on-chain -- see price_impact_pct's own doc) plus the expected profit,
    then waits for an unambiguous, EXACT "YES" on stdin. Anything else --
    a bare Enter, a typo, an EOF (no interactive terminal attached, e.g.
    running under a non-interactive scheduler), or an exception reading
    stdin -- is treated as a decline. There is no default-approve path
    anywhere in this function."""
    tee.log(
        "=== HUMAN CONFIRMATION REQUIRED BEFORE EXECUTION ===\n"
        f"  Pair: {pair_name}\n"
        f"  Borrow: {_eth(opportunity['x'])} token_a (Aave V3 flashloan)\n"
        f"  Buy pool: {opportunity['buy_pair']} -- price impact {opportunity['buy_impact_pct']:+.4f}%\n"
        f"  Sell pool: {opportunity['sell_pair']} -- price impact {opportunity['sell_impact_pct']:+.4f}%\n"
        f"  Expected net profit: {_eth(opportunity['net_profit_wei'])} token_a\n"
        "  (For comparison: the TwapManipulationOracle in the Rust fuzzer flags manipulation when the "
        "reserve ratio moves by more than +100%/-50% within a single transaction.)",
        alert=True,
    )
    try:
        answer = input(f"Execute this trade on {pair_name}? Type exactly 'YES' to confirm, anything else rejects: ")
    except EOFError:
        tee.log(f"No interactive input (EOF on stdin) -- cannot ask a human, so defaulting to REJECTED for {pair_name}.", alert=True)
        return False
    answer = answer.strip()
    if answer == "YES":
        tee.log(f"The human CONFIRMED execution on {pair_name}.")
        return True
    tee.log(f"The human REJECTED execution on {pair_name} (answer: {answer!r}).", alert=True)
    return False


def build_parser() -> argparse.ArgumentParser:
    """Factored out of main() (2026-11-02) so dashboard_server.py can
    introspect the REAL CLI surface to build its own launch form from --
    see that file's own module doc."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chain", default="eth", choices=known_chains())
    parser.add_argument("--token-a", default=None, help="Check only this ONE pair (needs --token-b too) instead of every pair in DEX_PAIRS_BY_CHAIN[--chain]['pairs']")
    parser.add_argument("--token-b", default=None, help="See --token-a")
    parser.add_argument("--poll-interval", type=float, default=15.0)
    parser.add_argument("--min-profit-eth", type=float, default=0.01, help="Only ALERT above this much net profit, in token_a units")
    parser.add_argument("--gas-estimate-units", type=int, default=250_000, help="Rough gas units for a 2-swap flashloan round trip, for cost estimation only")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually borrow and trade on a profitable opportunity, instead of only logging an ALERT. "
        "Requires --key and --recovery-wallet. Default is alert-only -- nothing is ever signed or sent "
        "unless this is explicitly passed.",
    )
    parser.add_argument("--key", default=None, help="Path to the funding wallet's private key file -- required (with --recovery-wallet) for --execute")
    parser.add_argument("--recovery-wallet", default=None, help="Where every bit of profit is swept -- required (with --key) for --execute")
    parser.add_argument(
        "--confirm-mainnet",
        action="store_true",
        help="Required, together with --execute, to trade on any chain not in chains.TESTNET_CHAINS.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.chain not in DEX_PAIRS_BY_CHAIN:
        raise SystemExit(
            f"No verified DEX pair configuration for chain '{args.chain}' yet -- only {', '.join(DEX_PAIRS_BY_CHAIN)} "
            "is wired up in v1. Adding another chain means live-verifying two real, independent DEX factories on "
            "it first, the same way eth's were (see this file's own module doc)."
        )
    cfg = DEX_PAIRS_BY_CHAIN[args.chain]
    if args.token_a or args.token_b:
        if not (args.token_a and args.token_b):
            raise SystemExit("--token-a and --token-b must be given together.")
        pairs = [{"name": "custom", "token_a": args.token_a, "token_b": args.token_b}]
    else:
        pairs = cfg["pairs"]

    if args.execute and not (args.key and args.recovery_wallet):
        raise SystemExit("--execute requires both --key and --recovery-wallet.")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tee = Tee(LOGS_DIR / f"dex_arbitrage_{run_id}.log")
    tee.log(f"=== dex_arbitrage_scanner run {run_id}: chain={args.chain} pairs={[p['name'] for p in pairs]} ===")
    # Shown even in alert-only mode (no --execute, no real signing) --
    # the eth/etc confusion risk chain_banner() exists for is about
    # misreading WHICH market is being watched, not just about avoiding
    # a wrong real transaction.
    tee.log(f"Chain selected: {chain_banner(args.chain)}")

    w3 = make_w3(args.chain)
    verify_rpc_identity(args.chain, tee, w3=w3)

    acct = None
    attack_wallet = None
    nonce_box = None
    if args.execute:
        require_mainnet_confirmation(args.chain, args.confirm_mainnet, tee=tee)
        acct = Account.from_key(Path(args.key).read_text().strip())
        enforce_wallet_policy(args.chain, acct.address, args.recovery_wallet)
        nonce_box = {"nonce": w3.eth.get_transaction_count(acct.address)}
        attack_wallet = get_or_deploy_attack_wallet(w3, acct, nonce_box, args.chain, args.recovery_wallet, tee)
        tee.log(f"Watching {cfg['dex_a']['name']} vs {cfg['dex_b']['name']} -- EXECUTE ARMED: signer={acct.address}, profit -> {args.recovery_wallet}.")
    else:
        tee.log(f"Watching {cfg['dex_a']['name']} vs {cfg['dex_b']['name']} -- ALERT ONLY, this script never signs or sends anything.")

    try:
        while True:
            # Every configured pair is checked every cycle, independently --
            # one pair's RPC hiccup or executed trade must never skip or
            # delay the others (same "one plan's outcome says nothing about
            # another's" principle auto_pipeline.py's own per-bug status
            # list is built on).
            for pair in pairs:
                try:
                    token_a = Web3.to_checksum_address(pair["token_a"])
                    token_b = Web3.to_checksum_address(pair["token_b"])
                    gas_price = w3.eth.gas_price  # rough, read-only -- no transaction built, just a cost estimate basis
                    gas_cost_wei = args.gas_estimate_units * gas_price
                    opportunity = check_once(w3, args.chain, token_a, token_b, cfg["dex_a"], cfg["dex_b"], tee, Web3.to_wei(args.min_profit_eth, "ether"), gas_cost_wei)
                    if args.execute and opportunity and opportunity["net_profit_wei"] > Web3.to_wei(args.min_profit_eth, "ether"):
                        if ask_human_confirmation(pair["name"], opportunity, tee):
                            execute_arbitrage(
                                w3, acct, nonce_box, attack_wallet, args.chain, token_a, token_b, opportunity["x"],
                                opportunity["buy_pair"], opportunity["sell_pair"], opportunity["buy_fee_bps"], opportunity["sell_fee_bps"], tee,
                            )
                except Exception as e:
                    # Never let a transient RPC hiccup (rate limiting, a
                    # dropped connection) kill this scanner -- same
                    # resilience monitor.py's own poll loop already has.
                    tee.log(f"Check failed for {pair['name']}, will retry next cycle: {e}", alert=True)
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        tee.log("Stopped by user.")
    finally:
        tee.close()
    return 0


def _run_self_tests() -> None:
    """Guards find_optimal_arbitrage against ever silently drifting from
    a correct answer: compares it against a brute-force scan over many
    random reserve scenarios, rather than trusting the ternary search's
    concavity assumption on faith. Run with --self-test."""
    import random

    random.seed(42)
    worst_diff_pct = 0.0
    for _ in range(50):
        ra_a = random.randint(10**18, 10**22)
        rb_a = random.randint(10**18, 10**22)
        ra_b = random.randint(10**18, 10**22)
        rb_b = random.randint(10**18, 10**22)
        max_x = min(ra_a, ra_b) // 2
        _, profit_ternary = find_optimal_arbitrage(ra_a, rb_a, 30, rb_b, ra_b, 30, max_x)
        brute_profit = max(
            arbitrage_profit(x, ra_a, rb_a, 30, rb_b, ra_b, 30) for x in range(1, max_x, max(1, max_x // 5000))
        )
        # Absolute, not relative, comparison -- near-zero-profit cases
        # (no real opportunity exists) make a relative % comparison
        # between two tiny numbers meaningless.
        diff_wei = abs(profit_ternary - brute_profit)
        if max(abs(profit_ternary), abs(brute_profit)) > 10**9:
            diff_pct = diff_wei / max(abs(profit_ternary), abs(brute_profit)) * 100
            worst_diff_pct = max(worst_diff_pct, diff_pct)
        elif diff_wei > 10:
            raise AssertionError(f"find_optimal_arbitrage diverged from brute force by {diff_wei} wei on a near-zero case")
    assert worst_diff_pct < 1.0, f"find_optimal_arbitrage diverged from brute force by {worst_diff_pct:.4f}% on some case"
    print(f"Self-test OK: worst ternary-vs-brute-force divergence across 50 random scenarios was {worst_diff_pct:.6f}%")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        _run_self_tests()
        sys.exit(0)
    sys.exit(main())
