#!/usr/bin/env python3
# Author: DanyTech
"""test_gas_limit_cap.py -- the gas limit estimate_gas_limit() returns is a
HARD ceiling: it may never exceed MAX_GAS_LIMIT (8,000,000), on any chain, no
matter what eth_estimateGas says or what the block's own gasLimit currently is.

Regression test for a real ETC mainnet failure: ETC's block gasLimit
fluctuates between 8,000,000 and 8,007,811. estimate_gas_limit used to fall
back to the bare (fluctuating) block gasLimit when eth_estimateGas returned an
inflated number, so a tx was signed with gas=8,007,811. That tx was
un-includable the moment the block limit dropped back to 8,000,000, and it then
blocked the wallet's nonce forever, aborting the run with a web3
TimeExhausted.

No network: a fake Web3 supplies only the eth surface estimate_gas_limit
touches, so the real function runs unmodified.

Run: python -m unittest onchain_scripts/test_gas_limit_cap.py -v
 or: python onchain_scripts/test_gas_limit_cap.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gas_utils import (  # noqa: E402
    MAX_GAS_LIMIT,
    GasExceedsBlockLimitError,
    estimate_gas_limit,
)


class _FakeEth:
    def __init__(self, estimate, block_gas_limit, probe_reverts=False):
        self._estimate = estimate
        self._block_gas_limit = block_gas_limit
        self._probe_reverts = probe_reverts
        self.call_probe_gas = None

    def estimate_gas(self, tx):
        return self._estimate

    def get_block(self, which):
        return {"gasLimit": self._block_gas_limit}

    def call(self, tx):
        self.call_probe_gas = tx.get("gas")
        if self._probe_reverts:
            raise ValueError("execution reverted")
        return b"\x00" * 32


class _FakeW3:
    def __init__(self, estimate, block_gas_limit, probe_reverts=False):
        self.eth = _FakeEth(estimate, block_gas_limit, probe_reverts)


class GasLimitCapTest(unittest.TestCase):
    def test_never_exceeds_max_when_block_limit_is_higher(self):
        # ETC's 8,007,811 blocks: the cap must still hold at 8,000,000.
        w3 = _FakeW3(estimate=100_000, block_gas_limit=8_007_811)
        self.assertEqual(estimate_gas_limit(w3, {"to": "0x" + "00" * 20}), 110_000)

    def test_margin_clamped_to_cap_not_pushed_over(self):
        # An estimate whose 10% margin would land above the cap must be
        # clamped to the cap, not pushed over it.
        w3 = _FakeW3(estimate=7_300_000, block_gas_limit=8_007_811)
        self.assertEqual(estimate_gas_limit(w3, {"to": "0x" + "00" * 20}), MAX_GAS_LIMIT)

    def test_inflated_estimate_falls_back_to_cap_not_block_limit(self):
        # The exact real-world failure: estimateGas inflates, the probe
        # succeeds -- the fallback must be the fixed cap, NEVER the bare
        # (fluctuating) block limit of 8,007,811.
        w3 = _FakeW3(estimate=49_610_942, block_gas_limit=8_007_811)
        got = estimate_gas_limit(w3, {"to": "0x" + "00" * 20})
        self.assertEqual(got, MAX_GAS_LIMIT)
        self.assertLessEqual(got, MAX_GAS_LIMIT)

    def test_capped_at_block_limit_when_block_limit_is_lower(self):
        # A chain whose block limit is below the cap must not be exceeded:
        # an estimate over that lower limit falls back to it.
        w3 = _FakeW3(estimate=6_000_000, block_gas_limit=5_000_000)
        self.assertEqual(estimate_gas_limit(w3, {"to": "0x" + "00" * 20}), 5_000_000)

    def test_inflated_estimate_with_lower_block_limit_uses_that_limit(self):
        w3 = _FakeW3(estimate=50_000_000, block_gas_limit=5_000_000)
        self.assertEqual(estimate_gas_limit(w3, {"to": "0x" + "00" * 20}), 5_000_000)

    def test_probe_revert_raises_cleanly(self):
        w3 = _FakeW3(estimate=50_000_000, block_gas_limit=8_000_000, probe_reverts=True)
        with self.assertRaises(GasExceedsBlockLimitError):
            estimate_gas_limit(w3, {"to": "0x" + "00" * 20})

    def test_probe_used_the_cap_not_the_block_limit(self):
        # When the estimate inflates, the eth_call probe must be made at the
        # hard cap (8,000,000), not at the block's higher 8,007,811.
        w3 = _FakeW3(estimate=49_610_942, block_gas_limit=8_007_811)
        estimate_gas_limit(w3, {"to": "0x" + "00" * 20})
        self.assertEqual(w3.eth.call_probe_gas, MAX_GAS_LIMIT)


class BuildPreciseTxHardCapTest(unittest.TestCase):
    """build_precise_tx is the single point where a gas limit becomes a
    signable tx, so it clamps to MAX_GAS_LIMIT itself. This holds even if
    estimate_gas_limit is ever changed (or monkeypatched) to return
    something larger -- the signed tx can never exceed the cap."""

    def test_signed_gas_never_exceeds_cap_even_if_estimate_returns_more(self):
        import gas_utils

        orig_est = gas_utils.estimate_gas_limit
        orig_fee = gas_utils.get_fee_fields
        gas_utils.estimate_gas_limit = lambda w3, tx, margin=None: 50_000_000
        gas_utils.get_fee_fields = lambda w3, **kw: {"is_legacy": True, "gasPrice": 1_000_000_000}
        try:
            tx = gas_utils.build_precise_tx(object(), {"to": "0x" + "00" * 20})
        finally:
            gas_utils.estimate_gas_limit = orig_est
            gas_utils.get_fee_fields = orig_fee
        self.assertEqual(tx["gas"], MAX_GAS_LIMIT)
        self.assertLessEqual(tx["gas"], MAX_GAS_LIMIT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
