"""Unit tests for gas_oracle.py -- pure logic, NO network.

Run: python -m unittest onchain_scripts/test_gas_oracle.py -v
 or: python onchain_scripts/test_gas_oracle.py
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gas_oracle as go  # noqa: E402


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    """Records the last request and returns a canned payload."""
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status
        self.last_url = None
        self.last_params = None

    def get(self, url, params=None, timeout=None):
        self.last_url = url
        self.last_params = params
        return FakeResponse(self.payload, self.status)


class TestComputeFeeFieldsLegacy(unittest.TestCase):
    """ETC has no EIP-1559: no refund, so the price IS the cost. Getting it
    from the official median (not a padded node quote) is the whole point."""

    def test_uses_official_median_when_sane(self):
        q = go.GasQuote(chain="etc", source="blockscout-v2", is_legacy=True,
                        gas_price_wei=3_430_000_000)
        f = go.compute_fee_fields(q, node_base_fee=None, node_priority_fee=None,
                                  node_gas_price=1_000_000_000)
        self.assertTrue(f["is_legacy"])
        self.assertEqual(f["gasPrice"], 3_430_000_000)
        self.assertEqual(f["maxFeePerGas"], 3_430_000_000)
        self.assertEqual(f["source"], "blockscout-v2")

    def test_stale_official_median_falls_back_to_node(self):
        # Official median < 50% of the node's own gasPrice would underprice
        # the tx into never landing -- trust the node instead.
        q = go.GasQuote(chain="etc", source="blockscout-v2", is_legacy=True,
                        gas_price_wei=100)
        f = go.compute_fee_fields(q, node_base_fee=None, node_priority_fee=None,
                                  node_gas_price=1_000_000_000)
        self.assertEqual(f["gasPrice"], 1_000_000_000)

    def test_no_official_quote_uses_node(self):
        f = go.compute_fee_fields(None, node_base_fee=None, node_priority_fee=None,
                                  node_gas_price=2_000_000_000)
        self.assertEqual(f["gasPrice"], 2_000_000_000)
        self.assertEqual(f["source"], "node-rpc")

    def test_all_none_yields_zero_not_crash(self):
        f = go.compute_fee_fields(None, node_base_fee=None, node_priority_fee=None,
                                  node_gas_price=None)
        self.assertEqual(f["gasPrice"], 0)


class TestComputeFeeFields1559(unittest.TestCase):
    """ETH refunds unused base-fee headroom, so maxFeePerGas is a CEILING;
    only the tip is a real, non-refundable cost."""

    def test_max_fee_formula_and_tip(self):
        q = go.GasQuote(chain="eth", source="etherscan-v2", is_legacy=False,
                        base_fee_wei=193_000_000, priority_fee_wei=1_000_000)
        f = go.compute_fee_fields(q, node_base_fee=193_421_884, node_priority_fee=1907,
                                  node_gas_price=193_423_791, lookahead_blocks=2)
        self.assertFalse(f["is_legacy"])
        self.assertEqual(f["maxFeePerGas"], int(193_421_884 * (1.125 ** 2)) + 1_000_000)
        self.assertEqual(f["maxPriorityFeePerGas"], 1_000_000)
        self.assertNotIn("gasPrice", f)

    def test_tip_falls_back_to_node_when_official_has_none(self):
        q = go.GasQuote(chain="eth", source="etherscan-v2", is_legacy=False,
                        base_fee_wei=193_000_000, priority_fee_wei=None)
        f = go.compute_fee_fields(q, node_base_fee=193_000_000, node_priority_fee=1907,
                                  node_gas_price=193_000_000)
        self.assertEqual(f["maxPriorityFeePerGas"], 1907)

    def test_stale_official_base_falls_back_to_node_base(self):
        q = go.GasQuote(chain="eth", source="etherscan-v2", is_legacy=False,
                        base_fee_wei=1, priority_fee_wei=5)
        f = go.compute_fee_fields(q, node_base_fee=200_000_000, node_priority_fee=1,
                                  node_gas_price=200_000_000)
        self.assertEqual(f["base_fee_wei"], 200_000_000)
        self.assertEqual(f["maxFeePerGas"], int(200_000_000 * (1.125 ** 2)) + 5)

    def test_no_official_quote_degrades_to_node(self):
        f = go.compute_fee_fields(None, node_base_fee=100_000_000,
                                  node_priority_fee=42, node_gas_price=100_000_000)
        self.assertEqual(f["source"], "node-rpc")
        self.assertEqual(f["maxPriorityFeePerGas"], 42)
        self.assertEqual(f["maxFeePerGas"], int(100_000_000 * (1.125 ** 2)) + 42)


class TestSources(unittest.TestCase):
    def test_etherscan_v2_parses_and_derives_tip(self):
        payload = {"status": "1", "message": "OK", "result": {
            "SafeGasPrice": "0.186723491", "ProposeGasPrice": "0.193590611",
            "FastGasPrice": "0.236721584", "suggestBaseFee": "0.186721584",
        }}
        sess = FakeSession(payload)
        q = go.etherscan_v2_gas_oracle(1, session=sess)
        self.assertFalse(q.is_legacy)
        self.assertEqual(q.base_fee_wei, 186_721_584)
        self.assertEqual(q.propose_wei, 193_590_611)
        # tip = proposed total price - the base it is proposed on
        self.assertEqual(q.priority_fee_wei, 193_590_611 - 186_721_584)
        self.assertIn("chainid", sess.last_params)

    def test_etherscan_v2_notok_raises(self):
        sess = FakeSession({"status": "0", "message": "NOTOK", "result": "nope"})
        with self.assertRaises(RuntimeError):
            go.etherscan_v2_gas_oracle(1, session=sess)

    def test_blockscout_v2_parses_median_as_legacy_price(self):
        payload = {"gas_prices": {"slow": 2.77, "average": 3.43, "fast": 3.48}}
        sess = FakeSession(payload)
        q = go.blockscout_v2_gas_prices("https://etc.blockscout.com", "etc", session=sess)
        self.assertTrue(q.is_legacy)
        self.assertEqual(q.gas_price_wei, 3_430_000_000)
        self.assertEqual(q.safe_wei, 2_770_000_000)
        self.assertEqual(q.fast_wei, 3_480_000_000)
        self.assertTrue(sess.last_url.endswith("/api/v2/stats"))

    def test_blockscout_v2_empty_prices_raises(self):
        sess = FakeSession({"gas_prices": {}})
        with self.assertRaises(RuntimeError):
            go.blockscout_v2_gas_prices("https://etc.blockscout.com", "etc", session=sess)

    def test_blockscout_v2_falls_back_to_static_gas_price(self):
        # Some Blockscout instances transiently publish all-null gas_prices
        # while still exposing static_gas_price (seen live on Mordor).
        sess = FakeSession({"gas_prices": {"slow": None, "average": None, "fast": None},
                            "static_gas_price": 2.5})
        q = go.blockscout_v2_gas_prices("https://etc-mordor.blockscout.com", "mordor", session=sess)
        self.assertEqual(q.gas_price_wei, 2_500_000_000)

    def test_fetch_official_routes_by_chain_and_swallows_errors(self):
        go._CACHE.clear()
        with mock.patch.object(go, "blockscout_v2_gas_prices",
                               return_value=go.GasQuote(chain="etc", source="blockscout-v2",
                                                        is_legacy=True, gas_price_wei=3_000_000_000)) as m:
            q = go.fetch_official_gas_quote("etc")
            self.assertEqual(q.gas_price_wei, 3_000_000_000)
            m.assert_called_once()
        go._CACHE.clear()
        with mock.patch.object(go, "blockscout_v2_gas_prices", side_effect=RuntimeError("boom")):
            self.assertIsNone(go.fetch_official_gas_quote("etc"))
        go._CACHE.clear()
        self.assertIsNone(go.fetch_official_gas_quote("unknown-chain"))

    def test_fetch_official_caches_within_ttl(self):
        go._CACHE.clear()
        quote = go.GasQuote(chain="etc", source="blockscout-v2", is_legacy=True,
                            gas_price_wei=1)
        with mock.patch.object(go, "blockscout_v2_gas_prices", return_value=quote) as m:
            go.fetch_official_gas_quote("etc", ttl_seconds=60)
            go.fetch_official_gas_quote("etc", ttl_seconds=60)
            self.assertEqual(m.call_count, 1)
        go._CACHE.clear()


class TestGweiParsing(unittest.TestCase):
    def test_gwei_to_wei_handles_str_float_int_none(self):
        self.assertEqual(go._gwei_to_wei("0.193590611"), 193_590_611)
        self.assertEqual(go._gwei_to_wei(3.43), 3_430_000_000)
        self.assertEqual(go._gwei_to_wei(5), 5_000_000_000)
        self.assertIsNone(go._gwei_to_wei(None))
        self.assertIsNone(go._gwei_to_wei("not-a-number"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
