#!/usr/bin/env python3
# Author: DanyTech
"""test_gas_ledger.py -- unit tests for gas_utils.GasLedger / net_profit_wei.

Pure logic, no network, no chain: a "receipt" here is just a tiny dict with
the two fields GasLedger.record actually reads (gasUsed, effectiveGasPrice),
exactly the shape web3 returns.

Run: python -m unittest onchain_scripts/test_gas_ledger.py -v
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gas_utils import GasLedger, format_wei_signed, net_profit_wei  # noqa: E402


def receipt(gas_used: int, gas_price: int) -> dict:
    return {"gasUsed": gas_used, "effectiveGasPrice": gas_price}


class GasLedgerTest(unittest.TestCase):
    def test_empty_ledger_spends_nothing(self):
        led = GasLedger()
        self.assertEqual(led.spent_wei, 0)
        self.assertEqual(led.tx_count, 0)

    def test_record_uses_gasused_times_effective_price(self):
        led = GasLedger()
        cost = led.record(receipt(21_000, 10**9))
        self.assertEqual(cost, 21_000 * 10**9)
        self.assertEqual(led.spent_wei, 21_000 * 10**9)
        self.assertEqual(led.tx_count, 1)

    def test_record_accumulates_across_txs(self):
        led = GasLedger()
        led.record(receipt(21_000, 2 * 10**9))
        led.record(receipt(50_000, 2 * 10**9))
        led.record(receipt(100_000, 2 * 10**9))
        self.assertEqual(led.spent_wei, (21_000 + 50_000 + 100_000) * 2 * 10**9)
        self.assertEqual(led.tx_count, 3)

    def test_missing_effective_price_counts_as_zero(self):
        # Some chains/nodes omit effectiveGasPrice on a legacy receipt; the
        # ledger must not crash on that, just treat the cost as unknown-zero.
        led = GasLedger()
        led.record({"gasUsed": 21_000})
        self.assertEqual(led.spent_wei, 0)
        self.assertEqual(led.tx_count, 1)

    def test_record_many_sums_all(self):
        led = GasLedger()
        total = led.record_many([receipt(10_000, 3 * 10**9), receipt(20_000, 3 * 10**9)])
        self.assertEqual(total, 30_000 * 3 * 10**9)
        self.assertEqual(led.spent_wei, total)
        self.assertEqual(led.tx_count, 2)


class NetProfitTest(unittest.TestCase):
    def test_profit_above_gas_is_positive(self):
        self.assertEqual(net_profit_wei(10**18, 3 * 10**15), 10**18 - 3 * 10**15)

    def test_profit_below_gas_is_negative_net_loss(self):
        # The whole point: a gross gain smaller than its own gas bill must
        # read as a loss, not be clamped to zero.
        self.assertEqual(net_profit_wei(10**15, 3 * 10**15), -(2 * 10**15))

    def test_zero_gas_leaves_gross_unchanged(self):
        self.assertEqual(net_profit_wei(10**18, 0), 10**18)

    def test_zero_profit_with_gas_is_pure_loss(self):
        self.assertEqual(net_profit_wei(0, 5 * 10**14), -(5 * 10**14))


class FormatWeiSignedTest(unittest.TestCase):
    """Web3.from_wei() rejects negative values, so the net-loss case needs a
    sign-aware formatter or the reporting crashes exactly when it matters."""

    def test_positive_matches_from_wei(self):
        from web3 import Web3

        self.assertEqual(format_wei_signed(Web3, 10**18), str(Web3.from_wei(10**18, "ether")))

    def test_negative_is_prefixed_with_minus(self):
        from web3 import Web3

        self.assertEqual(format_wei_signed(Web3, -(2 * 10**15)), "-" + str(Web3.from_wei(2 * 10**15, "ether")))

    def test_zero(self):
        from web3 import Web3

        self.assertEqual(format_wei_signed(Web3, 0), "0")


class ExecutePlanResultShapeTest(unittest.TestCase):
    """The 4-tuple execute_plan now returns must stay backwards-compatible
    with callers that only take the first two values (strategy_layer's
    _unpack_result exists precisely to bridge that), and the appended
    fields must be (gas_spent, net_profit) in that order."""

    def test_unpack_result_accepts_4_tuple(self):
        from strategy_layer import _unpack_result

        status, delta, gas, net = _unpack_result(("confirmed", 100, 30, 70))
        self.assertEqual((status, delta, gas, net), ("confirmed", 100, 30, 70))

    def test_unpack_result_defaults_gas_fields_for_2_tuple(self):
        from strategy_layer import _unpack_result

        status, delta, gas, net = _unpack_result(("confirmed", 100))
        self.assertEqual((status, delta), ("confirmed", 100))
        self.assertEqual((gas, net), (0, 0))

    def test_net_field_is_gross_minus_gas(self):
        # Mirrors execute_plan's own _result() construction: the 4th field
        # is always net_profit_wei(delta, gas_spent), never delta alone.
        delta, gas = 500, 120
        self.assertEqual(net_profit_wei(delta, gas), 380)


if __name__ == "__main__":
    unittest.main()
