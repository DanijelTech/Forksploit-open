#!/usr/bin/env python3
# Author: DanyTech
"""test_gas_fit.py -- PHASE 1.2/1.3 of TASK_SPEC.md: the plan must
carry an honest gas reality (gas_estimate, fits_block_gas_limit,
gas_headroom_pct), measured with the node's own eth_estimateGas because the
revm fork has no gas metering.

Two layers are tested:
  * gas_fit()          -- the pure arithmetic (no chain), and
  * estimate_plan_gas_on_fork() -- against a fake fork, driving the REAL
    function unmodified (no network).

Run: python -m unittest onchain_scripts/test_gas_fit.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account  # noqa: E402
from web3 import Web3  # noqa: E402

from gas_utils import DEFAULT_GAS_LIMIT_MARGIN, gas_fit  # noqa: E402
import auto_pipeline  # noqa: E402
from auto_pipeline import estimate_plan_gas_on_fork  # noqa: E402

TARGET = Web3.to_checksum_address("0x" + "22" * 20)
ATTACK_WALLET = Web3.to_checksum_address("0x" + "33" * 20)
SIGNER = Account.from_key("0x" + "11" * 32)


class GasFitTest(unittest.TestCase):
    def test_fits_with_headroom(self):
        r = gas_fit(1_000_000, 8_000_000)
        self.assertEqual(r["gas_estimate"], 1_000_000)
        self.assertEqual(r["gas_limit_with_margin"], int(1_000_000 * 1.10))
        self.assertTrue(r["fits_block_gas_limit"])
        self.assertGreater(r["gas_headroom_pct"], 80)

    def test_estimate_over_limit_does_not_fit(self):
        r = gas_fit(9_000_000, 8_000_000)
        self.assertFalse(r["fits_block_gas_limit"])
        self.assertLess(r["gas_headroom_pct"], 0)

    def test_margin_can_push_a_borderline_estimate_over_the_limit(self):
        # 7.3M * 1.10 = 8.03M > 8M block limit -> must NOT fit, even though
        # the raw estimate is under the limit. This is the whole point of
        # judging on the margin-inclusive limit.
        r = gas_fit(7_300_000, 8_000_000)
        self.assertLess(7_300_000, 8_000_000)
        self.assertGreater(r["gas_limit_with_margin"], 8_000_000)
        self.assertFalse(r["fits_block_gas_limit"])

    def test_exactly_at_limit_fits(self):
        limit = 8_000_000
        est = int(limit / (1 + DEFAULT_GAS_LIMIT_MARGIN))
        r = gas_fit(est, limit)
        self.assertTrue(r["fits_block_gas_limit"])

    def test_zero_block_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            gas_fit(1, 0)


class _FakeProvider:
    def __init__(self):
        self.reverted = 0

    def make_request(self, method, params):
        if method == "evm_snapshot":
            return {"result": "0x1"}
        if method == "evm_revert":
            self.reverted += 1
            return {"result": True}
        if method == "anvil_setBalance":
            return {"result": True}
        raise AssertionError(f"unexpected provider method {method}")


class _FakeEth:
    chain_id = 61

    def __init__(self, per_step):
        self._per_step = list(per_step)
        self._i = 0

    def get_block(self, which):
        return {"number": 1, "gasLimit": 8_000_000}

    def estimate_gas(self, tx):
        v = self._per_step[self._i]
        self._i += 1
        return v


class _FakeForkW3:
    def __init__(self, per_step):
        self.provider = _FakeProvider()
        self.eth = _FakeEth(per_step)
        self.to_wei = Web3.to_wei
        self.from_wei = Web3.from_wei


def _plan(steps):
    return {
        "contract_name": "fake",
        "kind": "flat",
        "steps": [
            {"contract": TARGET, "calldata": "deadbeef", "value": "0"} for _ in range(steps)
        ],
    }


class EstimatePlanGasOnForkTest(unittest.TestCase):
    def test_governing_number_is_the_largest_step(self):
        # Three steps, each its own tx: the plan fits if the LARGEST fits,
        # not the sum. 7M, 1M, 1M -> max 7M fits; sum 9M would not.
        fork = _FakeForkW3([7_000_000, 1_000_000, 1_000_000])
        fit = estimate_plan_gas_on_fork(fork, SIGNER, ATTACK_WALLET, _plan(3), "etc")
        self.assertEqual(fit["gas_estimate"], 7_000_000)
        self.assertEqual(fit["gas_estimate_total"], 9_000_000)
        self.assertEqual(fit["step_gas_estimates"], [7_000_000, 1_000_000, 1_000_000])
        self.assertTrue(fit["fits_block_gas_limit"])

    def test_oversized_step_is_flagged(self):
        fork = _FakeForkW3([9_000_000])
        fit = estimate_plan_gas_on_fork(fork, SIGNER, ATTACK_WALLET, _plan(1), "etc")
        self.assertFalse(fit["fits_block_gas_limit"])
        self.assertLess(fit["gas_headroom_pct"], 0)

    def test_no_fork_returns_none(self):
        self.assertIsNone(estimate_plan_gas_on_fork(None, SIGNER, ATTACK_WALLET, _plan(1), "etc"))

    def test_fork_is_reverted_after_measuring(self):
        fork = _FakeForkW3([1_000_000])
        estimate_plan_gas_on_fork(fork, SIGNER, ATTACK_WALLET, _plan(1), "etc")
        self.assertEqual(fork.provider.reverted, 1)

    def test_reverting_estimate_returns_none_not_a_guess(self):
        class _Boom(_FakeForkW3):
            def __init__(self):
                super().__init__([1])
                self.eth.estimate_gas = self._raise

            def _raise(self, tx):
                raise ValueError("execution reverted")

        fork = _Boom()
        self.assertIsNone(estimate_plan_gas_on_fork(fork, SIGNER, ATTACK_WALLET, _plan(1), "etc"))
        self.assertEqual(fork.provider.reverted, 1)


if __name__ == "__main__":
    unittest.main()
