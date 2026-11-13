#!/usr/bin/env python3
"""test_gas_oversized_gate.py -- FAZA 1.3/1.4 of TASK_SPEC.md: a plan
whose OWN measured gas footprint exceeds the block gas limit must be FLAGGED
(`oversized_gas`) and never executed -- not reported as "confirmed".

Regression test for the real ETC mainnet incident (plan `C9f53_2`): the
un-metered revm model reported the trace as "Confirmed", and the real send
then failed with "exceeds block gas limit" -- eth_estimateGas said ~49,610,942
gas against a real block.gasLimit of exactly 8,000,000. FAZA 1.3 requires that
such a plan be flagged before it is ever signed.

No network: a fake fork stands in for Anvil, so the REAL functions
(estimate_plan_gas_on_fork, preflight_skip_reason, skip_status_for,
build_proof) run unmodified.

Run: python -m unittest onchain_scripts/test_gas_oversized_gate.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account  # noqa: E402
from web3 import Web3  # noqa: E402

import auto_pipeline  # noqa: E402
from auto_pipeline import (  # noqa: E402
    PLAN_CONFIRMED,
    PLAN_OVERSIZED_GAS,
    build_proof,
    estimate_plan_gas_on_fork,
    gas_oversized_reason,
    preflight_skip_reason,
    skip_status_for,
)

SIGNER = Account.from_key("0x" + "11" * 32)
ATTACK_WALLET = Web3.to_checksum_address("0x" + "33" * 20)
RECOVERY = Web3.to_checksum_address("0x" + "44" * 20)
TARGET = Web3.to_checksum_address("0x" + "22" * 20)

# The real numbers from the C9f53_2 incident on ETC mainnet.
C9F53_2_ESTIMATE = 49_610_942
ETC_BLOCK_GAS_LIMIT = 8_000_000


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

    def __init__(self, per_step, block_gas_limit):
        self._per_step = list(per_step)
        self._i = 0
        self._block_gas_limit = block_gas_limit

    def get_block(self, which):
        return {"number": 1, "gasLimit": self._block_gas_limit}

    def estimate_gas(self, tx):
        v = self._per_step[self._i]
        self._i += 1
        return v


class _FakeForkW3:
    def __init__(self, per_step, block_gas_limit=ETC_BLOCK_GAS_LIMIT):
        self.provider = _FakeProvider()
        self.eth = _FakeEth(per_step, block_gas_limit)
        self.to_wei = Web3.to_wei
        self.from_wei = Web3.from_wei


def _plan(steps=1):
    return {
        "contract_name": "C9f53_2",
        "kind": "flat",
        "steps": [
            {"contract": TARGET, "calldata": "deadbeef", "value": "0"} for _ in range(steps)
        ],
    }


class GasOversizedReasonTest(unittest.TestCase):
    def test_no_measurement_is_not_flagged(self):
        # No fork -> no honest measurement -> must NOT be flagged (a missing
        # tool makes the pipeline less thrifty, never wrong).
        self.assertIsNone(gas_oversized_reason({"contract_name": "x"}))

    def test_fitting_plan_is_not_flagged(self):
        self.assertIsNone(gas_oversized_reason({"fits_block_gas_limit": True}))

    def test_oversized_plan_is_flagged_with_the_numbers(self):
        reason = gas_oversized_reason({
            "fits_block_gas_limit": False,
            "gas_estimate": C9F53_2_ESTIMATE,
            "block_gas_limit": ETC_BLOCK_GAS_LIMIT,
            "gas_headroom_pct": -520.14,
        })
        self.assertIsNotNone(reason)
        self.assertIn(str(C9F53_2_ESTIMATE), reason)
        self.assertIn(str(ETC_BLOCK_GAS_LIMIT), reason)


class SkipStatusForTest(unittest.TestCase):
    def test_gas_reason_maps_to_oversized_gas_status(self):
        status = skip_status_for("gas: its measured gas footprint does not fit in a block")
        self.assertEqual(status, PLAN_OVERSIZED_GAS)
        self.assertEqual(status, "oversized_gas")

    def test_oversized_gas_is_distinct_from_other_skips(self):
        self.assertNotEqual(PLAN_OVERSIZED_GAS, auto_pipeline.PLAN_SKIPPED_UNPROFITABLE)
        self.assertNotEqual(PLAN_OVERSIZED_GAS, auto_pipeline.PLAN_SKIPPED_NOT_EXTRACTABLE)
        self.assertNotEqual(PLAN_OVERSIZED_GAS, PLAN_CONFIRMED)


class C9f53_2EndToEndTest(unittest.TestCase):
    """The whole FAZA 1 path for the real incident, driving the REAL
    functions: measure on the fork -> stamp the plan -> gate flags it."""

    def test_measured_oversized_plan_is_flagged_and_never_confirmed(self):
        fork = _FakeForkW3([C9F53_2_ESTIMATE])
        plan = _plan()
        fit = estimate_plan_gas_on_fork(fork, SIGNER, ATTACK_WALLET, plan, "etc")
        # The fork measured a real footprint far above the block limit.
        self.assertEqual(fit["gas_estimate"], C9F53_2_ESTIMATE)
        self.assertFalse(fit["fits_block_gas_limit"])
        # The pipeline stamps those fields onto the plan (as main() does).
        plan["gas_estimate"] = fit["gas_estimate"]
        plan["fits_block_gas_limit"] = fit["fits_block_gas_limit"]
        plan["gas_headroom_pct"] = fit["gas_headroom_pct"]
        plan["block_gas_limit"] = fit["block_gas_limit"]

        # The gate flags it even with NO fork available in this call, because
        # it reads the field already stamped on the plan.
        finding = {"plan": plan, "contract_name": plan["contract_name"], "kind": plan["kind"]}
        reason = preflight_skip_reason(
            finding, None, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC"
        )
        self.assertIsNotNone(reason)
        self.assertTrue(reason.startswith("gas:"))
        self.assertEqual(skip_status_for(reason), PLAN_OVERSIZED_GAS)
        # And the status is never "confirmed".
        self.assertNotEqual(skip_status_for(reason), PLAN_CONFIRMED)

    def test_proof_blocks_an_oversized_plan(self):
        proof = build_proof(
            {"plan": {"contract_name": "C9f53_2", "kind": "flat"}},
            PLAN_OVERSIZED_GAS, 0, 0, 0,
        )
        self.assertFalse(proof.replayed)
        self.assertFalse(proof.chain_verified)
        self.assertTrue(any("oversized" in b for b in proof.blockers), proof.blockers)

    def test_composed_plan_without_measurement_is_measured_and_flagged(self):
        # A COMPOSED plan (strategy_layer.compose_plan) carries no fuzzer gas
        # metadata, so it has no `fits_block_gas_limit`. The gate must MEASURE
        # it on the fork and still flag it, otherwise a composition would
        # silently bypass the FAZA 1 guard and an oversized plan could be
        # shown as executable.
        plan = _plan()  # no fits_block_gas_limit / gas_estimate
        self.assertIsNone(plan.get("fits_block_gas_limit"))
        fork = _FakeForkW3([C9F53_2_ESTIMATE])
        finding = {"plan": plan, "contract_name": plan["contract_name"], "kind": plan["kind"]}
        reason = preflight_skip_reason(
            finding, fork, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC"
        )
        self.assertIsNotNone(reason)
        self.assertTrue(reason.startswith("gas:"))
        self.assertEqual(skip_status_for(reason), PLAN_OVERSIZED_GAS)
        # The gate stamped the measurement back onto the plan, so the report
        # carries the composed plan's own gas reality too (FAZA 1.2).
        self.assertEqual(plan["gas_estimate"], C9F53_2_ESTIMATE)
        self.assertFalse(plan["fits_block_gas_limit"])

    def test_composed_plan_that_fits_is_not_flagged_by_gas(self):
        # A composed plan whose measured footprint DOES fit must not be
        # flagged by the gas guard (it may still be skipped by the fork
        # replay, but not for gas reasons).
        plan = _plan()
        fork = _FakeForkW3([1_000_000])
        finding = {"plan": plan, "contract_name": plan["contract_name"], "kind": plan["kind"]}
        reason = preflight_skip_reason(
            finding, fork, SIGNER, ATTACK_WALLET, RECOVERY, "etc", _NullTee(), "ETC"
        )
        self.assertFalse(reason is not None and reason.startswith("gas:"))
        self.assertTrue(plan.get("fits_block_gas_limit"))


class _NullTee:
    def log(self, *a, **k):
        pass


if __name__ == "__main__":
    unittest.main()
