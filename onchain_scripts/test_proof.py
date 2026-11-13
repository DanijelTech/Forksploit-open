#!/usr/bin/env python3
"""test_proof.py -- the structured proof object (FAZA 5.2 of
TASK_SPEC.md) must collapse the three gates (state replay, gas
reality, independence from lies) into one record with an explicit,
non-empty `blockers` list whenever a gate fails, so a rejection is
explained rather than silently dropped (nalog §6.8).

No network: build_proof is a pure function over signals the pipeline
already has.

Run: python -m unittest onchain_scripts/test_proof.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auto_pipeline import (  # noqa: E402
    PLAN_CONFIRMED,
    PLAN_EXECUTED_NO_PROFIT,
    PLAN_NOT_CONFIRMED,
    PLAN_SKIPPED_NOT_EXTRACTABLE,
    PLAN_SKIPPED_UNPROFITABLE,
    Proof,
    build_proof,
)


def _finding(**overrides) -> dict:
    base = {
        "plan": {},
        "owner_impersonation": False,
        "atomic_replayable": True,
        "distinct_callers": 1,
    }
    base.update(overrides)
    return base


class TestBuildProof(unittest.TestCase):
    def test_confirmed_positive_delta_is_chain_verified_and_unblocked(self):
        p = build_proof(_finding(), PLAN_CONFIRMED, 10**18, 10**15, 10**18 - 10**15, gas_units=123456)
        self.assertIsInstance(p, Proof)
        self.assertTrue(p.replayed)
        self.assertTrue(p.independent)
        self.assertTrue(p.chain_verified)
        self.assertEqual(p.gas_used, 123456)
        self.assertEqual(p.blockers, [])
        # to_dict must be JSON-serialisable shape.
        d = p.to_dict()
        self.assertEqual(set(d), {"replayed", "gas_used", "independent", "net_profit_wei", "chain_verified", "blockers"})

    def test_not_confirmed_reports_replay_blocker(self):
        p = build_proof(_finding(), PLAN_NOT_CONFIRMED, 0, 0, 0)
        self.assertFalse(p.replayed)
        self.assertFalse(p.chain_verified)
        self.assertTrue(any("revert" in b for b in p.blockers))

    def test_executed_no_profit_reports_no_assets_moved(self):
        p = build_proof(_finding(), PLAN_EXECUTED_NO_PROFIT, 0, 5000, -5000)
        self.assertFalse(p.chain_verified)
        self.assertTrue(any("no real assets moved" in b for b in p.blockers))

    def test_owner_impersonation_is_an_independence_blocker(self):
        p = build_proof(_finding(owner_impersonation=True), PLAN_SKIPPED_NOT_EXTRACTABLE, 0, 0, 0)
        self.assertFalse(p.independent)
        self.assertTrue(any("owner_impersonation" in b for b in p.blockers))

    def test_control_leak_dependency_is_an_independence_blocker(self):
        p = build_proof(_finding(atomic_replayable=False), PLAN_SKIPPED_NOT_EXTRACTABLE, 0, 0, 0)
        self.assertFalse(p.independent)
        self.assertTrue(any("atomic_replayable" in b for b in p.blockers))

    def test_multi_caller_is_an_independence_blocker(self):
        p = build_proof(_finding(distinct_callers=3), PLAN_SKIPPED_NOT_EXTRACTABLE, 0, 0, 0)
        self.assertFalse(p.independent)
        self.assertTrue(any("multi-caller" in b for b in p.blockers))

    def test_unprofitable_skip_reports_gas_blocker(self):
        p = build_proof(_finding(), PLAN_SKIPPED_UNPROFITABLE, 0, 0, 0)
        self.assertFalse(p.replayed)
        self.assertTrue(any("out-earn" in b for b in p.blockers))

    def test_unknown_status_still_yields_a_blocker(self):
        p = build_proof(_finding(), "some_future_status", 0, 0, 0)
        self.assertFalse(p.replayed)
        self.assertTrue(p.blockers)

    def test_default_metadata_is_replayable_and_independent(self):
        # A composed plan that carries no fuzzer flags must not be blocked
        # for a missing field (mirrors gated_execute_plan's own defaulting).
        p = build_proof({"plan": {}}, PLAN_NOT_CONFIRMED, 0, 0, 0)
        self.assertTrue(p.independent)


if __name__ == "__main__":
    unittest.main()
